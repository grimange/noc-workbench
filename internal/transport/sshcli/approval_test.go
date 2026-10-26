package sshcli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

type records struct {
	customer    inventory.Customer
	environment inventory.Environment
	asset       inventory.Asset
	endpoint    inventory.Endpoint
}

func (r records) Customer(context.Context, string) (inventory.Customer, error) {
	return r.customer, nil
}
func (r records) Environment(context.Context, string, string) (inventory.Environment, error) {
	return r.environment, nil
}
func (r records) GetAsset(context.Context, string, string) (inventory.Asset, error) {
	return r.asset, nil
}
func (r records) GetEndpoint(context.Context, string, string) (inventory.Endpoint, error) {
	return r.endpoint, nil
}
func activeRecords(p Profile) records {
	return records{inventory.Customer{ID: p.CustomerID, Status: "active"}, inventory.Environment{ID: p.EnvironmentID, CustomerID: p.CustomerID, Status: "active"}, inventory.Asset{ID: p.Target.AssetID, EnvironmentID: p.EnvironmentID, Lifecycle: "active"}, inventory.Endpoint{ID: p.Target.EndpointID, EnvironmentID: p.EnvironmentID, AssetID: p.Target.AssetID, Protocol: "ssh", Host: p.Host, Port: int(p.Port), Status: "active", UpdatedAt: p.EndpointUpdatedAt}}
}
func writeEnrollment(t *testing.T, path string, p Profile) {
	t.Helper()
	v := Enrollment{Profile: p, ApprovedDigest: ProfileDigest(p), ApprovedBy: actor.ID, Evidence: "independent lab console host-key file", Enabled: true}
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestPersistentApproval(t *testing.T) {
	p, _ := fixture(t)
	path := filepath.Join(t.TempDir(), "enrollment.json")
	writeEnrollment(t, path, p)
	db := activeRecords(p)
	f := FileApproval{path, db, LabPolicy{}}
	for _, permission := range []workspace.Permission{ProfileUse, ExecutePermission} {
		if _, err := f.Approve(context.Background(), actor, p.Target, permission); err != nil {
			t.Fatal(err)
		}
	}
	// The existing browser policy deliberately grants neither SSH permission.
	f.Policy = workspace.LocalOperatorPolicy{}
	if _, err := f.Approve(context.Background(), actor, p.Target, ExecutePermission); err == nil {
		t.Fatal("inventory access became execution grant")
	}
	f.Policy = LabPolicy{}
	for _, tc := range []struct {
		name   string
		change func(*records)
	}{
		{"archived_customer", func(r *records) { r.customer.Status = "archived" }},
		{"archived_environment", func(r *records) { r.environment.Status = "archived" }},
		{"archived_asset", func(r *records) { r.asset.Lifecycle = "archived" }},
		{"disabled_endpoint", func(r *records) { r.endpoint.Status = "disabled" }},
		{"wrong_owner", func(r *records) { r.endpoint.AssetID = "22222222-2222-4222-8222-222222222222" }},
		{"wrong_scope", func(r *records) { r.environment.CustomerID = "22222222-2222-4222-8222-222222222222" }},
		{"changed_endpoint", func(r *records) { r.endpoint.Host = "127.0.0.2" }},
		{"changed_port", func(r *records) { r.endpoint.Port++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := db
			tc.change(&r)
			f.Inventory = r
			if _, err := f.Approve(context.Background(), actor, p.Target, ExecutePermission); err == nil {
				t.Fatal("invalid approval")
			}
		})
	}
	f.Inventory = db
	b, _ := os.ReadFile(path)
	b = []byte(strings.Replace(string(b), `"Port":2222`, `"Port":2223`, 1))
	os.WriteFile(path, b, 0600)
	if _, err := ReadEnrollment(path); err == nil {
		t.Fatal("profile change reused approval")
	}
	writeEnrollment(t, path, p)
	os.Chmod(path, 0644)
	if _, err := ReadEnrollment(path); err == nil {
		t.Fatal("unprotected enrollment")
	}
}
func TestMaliciousConfigurationRejected(t *testing.T) {
	p, _ := fixture(t)
	path := filepath.Join(t.TempDir(), "enrollment.json")
	writeEnrollment(t, path, p)
	b, _ := os.ReadFile(path)
	for _, directive := range []string{"Include", "ProxyCommand", "Match exec", "KnownHostsCommand", "LocalCommand", "RemoteCommand", "ProxyJump", "ForwardAgent", "ControlMaster"} {
		raw := append([]byte(`{"`+directive+`":"touch /tmp/must-not-run",`), b[1:]...)
		os.WriteFile(path, raw, 0600)
		if _, err := ReadEnrollment(path); err == nil {
			t.Fatalf("accepted %s", directive)
		}
	}
	symlink := filepath.Join(t.TempDir(), "link")
	os.Symlink(path, symlink)
	if _, err := ReadEnrollment(symlink); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestNonRegularProtectedFilesDoNotBlock(t *testing.T) {
	for _, kind := range []string{"enrollment", "identity"} {
		t.Run(kind, func(t *testing.T) {
			p, e := fixture(t)
			fifo := filepath.Join(t.TempDir(), "fifo")
			if err := syscall.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if kind == "enrollment" {
					_, err := ReadEnrollment(fifo)
					done <- err
					return
				}
				p.IdentityFile = fifo
				e.approval = approvalFunc(func(context.Context, workspace.Principal, Target, workspace.Permission) (Profile, error) {
					return p, nil
				})
				_, err := e.Execute(context.Background(), actor, p.Target, "lab.probe.v1")
				done <- err
			}()
			select {
			case err := <-done:
				category(t, err, Unsupported)
			case <-time.After(500 * time.Millisecond):
				t.Fatal("nonregular file blocked")
			}
		})
	}
}

func TestLabPolicyPointerStillRestrictsDestination(t *testing.T) {
	p, _ := fixture(t)
	p.Host = "192.0.2.1"
	p.Address = p.Host
	path := filepath.Join(t.TempDir(), "profile")
	writeEnrollment(t, path, p)
	for _, policy := range []workspace.Policy{LabPolicy{}, &LabPolicy{}, (*LabPolicy)(nil)} {
		f := FileApproval{Path: path, Inventory: activeRecords(p), Policy: policy}
		if _, err := f.Approve(context.Background(), actor, p.Target, ExecutePermission); err == nil {
			t.Fatal("lab escaped loopback restriction")
		}
	}
}
