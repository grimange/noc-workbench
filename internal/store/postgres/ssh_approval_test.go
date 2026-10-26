package postgres

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"noc-workbench/internal/inventory"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

func TestIntegrationSSHEnrollmentRechecksInventory(t *testing.T) {
	ctx := context.Background()
	dsn := isolatedDSN(t)
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { db.Close() }()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	c, err := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic SSH lab", ShortCode: "SSHLAB", Status: "active"})
	must(err)
	env, err := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Loopback lab", Kind: "lab", Status: "active"})
	must(err)
	asset, err := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic SSH host", Kind: "server", Lifecycle: "active"})
	must(err)
	ep, err := db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: asset.ID, Host: "127.0.0.1", Protocol: "ssh", Port: 2222, Status: "active"})
	must(err)
	p := sshcli.Profile{Target: sshcli.Target{AssetID: asset.ID, EndpointID: ep.ID, ProfileID: "11111111-1111-4111-8111-111111111111", ProfileVersion: 1}, EndpointUpdatedAt: ep.UpdatedAt, CustomerID: c.ID, EnvironmentID: env.ID, Host: ep.Host, Address: ep.Host, Port: uint16(ep.Port), User: "lab", IdentityFile: "/nonexistent/synthetic-key", IdentitySHA256: strings.Repeat("0", 64)}
	v := sshcli.Enrollment{Profile: p, ApprovedDigest: sshcli.ProfileDigest(p), ApprovedBy: workspace.OperatorID, Evidence: "synthetic independent console evidence", Enabled: true}
	b, _ := json.Marshal(v)
	path := filepath.Join(t.TempDir(), "profile.json")
	must(os.WriteFile(path, b, 0600))
	approval := sshcli.FileApproval{Path: path, Inventory: db, Policy: sshcli.LabPolicy{}}
	actor := workspace.Principal{ID: workspace.OperatorID}
	_, err = approval.Approve(ctx, actor, p.Target, sshcli.ExecutePermission)
	must(err)
	db.Close()
	db, err = Open(ctx, dsn)
	must(err)
	approval.Inventory = db
	_, err = approval.Approve(ctx, actor, p.Target, sshcli.ExecutePermission)
	must(err)
	ep.Port++
	_, err = db.SaveEndpoint(ctx, ep)
	must(err)
	if _, err = approval.Approve(ctx, actor, p.Target, sshcli.ExecutePermission); err == nil {
		t.Fatal("endpoint change retained trust")
	}
	ep.Port--
	ep, err = db.SaveEndpoint(ctx, ep)
	must(err)
	if _, err = approval.Approve(ctx, actor, p.Target, sshcli.ExecutePermission); err == nil {
		t.Fatal("restoring endpoint value silently restored stale approval")
	}
	asset.Lifecycle = "archived"
	_, err = db.SaveAsset(ctx, asset)
	must(err)
	if _, err = approval.Approve(ctx, actor, p.Target, sshcli.ProfileUse); err == nil {
		t.Fatal("archived asset retained authorization")
	}
	t.Log("PASS persisted inventory/restart, endpoint-change suspension, archived asset rejection; no SSH launched")
}
