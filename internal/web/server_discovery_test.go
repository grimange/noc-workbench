package web

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/connections"
	discovery "noc-workbench/internal/integrations/vicidialdiscovery"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/testlab"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type serverDiscoveryExecutor struct{ calls int }

func (e *serverDiscoveryExecutor) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, _ string) (sshcli.Result, error) {
	e.calls++
	at := time.Now().UTC()
	return sshcli.Result{StartedAt: at, EndedAt: at, Stdout: []byte("NW_VICIDIAL_DISCOVERY_1\nvbox=12.0.2\nsvn=4034\napp_version=2.14-968a\nidentity=matched\nweb=present\ndialer=unavailable\napache=2.4.66\nasterisk=18.26.4\ndatabase=10.11.15\nconfig=unavailable\nregistry=unavailable\nreplica=unavailable\nprimary_streams=unavailable\narchive_alias=unavailable\nEND\n")}, nil
}

func TestServerDiscoveryAuthentication(t *testing.T) {
	h, _ := fixture(t)
	if request(h, "POST", "/servers/00000000-0000-4000-8000-000000000001/discovery", nil).Code != 401 {
		t.Fatal("anonymous discovery")
	}
}

func TestIntegrationServerDiscoveryHTTP(t *testing.T) {
	lab := testlab.Start(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var enroll *connections.Service
	var rec connections.Record
	var asset inventory.Asset
	exec := &serverDiscoveryExecutor{}
	h := inventoryFixtureWith(t, func(db *postgres.Store, o *Options) {
		var e error
		enroll, e = connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
		must(e)
		o.Enrollment = enroll
		o.Discovery = collection.NewService(discovery.Executor{Next: exec, Authority: db}, mustDiscoveryRegistry(t), db)
		c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic discovery", ShortCode: "DISCOVERY", Status: "active"})
		must(e)
		env, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Lab", Kind: "lab", Status: "active"})
		must(e)
		asset, e = db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic installation", Kind: "server", Lifecycle: "active"})
		must(e)
		ep, e := db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: asset.ID, Host: "127.0.0.1", Port: lab.Port, Protocol: "ssh", Status: "active"})
		must(e)
		rec, e = enroll.Create(ctx, p, c.ID, env.ID, asset.ID, ep.ID, "127.0.0.1", lab.Credential.ID)
		must(e)
		for _, action := range []string{"submit", "authorize", "inspect", "approve", "verify"} {
			reason := "Independent synthetic lab key"
			if action == "authorize" {
				reason = "standard"
			}
			rec, e = enroll.Act(ctx, p, ep.ID, rec.ID, rec.Revision, action, lab.Fingerprint, reason)
			must(e)
		}
	})
	cookie := authenticate(t, h)
	path := "/servers/" + asset.ID
	page := request(h, "GET", path, nil, cookie)
	if page.Code != 200 || exec.calls != 0 || !strings.Contains(page.Body.String(), "Refresh Discovery") {
		t.Fatal("passive read or form", page.Code)
	}
	token := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())
	if len(token) != 2 {
		t.Fatal("CSRF form")
	}
	form := url.Values{"csrf": {token[1]}, "profile": {rec.ID}, "endpoint": {rec.EndpointID}, "revision": {fmt.Sprint(rec.Revision)}}
	invalid := url.Values{"profile": {rec.ID}}
	if request(h, "POST", path+"/discovery", invalid, cookie).Code != 403 || exec.calls != 0 {
		t.Fatal("CSRF bypass")
	}
	form.Set("revision", fmt.Sprint(rec.Revision-1))
	if request(h, "POST", path+"/discovery", form, cookie).Code != 409 || exec.calls != 0 {
		t.Fatal("stale profile executed")
	}
	form.Set("revision", fmt.Sprint(rec.Revision))
	response := request(h, "POST", path+"/discovery", form, cookie)
	if response.Code != 303 || exec.calls != 1 {
		t.Fatal("refresh", response.Code, response.Body.String())
	}
	for range 2 {
		page = request(h, "GET", path, nil, cookie)
		if page.Code != 200 || exec.calls != 1 {
			t.Fatal("passive discovery execution")
		}
	}
	for _, text := range []string{"Candidate", "Database Primary", "Database Replica", "Archive", "Unknown", "4034", "12.0.2", "Observation ", "unavailable to the approved SSH account"} {
		if !strings.Contains(page.Body.String(), text) {
			t.Fatal("missing evidence detail", text)
		}
	}
	if strings.Contains(page.Body.String(), "Standalone · Confirmed") || strings.Contains(page.Body.String(), "Cluster Member · Confirmed") {
		t.Fatal("fabricated topology")
	}
}

func mustDiscoveryRegistry(t *testing.T) *collection.Registry {
	t.Helper()
	r, e := collection.NewRegistry(discovery.Specs())
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestDiscoveryRequestBudget(t *testing.T) {
	if got := requestBudget("/servers/synthetic/discovery"); got != 12*time.Second {
		t.Fatalf("discovery transport budget: %v", got)
	}
	if got := requestBudget("/servers/synthetic"); got != 3*time.Second {
		t.Fatalf("passive read budget: %v", got)
	}
}
