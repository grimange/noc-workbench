package web

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/collectors/services"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/testlab"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type serverRuntimeExecutor struct{ calls int }

func (e *serverRuntimeExecutor) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, _ string) (sshcli.Result, error) {
	e.calls++
	at := time.Now().UTC()
	output := "NW_RUNTIME_1\n"
	for _, id := range services.IDs {
		support := "linux"
		unit := "loaded"
		active := "running"
		name := map[string]string{"asterisk": "asterisk.service", "database": "mariadb.service", "apache": "apache2.service"}[id]
		if name == "" {
			support = "svn4034"
			unit = "unavailable"
			active = "unavailable"
			name = "unknown"
		}
		if id == "asterisk" {
			active = "stopped"
		}
		output += id + "|present|" + unit + "|" + active + "|observed|" + support + "|" + name + "\n"
	}
	output += "END\n"
	return sshcli.Result{StartedAt: at, EndedAt: at, Stdout: []byte(output)}, nil
}

func TestServerMonitoringAuthentication(t *testing.T) {
	h, _ := fixture(t)
	for _, path := range []string{"/console/events", "/servers/00000000-0000-4000-8000-000000000001/events"} {
		if request(h, "GET", path, nil).Code != 401 {
			t.Fatal("anonymous SSE", path)
		}
	}
	if request(h, "POST", "/servers/00000000-0000-4000-8000-000000000001/monitoring", nil).Code != 401 {
		t.Fatal("anonymous discovery")
	}
}

func TestIntegrationServerMonitoringHTTP(t *testing.T) {
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
	exec := &serverRuntimeExecutor{}
	var svc *collection.Service
	var schedules *scheduler.Service
	h := inventoryFixtureWith(t, func(db *postgres.Store, o *Options) {
		var e error
		enroll, e = connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
		must(e)
		o.Enrollment = enroll
		svc = collection.NewService(services.Executor{Next: exec, Authority: db}, linux.Registry().Extend(services.Specs()...), db)
		o.Discovery = svc
		schedules = scheduler.New(db, svc)
		o.Scheduler = schedules
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
				reason = "authorized"
			}
			rec, e = enroll.Act(ctx, p, ep.ID, rec.ID, rec.Revision, action, lab.Fingerprint, reason)
			must(e)
		}
	})
	cookie := authenticate(t, h)
	path := "/servers/" + asset.ID
	page := request(h, "GET", path, nil, cookie)
	if page.Code != 200 || exec.calls != 0 || !strings.Contains(page.Body.String(), "Enrollment and baseline monitoring authority") {
		t.Fatal("passive read or form", page.Code)
	}
	token := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())
	if len(token) != 2 {
		t.Fatal("CSRF form")
	}
	form := url.Values{"csrf": {token[1]}, "profile": {rec.ID}, "endpoint": {rec.EndpointID}, "revision": {fmt.Sprint(rec.Revision)}, "schedule_revision": {"0"}, "action": {"enable"}, "authorize": {"yes"}}
	invalid := url.Values{"action": {"enable"}}
	if request(h, "POST", path+"/monitoring", invalid, cookie).Code != 403 || exec.calls != 0 {
		t.Fatal("CSRF bypass")
	}
	form.Set("revision", fmt.Sprint(rec.Revision-1))
	if request(h, "POST", path+"/monitoring", form, cookie).Code != 409 || exec.calls != 0 {
		t.Fatal("stale enrollment")
	}
	form.Set("revision", fmt.Sprint(rec.Revision))
	must(schedules.Control(ctx, p, scheduler.Control{Kind: "customer", ID: rec.CustomerID, Paused: true}))
	if request(h, "POST", path+"/monitoring", form, cookie).Code != 409 || exec.calls != 0 {
		t.Fatal("parent pause bypassed")
	}
	must(schedules.Control(ctx, p, scheduler.Control{Kind: "customer", ID: rec.CustomerID, Paused: false}))
	response := request(h, "POST", path+"/monitoring", form, cookie)
	if response.Code != 303 || exec.calls != 0 {
		t.Fatal("opt-in response or synchronous SSH", response.Code, response.Body.String())
	}
	snap, e := schedules.Status(ctx, p)
	must(e)
	if len(snap.Profiles) != 1 || snap.Profiles[0].Interval != 60 || len(snap.Profiles[0].Collectors) != 1 || snap.Profiles[0].Collectors[0] != services.Collector || !snap.Profiles[0].Enabled {
		t.Fatal("default profile", snap)
	}
	if request(h, "POST", path+"/monitoring", form, cookie).Code != 409 {
		t.Fatal("stale schedule accepted")
	}
	_, e = svc.Collect(collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{services.Collector}}), p, rec.Target())
	must(e)
	for range 2 {
		page = request(h, "GET", path, nil, cookie)
		if page.Code != 200 || exec.calls != 1 {
			t.Fatal("passive SSH")
		}
	}
	for _, text := range []string{"Application process observations", "Monitoring enabled", "Process running", "mariadb.service", "apache2.service", "linux.services v1", "Historical / last observed:", "Freshness: fresh", "observation "} {
		if !strings.Contains(page.Body.String(), text) {
			t.Fatal("missing evidence", text, page.Body.String())
		}
	}
	// Dashboard bulk reader must show the same persisted state without SSH.
	dashboard := request(h, "GET", "/", nil, cookie)
	for _, text := range []string{"Synthetic installation", "Monitoring enabled", "8 running", "Freshness: fresh", "Topology: Unknown", "PHT"} {
		if dashboard.Code != 200 || !strings.Contains(dashboard.Body.String(), text) {
			t.Fatal("dashboard evidence", text, dashboard.Body.String())
		}
	}
	if exec.calls != 1 {
		t.Fatal("dashboard collected")
	}
	if !strings.Contains(page.Body.String(), "asterisk.service · stopped") {
		t.Fatal("lost independent unit state")
	}
	// A passive credential-catalog change must invalidate current runtime even
	// though the persisted connection profile and prior samples are unchanged.
	catalog, e := os.ReadFile(lab.Catalog)
	must(e)
	must(os.WriteFile(lab.Catalog, []byte("[]\n"), 0600))
	page = request(h, "GET", path, nil, cookie)
	if page.Code != 200 || exec.calls != 1 || strings.Contains(page.Body.String(), "<strong>Process running</strong>") || !strings.Contains(page.Body.String(), "Historical / last observed: Running") {
		t.Fatal("revoked credential presented current runtime", page.Body.String())
	}
	dashboard = request(h, "GET", "/", nil, cookie)
	if dashboard.Code != 200 || strings.Contains(dashboard.Body.String(), "8 running") || exec.calls != 1 {
		t.Fatal("revoked dashboard evidence", dashboard.Body.String())
	}
	must(os.WriteFile(lab.Catalog, catalog, 0600))
	// An explicitly paused schedule is not resumed by runtime enable.
	own := snap.Profiles[0]
	own.Paused = true
	_, e = schedules.Save(ctx, p, own)
	must(e)
	form.Set("schedule_revision", fmt.Sprint(snap.Profiles[0].Revision))
	// Controls increment revision; reload the current revision.
	paused, e := schedules.Status(ctx, p)
	must(e)
	form.Set("schedule_revision", fmt.Sprint(paused.Profiles[0].Revision))
	if request(h, "POST", path+"/monitoring", form, cookie).Code != 409 {
		t.Fatal("schedule pause bypassed")
	}
	own = paused.Profiles[0]
	own.Paused = false
	_, e = schedules.Save(ctx, p, own)
	must(e)
	snap, e = schedules.Status(ctx, p)
	must(e)
	form.Set("action", "disable")
	form.Set("schedule_revision", fmt.Sprint(snap.Profiles[0].Revision))
	if response = request(h, "POST", path+"/monitoring", form, cookie); response.Code != 303 {
		t.Fatal("disable", response.Code)
	}
	page = request(h, "GET", path, nil, cookie)
	if exec.calls != 1 || !strings.Contains(page.Body.String(), "Monitoring disabled") || !strings.Contains(page.Body.String(), "<strong>Unknown</strong>") || !strings.Contains(page.Body.String(), "Historical / last observed: Running") {
		t.Fatal("disabled fabricated current state", page.Body.String())
	}
	consoleBrowser(t, h, cookie, path)
	if exec.calls != 1 {
		t.Fatal("browser triggered collection")
	}

}
