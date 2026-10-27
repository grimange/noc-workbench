package web

import (
	"context"
	"fmt"
	"net/url"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/testlab"
	"noc-workbench/internal/workspace"
	"regexp"
	"strings"
	"testing"
)

func TestIntegrationSchedulingHTTP(t *testing.T) {
	lab := testlab.Start(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	var db *postgres.Store
	var svc *connections.Service
	var discover *collection.Service
	var schedule *scheduler.Service
	var c inventory.Customer
	var env inventory.Environment
	var asset inventory.Asset
	var ep inventory.Endpoint
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	h := inventoryFixtureWith(t, func(store *postgres.Store, o *Options) {
		db = store
		var e error
		svc, e = connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
		must(e)
		discover = collection.NewService(svc, linux.Registry())
		o.Enrollment = svc
		o.Discovery = discover
		c, e = db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic Linux discovery", ShortCode: "LINUXLAB", Status: "active"})
		must(e)
		env, e = db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Loopback lab", Kind: "lab", Status: "active"})
		must(e)
		asset, e = db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic observed host", Kind: "server", Lifecycle: "active"})
		must(e)
		ep, e = db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: asset.ID, Host: "127.0.0.1", Port: lab.Port, Protocol: "ssh", Status: "active"})
		must(e)
		schedule = scheduler.New(db, discover)
		o.Scheduler = schedule
	})
	path := fmt.Sprintf("/customers/%s/environments/%s/assets/%s/linux", c.ID, env.ID, asset.ID)
	cookie := authenticate(t, h)
	page := request(h, "GET", path, nil, cookie)
	if page.Code != 200 {
		t.Fatal(page.Code, page.Body.String())
	}
	// No enrollment and no collection merely by visiting.
	if strings.Contains(page.Body.String(), "Last requested collection</h2>") {
		t.Fatal("automatic collection")
	}
	r, e := svc.Create(ctx, actor, c.ID, env.ID, asset.ID, ep.ID, "127.0.0.1", lab.Credential.ID)
	must(e)
	act := func(action, fp, evidence string) {
		t.Helper()
		r, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, action, fp, evidence)
		must(e)
	}
	act("submit", "", "")
	act("authorize", "", "authorized")
	act("inspect", "", "")
	if r.Details.CandidateFingerprint != lab.Fingerprint {
		t.Fatal("independent fingerprint mismatch")
	}
	act("approve", lab.Fingerprint, "Synthetic lab console host key")
	// Approval alone is insufficient: discovery requires verified connectivity.
	_, e = svc.Execute(ctx, actor, r.Target(), "linux.uptime.v1")
	if e == nil {
		t.Fatal("unverified discovery executed")
	}
	act("verify", "", "")
	if r.State != "connection_verified" {
		t.Fatal(r.State, r.Details.LastCategory)
	}
	page = request(h, "GET", path, nil, cookie)
	csrfMatch := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())
	if len(csrfMatch) != 2 {
		t.Fatal("missing collect form")
	}
	csrf := csrfMatch[1]

	schedulePath := fmt.Sprintf("/customers/%s/environments/%s/assets/%s/schedule", c.ID, env.ID, asset.ID)
	form := func() url.Values {
		return url.Values{"csrf": {csrf}, "profile": {r.ID}, "revision": {fmt.Sprint(r.Revision)}, "schedule_revision": {"0"}, "action": {"save"}, "collectors": {"linux.uptime", "linux.memory"}, "interval": {"60"}, "authorize": {"yes"}}
	}
	if request(h, "POST", schedulePath, form()).Code != 401 {
		t.Fatal("anonymous scheduling")
	}
	bad := form()
	bad.Del("csrf")
	if request(h, "POST", schedulePath, bad, cookie).Code != 403 {
		t.Fatal("missing CSRF")
	}
	bad = form()
	bad.Set("interval", "1")
	if request(h, "POST", schedulePath, bad, cookie).Code != 409 {
		t.Fatal("unsafe interval")
	}
	bad = form()
	bad.Set("collectors", "unknown")
	if request(h, "POST", schedulePath, bad, cookie).Code != 409 {
		t.Fatal("unknown collector")
	}
	bad = form()
	bad.Set("authorize", "")
	if response := request(h, "POST", schedulePath, bad, cookie); response.Code != 303 {
		t.Fatal(response.Code, response.Body.String())
	}
	snap, e := schedule.Status(ctx, actor)
	must(e)
	if len(snap.Profiles) != 1 || snap.Profiles[0].Enabled || snap.Profiles[0].Authorized {
		t.Fatal("implicit polling authority")
	}
	f := form()
	f.Set("schedule_revision", fmt.Sprint(snap.Profiles[0].Revision))
	if response := request(h, "POST", schedulePath, f, cookie); response.Code != 303 {
		t.Fatal(response.Code, response.Body.String())
	}
	if request(h, "POST", schedulePath, f, cookie).Code != 409 {
		t.Fatal("stale schedule edit")
	}
	for _, action := range []string{"pause", "resume", "disable"} {
		snap, e = schedule.Status(ctx, actor)
		must(e)
		f = form()
		f.Set("schedule_revision", fmt.Sprint(snap.Profiles[0].Revision))
		f.Set("action", action)
		if response := request(h, "POST", schedulePath, f, cookie); response.Code != 303 {
			t.Fatal(action, response.Code, response.Body.String())
		}
		snap, e = schedule.Status(ctx, actor)
		must(e)
		p := snap.Profiles[0]
		if action == "pause" && !p.Paused || action == "resume" && p.Paused || action == "disable" && (p.Enabled || p.Authorized) {
			t.Fatal(action, p)
		}
	}
	for _, action := range []string{"stop", "pause", "resume", "release"} {
		f = url.Values{"csrf": {csrf}, "scope": {"global"}, "action": {action}}
		if response := request(h, "POST", "/scheduler", f, cookie); response.Code != 303 {
			t.Fatal(action, response.Code, response.Body.String())
		}
		snap, e = schedule.Status(ctx, actor)
		must(e)
		if action != "release" && !snap.Stopped {
			t.Fatal("pause/resume released emergency stop")
		}
	}
	for _, p := range []string{path, "/scheduler"} {
		response := request(h, "GET", p, nil, cookie)
		if response.Code != 200 || !strings.Contains(response.Body.String(), "Scheduled collection") && p == path {
			t.Fatal(response.Code, response.Body.String())
		}
	}
	history, e := db.CollectionHistory(ctx, actor, collection.HistoryScope{CustomerID: c.ID, EnvironmentID: env.ID, AssetID: asset.ID}, "")
	must(e)
	if len(history) != 0 {
		t.Fatal("GET/configuration executed SSH collection")
	}
}
