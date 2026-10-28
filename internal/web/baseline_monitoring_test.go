package web

import (
	"context"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/baseline"
	"noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/collectors/services"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/testlab"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type resourceExecutor struct{ calls atomic.Int64 }

func (e *resourceExecutor) Execute(ctx context.Context, p workspace.Principal, target sshcli.Target, id string) (sshcli.Result, error) {
	e.calls.Add(1)
	at := time.Now().UTC()
	if id == "linux.services.v1" {
		return (&serverRuntimeExecutor{}).Execute(ctx, p, target, id)
	}
	data := map[string]string{
		"linux.identity.v1":    "synthetic\n6.1\nx86_64\nNAME=\"Synthetic Linux\"\nVERSION_ID=1\n",
		"linux.uptime.v1":      "123.456 12.34\n",
		"linux.load.v1":        "0.10 1.25 2.00 1/123 99\nCPU_COUNT=4\n",
		"linux.memory.v1":      "MemTotal: 1048576 kB\nMemAvailable: 524288 kB\nMemFree: 128 kB\n",
		"linux.filesystems.v1": "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/synthetic 1000 100 900 10% /\n",
		"linux.baseline.v1":    "NW_BASELINE_1\ncpu|25\nprocess|42|asterisk|10|1024\nprocess|56|perl|5|2048\nprocess_status|sampled_up_to_4096\npage_bytes|4096\nswap_total|1024\nswap_free|512\npressure|1\nunit|asterisk.service|loaded|inactive|dead\nunit|oneshot.service|loaded|active|exited\nunit|mariadb.service|loaded|active|running\nunits_status|observed\nfiles_status|unavailable\njob|system cron|* * * * *|AST_update.pl\ncron_status|user_cron_unavailable_or_observed\ntimers_status|unavailable\nEND\n",
	}
	return sshcli.Result{StartedAt: at, EndedAt: at, Stdout: []byte(data[id])}, nil
}

type completionRepo struct {
	*postgres.Store
	done chan error
}

func (r completionRepo) CompleteSchedule(ctx context.Context, p scheduler.Profile, run collection.Run, err error, at time.Time) error {
	e := r.Store.CompleteSchedule(ctx, p, run, err, at)
	r.done <- e
	return e
}
func TestIntegrationBaselineConsoleAutomatic(t *testing.T) {
	lab := testlab.Start(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var db *postgres.Store
	var rec connections.Record
	var asset inventory.Asset
	var sched *scheduler.Service
	exec := &resourceExecutor{}
	done := make(chan error, 1)
	h := inventoryFixtureWith(t, func(store *postgres.Store, o *Options) {
		db = store
		enroll, e := connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
		must(e)
		o.Enrollment = enroll
		svc := collection.NewService(baseline.Executor{Next: services.Executor{Next: exec, Authority: db}, Authority: db}, linux.Registry().Extend(services.Specs()...).Extend(baseline.Specs()...), db)
		o.Discovery = svc
		sched = scheduler.New(completionRepo{db, done}, svc)
		o.Scheduler = sched
		c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic discovery", ShortCode: "BASE", Status: "active"})
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
			reason := "Independent synthetic key"
			if action == "authorize" {
				reason = "standard"
			}
			rec, e = enroll.Act(ctx, p, ep.ID, rec.ID, rec.Revision, action, lab.Fingerprint, reason)
			must(e)
		}
	})
	must(db.StandardMonitoringAllowed(ctx, p, rec.Target()))
	if db.IntegrationAllowed(ctx, p, rec.Target(), "asterisk_helper") == nil {
		t.Fatal("new standard enrollment implicitly authorized helper")
	}
	// Verification creates the schedule without any browser or manual enable call.
	snap, e := sched.Status(ctx, p)
	must(e)
	if len(snap.Profiles) != 1 || !snap.Profiles[0].Enabled || snap.Profiles[0].Interval != 60 || exec.calls.Load() != 0 {
		t.Fatal(snap)
	}
	must(sched.Step(ctx, time.Now().UTC()))
	select {
	case e := <-done:
		must(e)
	case <-time.After(10 * time.Second):
		t.Fatal("background dispatch did not finish")
	}
	if exec.calls.Load() != 7 {
		t.Fatal("default profile", exec.calls.Load())
	}
	// A fresh scheduler instance resumes the persisted profile before a browser
	// has authenticated. Advance the explicit scheduler clock to its due time.
	snap, e = sched.Status(ctx, p)
	must(e)
	recoveryAt := time.Now().UTC().Add(-2 * time.Minute)
	// Repository admission deliberately uses the database clock. Arrange a due
	// persisted profile with the repository's explicit test clock, then recover
	// it in the past so the real admission guard can accept it without sleeps.
	must(db.SetScheduleControl(ctx, p, scheduler.Control{Kind: "asset", ID: asset.ID}, recoveryAt.Add(-time.Minute)))
	must(db.RecoverSchedules(ctx, recoveryAt))
	svc := collection.NewService(baseline.Executor{Next: services.Executor{Next: exec, Authority: db}, Authority: db}, linux.Registry().Extend(services.Specs()...).Extend(baseline.Specs()...), db)
	restarted := scheduler.New(completionRepo{db, done}, svc)
	must(restarted.Step(ctx, time.Now().UTC()))
	select {
	case e := <-done:
		must(e)
	case <-time.After(10 * time.Second):
		t.Fatal("restart did not resume background dispatch")
	}
	if exec.calls.Load() != 14 {
		t.Fatal("restart profile dispatch", exec.calls.Load())
	}
	cookie := authenticate(t, h)
	path := "/servers/" + asset.ID
	page := request(h, "GET", path, nil, cookie)
	if page.Code != 200 {
		t.Fatal(page.Code, page.Body.String())
	}
	for _, text := range []string{"25.0%", "RAM used", "512.0 MiB", "Load · 1 minute", "Filesystems", "Top CPU consumers", "asterisk", "Services — systemd units", "oneshot.service", "exited", "Scheduled jobs", "AST_update.pl", "Application process observations", "asterisk.service · stopped", "Process running"} {
		if !strings.Contains(page.Body.String(), text) {
			t.Fatal("missing resource", text)
		}
	}
	dash := request(h, "GET", "/", nil, cookie)
	if dash.Code != 200 || !strings.Contains(dash.Body.String(), ">25.0%</td>") || !strings.Contains(dash.Body.String(), "512.0 MiB available") || !strings.Contains(dash.Body.String(), "10% · /") || !strings.Contains(dash.Body.String(), "0 failed units") {
		t.Fatal(dash.Body.String())
	}
	consoleBrowser(t, h, cookie, path, true)
	if exec.calls.Load() != 14 {
		t.Fatal("passive reads executed collection")
	}
	must(sched.Control(ctx, p, scheduler.Control{Kind: "asset", ID: asset.ID, Paused: true}))
	page = request(h, "GET", path, nil, cookie)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Historical — monitoring paused or not authorized") || strings.Contains(page.Body.String(), "<strong>Process running</strong>") {
		t.Fatal("paused history", page.Body.String())
	}
	// A changed-key enrollment remains blocked, but its trust incident is visible.
	rec.State = "identity_changed"
	rec.Details.LastCategory = "host_key_mismatch"
	rec.Details.ApprovedKey = ""
	_, e = db.SaveEnrollment(ctx, p, rec, rec.Revision, "verify")
	must(e)
	must(sched.Control(ctx, p, scheduler.Control{Kind: "asset", ID: asset.ID, Paused: false}))
	page = request(h, "GET", path, nil, cookie)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "SSH host-key trust problem") || strings.Contains(page.Body.String(), "<progress") {
		t.Fatal("quarantine lost diagnostic or gained current data", page.Body.String())
	}

}
