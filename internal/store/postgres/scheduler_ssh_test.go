package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/testlab"
	"noc-workbench/internal/workspace"
)

func TestIntegrationRealScheduledSSH(t *testing.T) {
	lab := testlab.Start(t)
	ctx := context.Background()
	db, e := Open(ctx, isolatedDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	actor := workspace.Principal{ID: workspace.OperatorID}
	c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic scheduled SSH", ShortCode: "SCHEDULE", Status: "active"})
	must(e)
	env, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Authorized loopback lab", Kind: "lab", Status: "active"})
	must(e)
	a, e := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic scheduler host", Kind: "server", Lifecycle: "active"})
	must(e)
	ep, e := db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Host: "127.0.0.1", Port: int(lab.Port), Protocol: "ssh", Status: "active"})
	must(e)
	enrollment, e := connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
	must(e)
	rec, e := enrollment.Create(ctx, actor, c.ID, env.ID, a.ID, ep.ID, ep.Host, lab.Credential.ID)
	must(e)
	act := func(op, fp, evidence string) {
		t.Helper()
		rec, e = enrollment.Act(ctx, actor, rec.EndpointID, rec.ID, rec.Revision, op, fp, evidence)
		must(e)
	}
	act("submit", "", "")
	act("authorize", "", "authorized")
	act("inspect", "", "")
	if rec.Details.CandidateFingerprint != lab.Fingerprint {
		t.Fatal("independent identity")
	}
	act("approve", lab.Fingerprint, "Synthetic console fingerprint")
	act("verify", "", "")
	discovery := collection.NewService(enrollment, linux.Registry(), db)
	s := scheduler.New(db, discovery)
	p, e := s.Save(ctx, actor, scheduler.Profile{CustomerID: c.ID, EnvironmentID: env.ID, AssetID: a.ID, Target: rec.Target(), Collectors: linux.Registry().IDs(), Interval: 60, Budget: 20, Enabled: true, Authorized: true})
	must(e)
	due := func() {
		_, e := db.pool.Exec(ctx, `UPDATE collection_schedule SET next_due=clock_timestamp()-interval '1 second' WHERE id=$1`, p.ID)
		must(e)
	}
	wait := func(count int) {
		t.Helper()
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		poll := time.NewTicker(10 * time.Millisecond)
		defer poll.Stop()
		for {
			var n int
			must(db.pool.QueryRow(ctx, `SELECT count(*) FROM collection_run WHERE schedule_id=$1 AND state<>'running'`, p.ID).Scan(&n))
			if n == count {
				return
			}
			select {
			case <-deadline.C:
				t.Fatal("scheduled collection stalled", n)
			case <-poll.C:
			}
		}
	}
	due()
	must(s.Step(ctx, time.Now().UTC()))
	wait(1)
	h := collection.HistoryScope{CustomerID: c.ID, EnvironmentID: env.ID, AssetID: a.ID}
	history, e := db.CollectionHistory(ctx, actor, h, "")
	must(e)
	if history[0].Source != "scheduled" || history[0].SuccessCount != 5 {
		t.Fatalf("real run %+v", history[0])
	}
	facts, e := db.LatestEvidence(ctx, actor, h)
	must(e)
	hostname, _ := os.Hostname()
	found := false
	for _, o := range facts {
		if o.Key == "linux.hostname" {
			found = true
			if o.Value.Text != hostname {
				t.Fatal("actual hostname mismatch")
			}
		}
		if o.Transport != "ssh" || o.RunID != history[0].ID {
			t.Fatal("provenance")
		}
	}
	if !found {
		t.Fatal("no Linux identity")
	}
	must(s.Control(ctx, actor, scheduler.Control{Kind: "global", Action: "pause"}))
	due()
	must(s.Step(ctx, time.Now().UTC()))
	var n int
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM collection_run`).Scan(&n))
	if n != 1 {
		t.Fatal("paused dispatch")
	}
	must(s.Control(ctx, actor, scheduler.Control{Kind: "global", Action: "resume"}))
	due()
	must(s.Step(ctx, time.Now().UTC()))
	wait(2)
	must(s.Control(ctx, actor, scheduler.Control{Kind: "global", Action: "stop"}))
	if _, e = discovery.Collect(ctx, actor, rec.Target()); e == nil {
		t.Fatal("manual stop bypass")
	}
	must(db.RecoverSchedules(ctx, time.Now().UTC()))
	snap, e := db.Schedules(ctx, actor)
	must(e)
	if !snap.Stopped {
		t.Fatal("restart released stop")
	}
	must(s.Control(ctx, actor, scheduler.Control{Kind: "global", Action: "release"}))
	// Actual host key changes must disable the profile with no automatic retry.
	wrong, e := os.ReadFile(lab.Dir + "/wrong")
	must(e)
	lab.ReplaceHostKey(t, wrong)
	due()
	must(s.Step(ctx, time.Now().UTC()))
	wait(3)
	deadline := time.Now().Add(5 * time.Second)
	for {
		snap, e = db.Schedules(ctx, actor)
		must(e)
		if !snap.Profiles[0].Enabled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("key mismatch schedule not suspended", snap.Profiles[0])
		}
		time.Sleep(time.Millisecond)
	}
	if snap.Profiles[0].RetryCount != 0 {
		t.Fatal("host key retried")
	}
	history, e = db.CollectionHistory(ctx, actor, h, "")
	must(e)
	if !strings.Contains(history[0].Category, "host_key_mismatch") {
		t.Fatal("changed key diagnostic", history[0].Category)
	}
	retained, e := db.LatestEvidence(ctx, actor, h)
	must(e)
	if len(retained) == 0 {
		t.Fatal("failed attempt erased successful observations")
	}
	t.Log("PASS actual ordinary-user OpenSSH: independent enrollment/identity, five scheduled Linux collectors, source measurements/provenance, durable history, pause/resume, stop/manual rejection, restart controls, actual changed-key suspension/no retry, prior valid evidence retained; disposable resources cleaned")
}
