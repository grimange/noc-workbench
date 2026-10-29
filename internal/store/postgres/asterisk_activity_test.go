package postgres

import (
	"context"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/linux"
	ast "noc-workbench/internal/integrations/asterisk"
	activity "noc-workbench/internal/integrations/asteriskactivity"
	ami "noc-workbench/internal/integrations/asteriskami"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
	"testing"
	"time"
)

type activityExecutor struct {
	snap   activity.Snapshot
	at     time.Time
	fail   bool
	during func()
}

func (x *activityExecutor) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, id string) (sshcli.Result, error) {
	b := []byte("Asterisk 18.26.4-vici\nNW_ACTIVITY_runtime\n" + x.snap.Runtime + "  -\nNW_ACTIVITY_channels\n")
	for _, c := range x.snap.Channels {
		b = append(b, []byte(c.Name+"!private!private!1!"+c.State+"!private!private!private!private!private!3!0!!"+c.ID+"\n")...)
	}
	b = append(b, []byte("\nNW_ACTIVITY_bridges\nBridge-ID Chans Type Technology Duration\nNW_ACTIVITY_meetme\n\nNW_ACTIVITY_confbridge\nConference Bridge Name Users Marked Locked Muted\n================ ===== ====== ===== =====\nNW_ACTIVITY_runtime_end\n"+x.snap.Runtime+"  -\nNW_ACTIVITY_END\n")...)
	r := sshcli.Result{CommandID: id, StartedAt: x.at, EndedAt: x.at.Add(time.Millisecond), Stdout: b}
	if x.during != nil {
		x.during()
		x.during = nil
	}
	if x.fail {
		return r, &sshcli.Failure{Category: sshcli.ExecutionTimeout}
	}
	return r, nil
}
func TestIntegrationActivityReconciliationPersistenceIsolation(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk", true))
	_, e := db.SaveSchedule(ctx, p, scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Interval: 60, Budget: 20, Collectors: []string{"linux.uptime"}, Enabled: true, Authorized: true})
	must(e)
	must(db.SetAMIGrant(ctx, p, h, target, "synthetic", strings.Repeat("a", 64), true))
	bindings, e := db.AMIBindings(ctx, p)
	must(e)
	b := bindings[0]
	now := time.Now().UTC().Truncate(time.Microsecond)
	session, e := db.BeginAMISession(ctx, b, now.Add(-time.Second))
	must(e)
	must(db.AMITransition(ctx, b, session, "connected", "", now.Add(-time.Second), 0, false))
	event := ami.Event{Name: "Newchannel", Activity: activity.Event{Channel: "SIP/phone-00000001", Uniqueid: "1.1", State: "Up"}, ReceivedAt: now, Sequence: 1}
	if db.PersistAMIEvent(ctx, b, session, event, 0) == nil {
		t.Fatal("no activity grant accepted")
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk_activity", true))
	bindings, e = db.AMIBindings(ctx, p)
	must(e)
	b = bindings[0]
	// Advance the fake session heartbeat with the controlled observation clock.
	// Persistence uses the database wall clock; race instrumentation may take
	// longer than the synthetic one-second lifecycle increments.
	view := func(store *Store, at time.Time) (activity.View, error) {
		must(db.AMITransition(ctx, b, session, "connected", "", at, 0, false))
		return store.ActivityView(ctx, p, h, target, at)
	}
	if !b.Activity {
		t.Fatal("subscription not expanded")
	}
	x := &activityExecutor{snap: activity.Snapshot{Runtime: strings.Repeat("a", 64), Channels: []activity.Channel{{ID: "1.1", Name: "SIP/phone-00000001", State: "Up"}}}, at: now}
	svc := collection.NewService(x, linux.Registry().Extend(ast.Specs()...), db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{activity.Collector}})
	run, e := svc.Collect(req, p, target)
	must(e)
	if run.SuccessCount != 1 {
		t.Fatalf("snapshot failed %+v", run)
	}
	v, e := view(db, now.Add(time.Second))
	must(e)
	if !v.Current || len(v.Channels) != 1 {
		t.Fatalf("baseline %+v", v)
	}
	// Activity is operational data, not an unknown health selector.
	_, e = db.EvaluationEvidence(ctx, p, h, time.Now().UTC().Add(time.Second))
	must(e)
	must(db.PersistAMIEvent(ctx, b, session, event, 0))
	must(db.PersistAMIEvent(ctx, b, session, event, 0))
	var n int
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM asterisk_ami_event WHERE session_id=$1`, session).Scan(&n))
	if n != 1 {
		t.Fatal("duplicate journal")
	}
	// An event committed while the remote snapshot is being collected is
	// replayed, never silently overwritten by the older snapshot.
	x.at = now.Add(time.Second)
	x.during = func() {
		e := event
		e.Sequence = 2
		e.Activity.Uniqueid = "1.2"
		e.ReceivedAt = x.at.Add(500 * time.Microsecond)
		must(db.PersistAMIEvent(ctx, b, session, e, 0))
	}
	_, e = svc.Collect(req, p, target)
	must(e)
	v, e = view(db, now.Add(2*time.Second))
	must(e)
	if v.Current || len(v.Channels) != 2 || !strings.Contains(v.Reason, "during snapshot") {
		t.Fatal("concurrent event lost or falsely current", v)
	}
	// A fresh empty snapshot replaces current state without inventing hangup events.
	x.snap.Channels = nil
	x.at = now.Add(2 * time.Second)
	_, e = svc.Collect(req, p, target)
	must(e)
	v, e = view(db, now.Add(3*time.Second))
	must(e)
	if !v.Current || len(v.Channels) != 0 {
		t.Fatal("obsolete active channels survived", v)
	}
	reopened, e := Open(ctx, db.pool.Config().ConnString())
	must(e)
	defer reopened.Close()
	v, e = view(reopened, now.Add(3*time.Second))
	must(e)
	if !v.Current || v.Generation != 3 {
		t.Fatal("restart persistence", v)
	}
	alien := h
	alien.CustomerID = workspace.OperatorID
	if _, e = db.ActivityView(ctx, p, alien, target, now); e == nil {
		t.Fatal("cross customer API")
	}
	if _, e = db.pool.Exec(ctx, `UPDATE asterisk_activity_state SET customer_id=$1`, workspace.OperatorID); e == nil {
		t.Fatal("cross customer SQL")
	}
	// A failed snapshot retains history but invalidates the current active set.
	x.fail = true
	x.at = now.Add(4 * time.Second)
	_, e = svc.Collect(req, p, target)
	must(e)
	v, e = view(db, now.Add(5*time.Second))
	must(e)
	if v.Current {
		t.Fatal("failed snapshot current")
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk_activity", false))
	event.Sequence = 3
	event.ReceivedAt = now.Add(6 * time.Second)
	if db.PersistAMIEvent(ctx, b, session, event, 0) == nil {
		t.Fatal("queued event accepted after revoke")
	}
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM asterisk_ami_event WHERE session_id=$1`, session).Scan(&n))
	if n != 2 {
		t.Fatal("revoked data journaled")
	}
	must(db.RecoverAMI(ctx))
	v, e = db.ActivityView(ctx, p, h, target, now.Add(7*time.Second))
	must(e)
	if v.Current {
		t.Fatal("disconnected current")
	}
}
