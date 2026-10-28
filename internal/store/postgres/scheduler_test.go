package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/workspace"
)

func TestIntegrationSchedulerPersistenceAuthorityAndRecovery(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	snap, e := db.Schedules(ctx, actor)
	must(e)
	if len(snap.Profiles) != 0 || snap.Stopped || snap.Paused {
		t.Fatal("migration enabled polling")
	}
	p := scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Interval: 60, Budget: 20, Collectors: []string{"linux.uptime", "linux.memory"}, Enabled: true, Authorized: true}
	if _, e = db.SaveSchedule(ctx, workspace.Principal{ID: "foreign"}, p); e == nil {
		t.Fatal("unauthorized schedule")
	}
	alien := p
	alien.CustomerID = workspace.OperatorID
	if _, e = db.SaveSchedule(ctx, actor, alien); e == nil {
		t.Fatal("crosscustomer schedule")
	}
	p, e = db.SaveSchedule(ctx, actor, p)
	must(e)
	if _, e = db.SaveSchedule(ctx, actor, scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Interval: 60, Budget: 20, Collectors: p.Collectors}); e == nil {
		t.Fatal("duplicate asset schedule")
	}
	collect := collection.NewService(historyExecutor{}, linux.Registry(), db)
	req := collection.Request{Source: "scheduled", ScheduleID: p.ID, Revision: p.Revision, Collectors: p.Collectors, Budget: 20 * time.Second}
	scheduled := collection.WithRequest(ctx, req)
	due := func() {
		_, e := db.pool.Exec(ctx, `UPDATE collection_schedule SET next_due=clock_timestamp()-interval '10 seconds',state='queued' WHERE id=$1`, p.ID)
		must(e)
	}
	latest := func() scheduler.Profile { t.Helper(); v, e := db.Schedules(ctx, actor); must(e); return v.Profiles[0] }
	// Expiry/cancellation while waiting for shared capacity is a scheduling
	// deferral, not an SSH attempt or permanent withdrawal of authorization.
	for _, expired := range []error{context.DeadlineExceeded, context.Canceled, collection.ErrBusy} {
		due()
		before := time.Now().UTC()
		must(db.CompleteSchedule(ctx, p, collection.Run{}, expired, before))
		got := latest()
		if !got.Enabled || !got.Authorized || got.State != "delayed" || got.RetryCount != 0 || got.NextDue.Before(before.Add(5*time.Second)) {
			t.Fatal("admission deferral disabled schedule", got)
		}
	}
	due()
	run, e := collect.Collect(scheduled, actor, target)
	must(e)
	if run.Source != "scheduled" || run.ScheduleID != p.ID || len(run.Results) != 2 || run.State != "completed" {
		t.Fatalf("scheduled provenance %+v", run)
	}
	must(db.CompleteSchedule(ctx, p, run, nil, time.Now().UTC()))
	history, e := db.CollectionHistory(ctx, actor, h, "")
	must(e)
	if len(history) != 1 || history[0].Source != "scheduled" || len(history[0].Results) != 2 {
		t.Fatal("durable subset history")
	}
	prior, e := db.LatestEvidence(ctx, actor, h)
	must(e)
	if len(prior) != 4 {
		t.Fatal("subset evidence", len(prior))
	}
	// Retry one actual transport failure. Parser/permission/host-key failures never retry.
	due()
	failedCollect := collection.NewService(historyExecutor{failAll: true}, linux.Registry(), db)
	failed, e := failedCollect.Collect(scheduled, actor, target)
	must(e)
	failed.State = "failed"
	for i := range failed.Results {
		failed.Results[i].TransportOutcome = "connection_timeout"
	}
	failed.Category = "connection_timeout"
	before := time.Now().UTC()
	must(db.CompleteSchedule(ctx, p, failed, nil, before))
	after := latest()
	if after.RetryCount != 1 || after.NextDue.Before(before.Add(5*time.Second)) || after.NextDue.After(before.Add(7*time.Second)) {
		t.Fatal("retry due", after)
	}
	p = after
	due()
	retry, e := failedCollect.Collect(scheduled, actor, target)
	must(e)
	retry.State = "failed"
	for i := range retry.Results {
		retry.Results[i].TransportOutcome = "connection_timeout"
	}
	must(db.CompleteSchedule(ctx, p, retry, nil, time.Now().UTC()))
	if latest().RetryCount != 0 {
		t.Fatal("retry exhaustion")
	}
	// A running completion cannot erase a global pause or replace its due time.
	p = latest()
	due()
	pausedRun, e := collect.Collect(scheduled, actor, target)
	must(e)
	must(db.SetScheduleControl(ctx, actor, scheduler.Control{Kind: "global", Action: "pause", Paused: true}, time.Now().UTC()))
	paused := latest()
	if e := db.ScheduleDecision(ctx, p, "queued", time.Now().UTC()); e == nil {
		t.Fatal("stale dispatch decision overwrote pause")
	}
	if latest().State != "paused" || !latest().Enabled {
		t.Fatal("pause changed by stale decision")
	}

	pausedRun.State = "failed"
	for i := range pausedRun.Results {
		pausedRun.Results[i].TransportOutcome = "connection_timeout"
	}
	must(db.CompleteSchedule(ctx, p, pausedRun, nil, time.Now().UTC()))
	after = latest()
	if after.State != "paused" || after.RetryCount != 0 || !after.NextDue.Equal(paused.NextDue) {
		t.Fatal("completion overwrote pause", after)
	}
	due()
	if _, e = collect.Collect(scheduled, actor, target); e == nil {
		t.Fatal("global pause bypass")
	}
	must(db.SetScheduleControl(ctx, actor, scheduler.Control{Kind: "global", Action: "stop", Stopped: true}, time.Now().UTC()))
	if _, e = collect.Collect(ctx, actor, target); e == nil {
		t.Fatal("manual bypass stop")
	}
	// Reopening repository preserves configuration and emergency stop.
	reopened, e := Open(ctx, db.pool.Config().ConnString())
	must(e)
	defer reopened.Close()
	v, e := reopened.Schedules(ctx, actor)
	must(e)
	if !v.Stopped || len(v.Profiles) != 1 {
		t.Fatal("restart controls")
	}
	must(db.SetScheduleControl(ctx, actor, scheduler.Control{Kind: "global", Action: "release"}, time.Now().UTC()))
	must(db.SetScheduleControl(ctx, actor, scheduler.Control{Kind: "global", Action: "resume"}, time.Now().UTC()))
	// Asset/customer scope pauses block before any durable attempt/SSH.
	for _, control := range []scheduler.Control{{Kind: "asset", ID: h.AssetID, Paused: true}, {Kind: "customer", ID: h.CustomerID, Paused: true}} {
		must(db.SetScheduleControl(ctx, actor, control, time.Now().UTC()))
		if got := latest(); !got.Paused || got.OwnPaused {
			t.Fatal("independent pause provenance", got)
		}
		due()
		if _, e = collect.Collect(scheduled, actor, target); e == nil {
			t.Fatal("scope pause bypass")
		}
		control.Paused = false
		must(db.SetScheduleControl(ctx, actor, control, time.Now().UTC()))
	}
	// CAS edits invalidate queued work. Withdrawal works even after enrollment invalidation.
	p = latest()
	p.Paused = true
	p, e = db.SaveSchedule(ctx, actor, p)
	must(e)
	due()
	if _, e = collect.Collect(scheduled, actor, target); e == nil {
		t.Fatal("stale queue revision")
	}
	p.Paused = false
	p, e = db.SaveSchedule(ctx, actor, p)
	must(e)
	req.Revision = p.Revision
	scheduled = collection.WithRequest(ctx, req)
	due()
	pending, e := db.BeginCollection(scheduled, actor, target)
	must(e)
	must(db.RecoverCollections(ctx))
	must(db.RecoverSchedules(ctx, time.Now().UTC()))
	if latest().State != "recovered" || !latest().NextDue.After(time.Now()) {
		t.Fatal("restart catchup")
	}
	history, e = db.CollectionHistory(ctx, actor, h, "")
	must(e)
	if history[0].ID != pending.ID || history[0].State != "interrupted" {
		t.Fatal("interrupted replay")
	}
	// Unavailable durable admission must execute no remote commands and fabricate no evidence.
	_, e = db.pool.Exec(ctx, `ALTER TABLE collection_run ADD CONSTRAINT synthetic_outage CHECK(false) NOT VALID`)
	must(e)
	due()
	if _, e = collect.Collect(scheduled, actor, target); !errors.Is(e, collection.ErrPersistence) {
		t.Fatal("write failure", e)
	}
	_, e = db.pool.Exec(ctx, `ALTER TABLE collection_run DROP CONSTRAINT synthetic_outage`)
	must(e)
	due()
	_, e = collect.Collect(scheduled, actor, target)
	must(e)
	_, e = db.pool.Exec(ctx, `UPDATE connection_profile SET state='disabled',revision=revision+1 WHERE id=$1`, target.ProfileID)
	must(e)
	p = latest()
	p.Enabled = false
	p.Authorized = false
	_, e = db.SaveSchedule(ctx, actor, p)
	must(e)
	for _, sql := range []string{`UPDATE collection_run SET schedule_revision=NULL WHERE request_source='scheduled'`, `UPDATE collection_schedule SET customer_id='00000000-0000-4000-8000-000000000001'`, `UPDATE collection_schedule SET interval_seconds=1`, `UPDATE collection_schedule SET collector_ids=ARRAY['linux.uptime','linux.uptime']`, `UPDATE collection_schedule SET collector_ids=ARRAY['arbitrary']`, `UPDATE collection_schedule SET enabled=true,authorized=false`} {
		if _, e = db.pool.Exec(ctx, sql); e == nil {
			t.Fatal("constraint missing", sql)
		}
	}
	must(db.Migrate(ctx))
	t.Log("PASS PostgreSQL: no automatic activation, scoped CAS opt-in, subset provenance/history, retry/exhaustion, pause/completion race, scope controls, stop/restart, interrupted coalescing, write outage/recovery, withdrawal after trust invalidation, direct SQL constraints")
}
func TestIntegrationSingleApplicationOwner(t *testing.T) {
	db, _, _ := collectionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release, e := db.OwnApplication(ctx, cancel)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := db.OwnApplication(ctx, cancel); e == nil {
		second()
		t.Fatal("two active owners")
	}
	release()
	release, e = db.OwnApplication(ctx, cancel)
	if e != nil {
		t.Fatal("owner not released", e)
	}
	release()
}

func TestIntegrationAtomicGlobalControls(t *testing.T) {
	db, _, _ := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	// A stale pause intent carries stopped=false. The repository must ignore it
	// and update only its explicit action after a stop has committed.
	stale := scheduler.Control{Kind: "global", Action: "pause", Stopped: false}
	if e := db.SetScheduleControl(ctx, actor, scheduler.Control{Kind: "global", Action: "stop"}, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e := db.SetScheduleControl(ctx, actor, stale, time.Now()); e != nil {
		t.Fatal(e)
	}
	snap, e := db.Schedules(ctx, actor)
	if e != nil || !snap.Stopped || !snap.Paused {
		t.Fatal("lost emergency stop", snap, e)
	}
	if e = db.SetScheduleControl(ctx, actor, scheduler.Control{Kind: "global", Action: "resume"}, time.Now()); e != nil {
		t.Fatal(e)
	}
	snap, e = db.Schedules(ctx, actor)
	if e != nil || !snap.Stopped || snap.Paused {
		t.Fatal("resume released stop", snap, e)
	}
}
func TestIntegrationApplicationOwnerSessionLoss(t *testing.T) {
	db, _, _ := collectionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release, e := db.OwnApplication(ctx, cancel)
	if e != nil {
		t.Fatal(e)
	}
	var killed bool
	e = db.pool.QueryRow(context.Background(), `SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype='advisory' AND classid=110010 AND objid=110011 AND pid<>pg_backend_pid()`).Scan(&killed)
	if e != nil || !killed {
		release()
		t.Fatal("owner failure injection", e)
	}
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		release()
		t.Fatal("owner loss failed to cancel application")
	}
	release()
	next, done := context.WithCancel(context.Background())
	defer done()
	release, e = db.OwnApplication(next, done)
	if e != nil {
		t.Fatal("successor ownership", e)
	}
	release()
}
