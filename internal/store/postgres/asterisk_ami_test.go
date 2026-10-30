package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	ami "noc-workbench/internal/integrations/asteriskami"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/workspace"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestIntegrationAMILifecyclePersistenceIsolation(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(db.SetIntegration(ctx, actor, h, target, "asterisk", true))
	_, e := db.SaveSchedule(ctx, actor, scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Interval: 60, Budget: 20, Collectors: []string{"linux.uptime"}, Enabled: true, Authorized: true})
	must(e)
	digest := strings.Repeat("a", 64)
	if db.SetAMIGrant(ctx, workspace.Principal{}, h, target, "synthetic", digest, true) == nil {
		t.Fatal("unauthenticated grant")
	}
	alien := h
	alien.CustomerID = workspace.OperatorID
	if db.SetAMIGrant(ctx, actor, alien, target, "synthetic", digest, true) == nil {
		t.Fatal("cross customer grant")
	}
	must(db.SetAMIGrant(ctx, actor, h, target, "synthetic", digest, true))
	// Enrichment must not retain the grant result's connection while querying
	// the pool again; this used to deadlock even one view with MaxConns=1.
	config := db.pool.Config()
	config.MaxConns = 1
	pool, poolErr := pgxpool.NewWithConfig(ctx, config)
	must(poolErr)
	defer pool.Close()
	single := &Store{pool: pool}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, poolErr = single.AMIBindings(bounded, actor)
	must(poolErr)
	_, poolErr = single.AMIView(bounded, actor, h, target, time.Now().UTC())
	must(poolErr)
	bindings, e := db.AMIBindings(ctx, actor)
	must(e)
	if len(bindings) != 1 || !bindings[0].Eligible || bindings[0].Paused {
		t.Fatal(bindings)
	}
	b := bindings[0]
	_, e = db.pool.Exec(ctx, `UPDATE collection_schedule SET enabled=false WHERE profile_id=$1`, target.ProfileID)
	must(e)
	disabled, e := db.AMIBindings(ctx, actor)
	must(e)
	if disabled[0].Eligible || disabled[0].BlockReason != "monitoring_disabled" {
		t.Fatal(disabled)
	}
	disabledView, e := db.AMIView(ctx, actor, h, target, time.Now().UTC())
	must(e)
	if !disabledView.Authorized || disabledView.State != "disconnected" || disabledView.Current {
		t.Fatal(disabledView)
	}
	_, e = db.pool.Exec(ctx, `UPDATE collection_schedule SET enabled=true WHERE profile_id=$1`, target.ProfileID)
	must(e)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id, e := db.BeginAMISession(ctx, b, now)
	must(e)
	if _, e = db.BeginAMISession(ctx, b, now); e == nil {
		t.Fatal("duplicate live session")
	}
	must(db.AMITransition(ctx, b, id, "authenticating", "", now, 0, false))
	must(db.AMITransition(ctx, b, id, "connected", "", now, 0, false))
	source := now.Add(-time.Minute)
	event := ami.Event{Name: "PeerStatus", Technology: "SIP", Endpoint: "example", Address: "192.0.2.50:5060", State: "Registered", SourceAt: &source, ReceivedAt: now, Sequence: 1}
	must(db.PersistAMIEvent(ctx, b, id, event, 0))
	event.ReceivedAt = now.Add(time.Hour)
	must(db.PersistAMIEvent(ctx, b, id, event, 0))
	// Persistence updates the session heartbeat using the database clock.
	// Observe after that heartbeat rather than assuming the writes finish in
	// one second on a loaded integration-test host.
	var viewAt time.Time
	must(db.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&viewAt))
	view, e := db.AMIView(ctx, actor, h, target, viewAt)
	must(e)
	if !view.Current || len(view.Events) != 1 || !view.Events[0].ReceivedAt.Equal(now) || !view.LastEventAt.Equal(now) || !view.Events[0].SourceAt.Equal(source) {
		t.Fatalf("replay changed timestamps %+v", view)
	}
	if _, e = db.AMIView(ctx, actor, alien, target, now); e == nil {
		t.Fatal("cross customer read")
	}
	// Replacing the credential digest cannot relabel the previous live session.
	must(db.SetAMIGrant(ctx, actor, h, target, "synthetic", strings.Repeat("b", 64), true))
	changed, e := db.AMIView(ctx, actor, h, target, now.Add(time.Second))
	must(e)
	if changed.Current || len(changed.Events) != 1 {
		t.Fatal("old session relabeled current")
	}
	must(db.SetAMIGrant(ctx, actor, h, target, "synthetic", digest, true))
	// A direct-SQL tenant mismatch must fail even without the repository checks.
	_, e = db.pool.Exec(ctx, `INSERT INTO asterisk_ami_event(session_id,customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,sequence,name,technology,endpoint,aor,address,state,received_at,parser_version,coverage_gap) VALUES($1,$2,$3,$4,$5,$6,1,99,'FullyBooted','','','','','Fully booted',$7,'1',false)`, id, workspace.OperatorID, h.EnvironmentID, h.AssetID, target.EndpointID, target.ProfileID, now)
	if e == nil {
		t.Fatal("SQL tenant constraint absent")
	}
	// Failed insert and session bookkeeping roll back together.
	_, e = db.pool.Exec(ctx, `CREATE FUNCTION reject_ami_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$; CREATE TRIGGER reject_fixture BEFORE INSERT ON asterisk_ami_event FOR EACH ROW EXECUTE FUNCTION reject_ami_fixture()`)
	must(e)
	event.Sequence = 2
	if db.PersistAMIEvent(ctx, b, id, event, 0) == nil {
		t.Fatal("failed persistence accepted")
	}
	_, e = db.pool.Exec(ctx, `DROP TRIGGER reject_fixture ON asterisk_ami_event`)
	must(e)
	view, e = db.AMIView(ctx, actor, h, target, now.Add(time.Second))
	must(e)
	if len(view.Events) != 1 || !view.LastEventAt.Equal(now) {
		t.Fatal("partial commit")
	}
	// A scoped pause that holds the singleton lock must be visible after the
	// waiter acquires it, not hidden by its earlier READ COMMITTED snapshot.
	pauseTx, e := db.pool.Begin(ctx)
	must(e)
	defer pauseTx.Rollback(ctx)
	_, e = pauseTx.Exec(ctx, `SELECT id FROM scheduler_control WHERE id FOR UPDATE`)
	must(e)
	_, e = pauseTx.Exec(ctx, `INSERT INTO schedule_pause(kind,asset_id) VALUES('asset',$1)`, h.AssetID)
	must(e)
	writeTx, e := db.pool.Begin(ctx)
	must(e)
	defer writeTx.Rollback(ctx)
	var backend int
	must(writeTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backend))
	verdict := make(chan error, 1)
	go func() { verdict <- amiAllowed(ctx, writeTx, b) }()
	deadline, cancelWait := context.WithTimeout(ctx, 3*time.Second)
	defer cancelWait()
	for {
		var waiting bool
		must(db.pool.QueryRow(deadline, `SELECT coalesce(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, backend).Scan(&waiting))
		if waiting {
			break
		}
		if deadline.Err() != nil {
			t.Fatal("AMI did not wait on pause lock")
		}
		runtime.Gosched()
	}
	must(pauseTx.Commit(ctx))
	if !errors.Is(<-verdict, workspace.ErrDenied) {
		t.Fatal("concurrent scoped pause accepted")
	}
	must(writeTx.Rollback(ctx))
	_, e = db.pool.Exec(ctx, `DELETE FROM schedule_pause WHERE asset_id=$1`, h.AssetID)
	must(e)
	// Pause and grant revocation prevent further accepted events.
	_, e = db.pool.Exec(ctx, `UPDATE scheduler_control SET paused=true`)
	must(e)
	if db.PersistAMIEvent(ctx, b, id, event, 0) == nil {
		t.Fatal("paused ingestion")
	}
	_, e = db.pool.Exec(ctx, `UPDATE scheduler_control SET paused=false`)
	must(e)
	must(db.AMITransition(ctx, b, id, "connected", "", now, 3, true))
	must(db.RecoverAMI(ctx))
	view, e = db.AMIView(ctx, actor, h, target, now.Add(time.Second))
	must(e)
	if view.Current || view.Session.EndedAt == nil || !view.Session.Gap || view.Session.Dropped != 3 || view.Session.Reason != "application_restart" || len(view.Events) != 1 {
		t.Fatal("restart recovery", view)
	}
	next, e := db.BeginAMISession(ctx, b, now.Add(time.Second))
	must(e)
	must(db.AMITransition(ctx, b, next, "connected", "", now.Add(time.Second), 0, false))
	stale, e := db.AMIView(ctx, actor, h, target, now.Add(time.Minute))
	must(e)
	if stale.Current || stale.State != "disconnected" {
		t.Fatal("stale connected")
	}
	must(db.SetAMIGrant(ctx, actor, h, target, "", "", false))
	if db.PersistAMIEvent(ctx, b, next, event, 0) == nil {
		t.Fatal("revoked ingestion")
	}
	must(db.AMITransition(ctx, b, next, "unauthorized", "authorization_revoked", now.Add(time.Minute), 0, true))
	view, e = db.AMIView(ctx, actor, h, target, now.Add(time.Minute))
	must(e)
	if view.Authorized || view.Current || len(view.Events) != 1 {
		t.Fatal(view)
	}
}
