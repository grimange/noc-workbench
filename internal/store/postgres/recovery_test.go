package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	ami "noc-workbench/internal/integrations/asteriskami"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

func TestIntegrationGuardFailureIdentityAndCancellation(t *testing.T) {
	db, _, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	check := func(err error, category sshcli.Category) {
		t.Helper()
		var f *sshcli.Failure
		if !errors.As(err, &f) || f.Category != category {
			t.Fatalf("want %s, got %v", category, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err := db.BeginSSH(cancelled, actor, target)
	check(err, sshcli.Cancelled)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation cause lost")
	}
	token, err := db.BeginSSH(ctx, actor, target)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.BeginSSH(ctx, actor, target)
	check(err, sshcli.GuardConflict)
	check(db.SSHAllowed(ctx, target, "wrong-owner"), sshcli.GuardConflict)
	if err = db.EndSSH(ctx, target.ProfileID, "wrong-owner"); err != nil {
		t.Fatal(err)
	}
	if err = db.SSHAllowed(ctx, target, token); err != nil {
		t.Fatal(err)
	}
	if err = db.EndSSH(ctx, target.ProfileID, token); err != nil {
		t.Fatal(err)
	}
	// A rolled-back/cancelled acquisition cannot strand a marker or authorize work.
	token, err = db.BeginSSH(ctx, actor, target)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.EndSSH(ctx, target.ProfileID, token); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, db.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	_, err = (&Store{pool: pool}).BeginSSH(ctx, actor, target)
	check(err, sshcli.StorageFailure)
	if err == nil || errors.Unwrap(err) == nil {
		t.Fatal("storage cause lost")
	}
}

func TestIntegrationTransientCompletionPreservesSchedule(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	p, err := db.SaveSchedule(ctx, actor, scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Interval: 60, Budget: 20, Collectors: []string{"linux.uptime"}, Enabled: true, Authorized: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, tc := range []struct {
		category         string
		cause            error
		attempt, enabled bool
	}{
		{"local_storage_failure", nil, true, true}, {"ssh_guard_conflict", nil, true, true}, {"ssh_guard_uncertain", nil, true, true}, {"cancelled", nil, true, true},
		{"", errors.Join(collection.ErrPersistence, errors.New("fixture storage failure")), false, true},
		{"", errors.Join(collection.ErrPersistence, workspace.ErrDenied), false, false},
		{"", errors.Join(collection.ErrPersistence, &sshcli.Failure{Category: sshcli.GuardConflict}), false, true},
		{"", errors.Join(collection.ErrPersistence, &sshcli.Failure{Category: sshcli.GuardUncertain, Cause: context.DeadlineExceeded}), false, true},
		{"", collection.ErrPersistence, true, true}, {"permission_denied", nil, true, false}, {"host_key_mismatch", nil, true, false}, {"credential_unavailable", nil, true, false},
	} {
		_, err = db.pool.Exec(ctx, `UPDATE collection_schedule SET enabled=true,state='queued',last_dispatch=$2 WHERE id=$1`, p.ID, now)
		if err != nil {
			t.Fatal(err)
		}
		r := collection.Run{}
		if tc.attempt {
			r = collection.Run{ID: workspace.OperatorID, State: "failed", Category: tc.category, StartedAt: now}
		}
		if err = db.CompleteSchedule(ctx, p, r, tc.cause, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		snap, err := db.Schedules(ctx, actor)
		if err != nil {
			t.Fatal(err)
		}
		if !tc.attempt {
			var f *sshcli.Failure
			if errors.As(tc.cause, &f) && snap.Profiles[0].Category != string(f.Category) {
				t.Fatalf("typed guard cause lost: %+v", snap.Profiles[0])
			}
		}
		if snap.Profiles[0].Enabled != tc.enabled || !snap.Profiles[0].Authorized {
			t.Fatalf("%+v: %+v", tc, snap.Profiles[0])
		}
	}
}

func TestIntegrationCancelledQueryReleasesPool(t *testing.T) {
	db, _, _ := collectionFixture(t)
	ctx := context.Background()
	config := db.pool.Config()
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = tx.Exec(cancelled, `SELECT 1`)
	if err == nil {
		t.Fatal("cancelled query succeeded")
	}
	_ = tx.Rollback(ctx)
	var one int
	deadline, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err = pool.QueryRow(deadline, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatal("cancelled transaction contaminated next request", err)
	}
}

type grantFaultRow struct{ err error }

func (r grantFaultRow) Scan(v ...any) error {
	if r.err == nil {
		*(v[0].(*bool)) = true
	}
	return r.err
}

type grantFaultQuery struct {
	name  string
	cause error
}

func (q grantFaultQuery) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	if args[3] == q.name {
		return grantFaultRow{q.cause}
	}
	return grantFaultRow{}
}
func TestOptionalAMIGrantFailureIsNotRevocation(t *testing.T) {
	for _, name := range []string{"asterisk_activity", "asterisk_media"} {
		cause := errors.New("private storage detail")
		b := ami.Binding{Activity: true, Media: true}
		err := amiOptionalGrants(context.Background(), grantFaultQuery{name, cause}, &b)
		var f *sshcli.Failure
		if !errors.Is(err, cause) || !errors.As(err, &f) || f.Category != sshcli.StorageFailure {
			t.Fatal(name, err)
		}
		b = ami.Binding{}
		if err = amiOptionalGrants(context.Background(), grantFaultQuery{name, pgx.ErrNoRows}, &b); err != nil {
			t.Fatal(err)
		}
		if name == "asterisk_activity" && (b.Activity || b.Media) || name == "asterisk_media" && b.Media {
			t.Fatal(b)
		}
	}
}

func TestIntegrationServerConcurrentCancellationAndLatestRun(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	run, err := db.BeginCollection(ctx, actor, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.pool.Exec(ctx, `UPDATE collection_run SET state='failed',ended_at=clock_timestamp(),failure_count=1,collector_ids=ARRAY['linux.uptime'],category='connection_timeout' WHERE id=$1`, run.ID); err != nil {
		t.Fatal(err)
	}
	// A newer run without linux.services must still be the aggregate latest run.
	attempt, err := db.RuntimeAttempt(ctx, actor, h)
	if err != nil || attempt == nil || attempt.ID != run.ID {
		t.Fatal(attempt, err)
	}
	// An in-progress newer run belongs in history, not the completed summary.
	pending, err := db.BeginCollection(ctx, actor, target)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := db.RuntimeAttempt(ctx, actor, h)
	if err != nil || latest == nil || latest.ID != run.ID {
		t.Fatal("in-progress run hid completed summary", latest, err)
	}
	if pending.ID == run.ID {
		t.Fatal("fixture did not create a newer run")
	}
	config := db.pool.Config()
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := &Store{pool: pool}
	scope := workspace.Scope{All: true}
	held, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	held2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err = store.ServerEvidence(cancelled, scope, []string{h.AssetID}, time.Now().UTC()); err == nil {
		t.Fatal("cancelled pool acquisition succeeded")
	}
	held.Release()
	held2.Release()
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			rows, _, e := store.ServerEvidence(deadline, scope, []string{h.AssetID}, time.Now().UTC())
			if e == nil && (len(rows) != 1 || rows[0].LatestAttempt == nil || rows[0].LatestAttempt.ID != run.ID) {
				e = errors.New("latest aggregate run missing")
			}
			results <- e
		}()
	}
	for i := 0; i < 8; i++ {
		if err = <-results; err != nil {
			t.Fatal(err)
		}
	}
	if pool.Stat().AcquiredConns() != 0 {
		t.Fatal("request leaked a pooled connection")
	}
}

func TestPersistenceFailurePreservesSanitizedCause(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, &pgconn.PgError{Code: "23514", Message: "private database detail"}, errors.New("private database detail")} {
		err := persistenceError("observation_insert", cause)
		if !errors.Is(err, ErrUnavailable) || !errors.Is(err, cause) || strings.Contains(err.Error(), "private database detail") || !strings.Contains(err.Error(), "observation_insert") {
			t.Fatal("persistence cause or sanitization lost", err)
		}
	}
}

// A test-owned row lock places finalization at a known query boundary. Cancellation
// must roll back atomically and preserve its cause rather than claim authorization
// denial; the next request must be able to use the same pool.
func TestIntegrationFinalizationCancellationIsAtomic(t *testing.T) {
	db, _, target := collectionFixture(t)
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	actor := workspace.Principal{ID: workspace.OperatorID}
	durable, err := db.BeginCollection(ctx, actor, target)
	if err != nil {
		t.Fatal(err)
	}
	run, err := linux.Registry().Collect(ctx, historyExecutor{}, actor, target, linux.Registry().IDs())
	if err != nil {
		t.Fatal(err)
	}
	run.ID = durable.ID
	run.PrincipalID = actor.ID
	run.StartedAt = durable.StartedAt
	run.EndpointRevision = durable.EndpointRevision
	run.Source = durable.Source
	lock, err := db.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	if _, err = lock.Exec(ctx, `SELECT id FROM collection_run WHERE id=$1 FOR UPDATE`, run.ID); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- db.FinishCollection(cancelled, actor, run, 120) }()
	for {
		var blocked bool
		err = db.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id::text,asset_id::text%')`).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
	}
	cancel()
	err = <-result
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "lock_run") {
		t.Fatal("cancellation classification lost", err)
	}
	if err = lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	var count int
	if err = db.pool.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM observation WHERE run_id=$1) FROM collection_run WHERE id=$1`, run.ID).Scan(&state, &count); err != nil || state != "running" || count != 0 {
		t.Fatal("partial finalization or unusable pool", state, count, err)
	}
	if err = db.FinishCollection(ctx, actor, run, 120); err != nil {
		t.Fatal("next finalization failed", err)
	}
}

type cancelledHistoryExecutor struct{}

func (cancelledHistoryExecutor) Execute(context.Context, workspace.Principal, sshcli.Target, string) (sshcli.Result, error) {
	at := time.Now().UTC()
	return sshcli.Result{StartedAt: at, EndedAt: at, Category: sshcli.Cancelled}, &sshcli.Failure{Category: sshcli.Cancelled}
}

func TestIntegrationCancelledCollectionReceipt(t *testing.T) {
	db, h, target := collectionFixture(t)
	actor := workspace.Principal{ID: workspace.OperatorID}
	run, err := collection.NewService(cancelledHistoryExecutor{}, linux.Registry(), db).Collect(context.Background(), actor, target)
	if err != nil || run.State != "cancelled" {
		t.Fatal("cancelled run did not persist", run.State, err)
	}
	history, err := db.CollectionHistory(context.Background(), actor, h, "")
	if err != nil || len(history) != 1 || history[0].State != "cancelled" || history[0].FailureCount != 5 {
		t.Fatal("cancelled run history lost", history, err)
	}
}
