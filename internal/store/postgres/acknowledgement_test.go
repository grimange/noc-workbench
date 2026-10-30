package postgres

import (
	"context"
	"errors"
	"noc-workbench/internal/transport/sshcli"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/workspace"
)

// Deterministically deliver or withhold COMMIT, then lose its acknowledgement.
// No network timing, sleeps or live infrastructure is involved.
type lostCommit struct {
	pgx.Tx
	commit bool
}

func (tx lostCommit) Commit(ctx context.Context) error {
	if tx.commit {
		if e := tx.Tx.Commit(ctx); e != nil {
			return e
		}
	}
	return context.DeadlineExceeded
}

func TestIntegrationCollectionCommitAcknowledgement(t *testing.T) {
	db, _, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	r, e := collection.NewService(historyExecutor{}, linux.Registry(), db).Collect(ctx, p, target)
	if e != nil {
		t.Fatal(e)
	}
	for _, commit := range []bool{false, true} {
		tx, e := db.pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		// Change an actual normalized observation in the isolated fixture. The
		// receipt must compare full payloads, not terminal state or row counts.
		if _, e = tx.Exec(ctx, `UPDATE observation SET text_value=$1 WHERE run_id=$2 AND kind='text'`, "receipt-proof", r.ID); e != nil {
			t.Fatal(e)
		}
		receipt, e := collectionReceipt(ctx, tx, r)
		if e != nil {
			t.Fatal(e)
		}
		e = db.commitCollection(ctx, lostCommit{Tx: tx, commit: commit}, r, receipt)
		_ = tx.Rollback(ctx)
		if (e == nil) != commit {
			t.Fatalf("commit=%v: %v", commit, e)
		}
	}
	receipt, e := collectionReceipt(ctx, db.pool, r)
	if e != nil {
		t.Fatal(e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if e = db.commitCollection(cancelled, lostCommit{}, r, receipt); e != nil {
		t.Fatal("durable outcome verification inherited cancelled execution", e)
	}
	unavailable, e := pgxpool.NewWithConfig(ctx, db.pool.Config())
	if e != nil {
		t.Fatal(e)
	}
	unavailable.Close()
	if (&Store{pool: unavailable}).commitCollection(ctx, lostCommit{}, r, receipt) == nil {
		t.Fatal("unreadable receipt recovered acknowledgement")
	}
	for _, mutate := range []func(*collection.Run){
		func(r *collection.Run) { r.PrincipalID = "00000000-0000-4000-8000-000000000099" },
		func(r *collection.Run) { r.Target.ProfileVersion++ },
		func(r *collection.Run) { r.Target.AssetID = "00000000-0000-4000-8000-000000000099" },
		func(r *collection.Run) { r.Source = "scheduled" },
		func(r *collection.Run) { r.ScheduleRevision++ },
	} {
		wrong := r
		mutate(&wrong)
		if db.commitCollection(ctx, lostCommit{}, wrong, receipt) == nil {
			t.Fatal("mismatched scope recovered acknowledgement")
		}
	}
	if _, e = db.pool.Exec(ctx, `UPDATE collector_result SET diagnostics=ARRAY['changed'] WHERE run_id=$1`, r.ID); e != nil {
		t.Fatal(e)
	}
	if db.commitCollection(ctx, lostCommit{}, r, receipt) == nil {
		t.Fatal("changed result payload recovered acknowledgement")
	}
	if db.commitCollection(ctx, lostCommit{}, r, "") == nil {
		t.Fatal("missing receipt accepted")
	}
}

func TestIntegrationGuardCommitAcknowledgement(t *testing.T) {
	db, _, target := collectionFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, outcome := range []string{"committed", "late_commit", "rollback"} {
		t.Run(outcome, func(t *testing.T) {
			tx, e := db.pool.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(context.Background())
			if _, e = tx.Exec(ctx, sshAcquisitionLock, target.ProfileID); e != nil {
				t.Fatal(e)
			}
			var pid int32
			if e = tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); e != nil {
				t.Fatal(e)
			}
			var token string
			if e = tx.QueryRow(ctx, `INSERT INTO ssh_execution_guard(profile_id,principal_id,revision) VALUES($1,$2,$3) RETURNING token::text`, target.ProfileID, workspace.OperatorID, target.ProfileVersion).Scan(&token); e != nil {
				t.Fatal(e)
			}
			type result struct {
				token string
				err   error
			}
			done := make(chan result, 1)
			go func() {
				got, err := db.commitSSHGuard(ctx, lostCommit{Tx: tx, commit: outcome == "committed"}, target.ProfileID, token)
				done <- result{got, err}
			}()
			if outcome != "committed" {
				// Establish the cleanup's lock wait before settling the originating
				// transaction. No arbitrary sleeps or timing-dependent late commit.
				for {
					var waiting bool
					e = db.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1::int=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting)
					if e != nil {
						t.Fatal(e)
					}
					if waiting {
						break
					}
					select {
					case r := <-done:
						t.Fatalf("cleanup returned before terminal transaction: %v", r.err)
					default:
					}
				}
				if outcome == "late_commit" {
					e = tx.Commit(ctx)
				} else {
					e = tx.Rollback(ctx)
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			r := <-done
			var failure *sshcli.Failure
			if r.token != "" || !errors.As(r.err, &failure) || failure.Category != sshcli.GuardUncertain || !errors.Is(r.err, context.DeadlineExceeded) {
				t.Fatal("uncertain acquisition authorized a child or lost cause", r.err)
			}
			var n int
			if e = db.pool.QueryRow(ctx, `SELECT count(*) FROM ssh_execution_guard WHERE profile_id=$1`, target.ProfileID).Scan(&n); e != nil || n != 0 {
				t.Fatal("pre-contact cleanup failed", n, e)
			}
			next, e := db.BeginSSH(ctx, workspace.Principal{ID: workspace.OperatorID}, target)
			if e != nil || next == "" {
				t.Fatal("next independent acquisition blocked", e)
			}
			if e = db.EndSSH(ctx, target.ProfileID, next); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestIntegrationGuardAcquisitionCleanupBoundaries(t *testing.T) {
	db, _, target := collectionFixture(t)
	ctx := context.Background()
	tx, e := db.pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, sshAcquisitionLock, target.ProfileID); e != nil {
		t.Fatal(e)
	}
	var token string
	if e = tx.QueryRow(ctx, `INSERT INTO ssh_execution_guard(profile_id,principal_id,revision) VALUES($1,$2,$3) RETURNING token::text`, target.ProfileID, workspace.OperatorID, target.ProfileVersion).Scan(&token); e != nil {
		t.Fatal(e)
	}
	// Cancel only after proving cleanup is blocked by the originating owner.
	var pid int32
	if e = tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); e != nil {
		t.Fatal(e)
	}
	bounded, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	cleanup, cancel := context.WithCancel(bounded)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- db.retireSSHAcquisition(cleanup, target.ProfileID, token) }()
	for {
		var waiting bool
		if e = db.pool.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1::int=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("cleanup escaped active acquisition: %v", err)
		default:
		}
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled cleanup succeeded")
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = db.retireSSHAcquisition(ctx, target.ProfileID, "different-token"); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = db.pool.QueryRow(ctx, `SELECT count(*) FROM ssh_execution_guard WHERE profile_id=$1 AND token::text=$2`, target.ProfileID, token).Scan(&n); e != nil || n != 1 {
		t.Fatal("wrong token removed guard", n, e)
	}
	if e = db.EndSSH(ctx, target.ProfileID, token); e != nil {
		t.Fatal(e)
	}
}
