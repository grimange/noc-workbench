package postgres

import (
	"context"
	"testing"

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
	ctx := context.Background()
	for _, commit := range []bool{true, false} {
		tx, e := db.pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		var token string
		if e = tx.QueryRow(ctx, `INSERT INTO ssh_execution_guard(profile_id,principal_id,revision) VALUES($1,$2,$3) RETURNING token::text`, target.ProfileID, workspace.OperatorID, target.ProfileVersion).Scan(&token); e != nil {
			t.Fatal(e)
		}
		got, e := db.commitSSHGuard(ctx, lostCommit{Tx: tx, commit: commit}, target.ProfileID, token)
		if e == nil || got != "" {
			t.Fatal("uncertain acquisition authorized a child")
		}
		if !commit {
			// A commit arriving after cleanup is still uncertainty, never authority.
			if e = tx.Commit(ctx); e != nil {
				t.Fatal(e)
			}
			if e = db.EndSSH(ctx, target.ProfileID, "different-token"); e != nil {
				t.Fatal(e)
			}
		}
		var n int
		if e = db.pool.QueryRow(ctx, `SELECT count(*) FROM ssh_execution_guard WHERE profile_id=$1 AND token::text=$2`, target.ProfileID, token).Scan(&n); e != nil || (n == 0) != commit {
			t.Fatalf("exact pre-contact cleanup commit=%v count=%d: %v", commit, n, e)
		}
		if !commit {
			if e = db.RecoverSSH(ctx); e != nil {
				t.Fatal(e)
			}
			r, e := db.Enrollment(ctx, target.EndpointID, target.ProfileID)
			if e != nil || r.State != "identity_changed" || r.Details.ApprovedKey != "" {
				t.Fatal("late guard must retain explicit trust recovery", e)
			}
		}
	}
	if db.EndSSH(ctx, target.ProfileID, "already-retired") != nil {
		t.Fatal("exact-token cleanup must be idempotent")
	}
}
