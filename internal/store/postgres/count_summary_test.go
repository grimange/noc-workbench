package postgres

import (
	"context"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/health"
	"noc-workbench/internal/workspace"
	"testing"
	"time"
)

func TestIntegrationCanonicalCountProjection(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	svc := collection.NewService(historyExecutor{}, linux.Registry(), db)
	r, err := svc.Collect(ctx, p, target)
	if err != nil {
		t.Fatal(err)
	}
	// Change only isolated fixture outcomes, retaining older successful readings.
	if _, err = db.pool.Exec(ctx, `UPDATE collector_result SET outcome=CASE collector_id WHEN 'linux.memory' THEN 'partial' WHEN 'linux.load' THEN 'failed' ELSE 'success' END,transport_outcome=CASE WHEN collector_id='linux.load' THEN 'permission_denied' ELSE 'success' END WHERE run_id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.pool.Exec(ctx, `UPDATE collection_run SET state='partial',success_count=3,failure_count=2 WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	attempt, err := db.RuntimeAttempt(ctx, p, h)
	if err != nil {
		t.Fatal(err)
	}
	history, err := db.CollectionHistory(ctx, p, h, "")
	if err != nil {
		t.Fatal(err)
	}
	bulk, _, err := db.ServerEvidence(ctx, workspace.Scope{All: true}, []string{h.AssetID}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	// The dashboard's pre-existing policy projection excludes linux.load.
	// Loading its outcome for counts must not change reachability evaluation.
	if health.Connectivity(*bulk[0].LatestAttempt) != "success" || health.Connectivity(bulk[0].RecentAttempts[0]) != "success" {
		t.Fatal("presentation changed policy evidence")
	}
	for _, got := range []*collection.Run{attempt, &history[0], bulk[0].LatestAttempt} {
		if got.ID != r.ID || got.CountSummary() != "3 successful, 1 partial, 1 failed" || got.State != "partial" {
			t.Fatalf("projection %+v: %s", got, got.CountSummary())
		}
		var success, partial, failed int
		if err = db.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE outcome='success'),count(*) FILTER(WHERE outcome='partial'),count(*) FILTER(WHERE outcome='failed') FROM collector_result WHERE run_id=$1`, r.ID).Scan(&success, &partial, &failed); err != nil {
			t.Fatal(err)
		}
		c := got.ResultCounts()
		if c.Successful != success || c.Partial != partial || c.Failed != failed {
			t.Fatal("SQL/count mismatch")
		}
	}
	denied := h
	denied.CustomerID = workspace.OperatorID
	if got, err := db.RuntimeAttempt(ctx, p, denied); err != nil || got != nil {
		t.Fatalf("scope escape: %+v %v", got, err)
	}
}
