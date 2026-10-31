package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/workspace"
)

func TestIntegrationServerEvidenceGenericPlanJITScope(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	var jitAvailable bool
	if err := db.pool.QueryRow(ctx, "SELECT pg_jit_available()").Scan(&jitAvailable); err != nil {
		t.Fatal(err)
	}
	if !jitAvailable {
		t.Skip("PostgreSQL JIT is unavailable; generic-plan HTTP coverage runs separately")
	}
	actor := workspace.Principal{ID: workspace.OperatorID}
	if _, err := collection.NewService(historyExecutor{}, linux.Registry(), db).Collect(ctx, actor, target); err != nil {
		t.Fatal(err)
	}
	// Pin every pool session to the repeated-request failure mode. Force even
	// inexpensive queries to qualify for JIT; the console transaction must opt out.
	sessions := make([]*pgxpool.Conn, 0, 5)
	for i := 0; i < 5; i++ {
		c, err := db.pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, c)
	}
	for _, c := range sessions {
		if _, err := c.Exec(ctx, "SET jit=on; SET jit_above_cost=0; SET plan_cache_mode=force_generic_plan"); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range sessions {
		c.Release()
	}
	deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
	rows, _, err := db.ServerEvidence(deadline, workspace.Scope{Customers: []string{h.CustomerID}}, []string{h.AssetID}, time.Now().UTC())
	cancel()
	if err != nil || len(rows) != 1 {
		t.Fatalf("generic console read: %v, rows=%d", err, len(rows))
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, _, err = db.ServerEvidence(cancelled, workspace.Scope{All: true}, []string{h.AssetID}, time.Now().UTC()); err == nil {
		t.Fatal("cancelled read succeeded")
	}
	// Cancel deterministically after SET LOCAL has executed, while the read
	// transaction is open. The cancelled transaction must not strand a pool
	// connection or carry its transaction-local setting into another request.
	cancelledRead, cancelRead := context.WithCancel(ctx)
	cfg := db.pool.Config()
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["jit"] = "on"
	cfg.ConnConfig.Tracer = &cancelAfterConsoleSet{cancel: cancelRead}
	cancelPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelPool.Close()
	cancelStore := &Store{pool: cancelPool}
	if _, _, err = cancelStore.ServerEvidence(cancelledRead, workspace.Scope{All: true}, []string{h.AssetID}, time.Now().UTC()); err == nil {
		t.Fatal("read cancelled after SET LOCAL succeeded")
	}
	cancelRead()
	recovered, stopRecovery := context.WithTimeout(ctx, 3*time.Second)
	defer stopRecovery()
	var restored string
	if err = cancelPool.QueryRow(recovered, "SHOW jit").Scan(&restored); err != nil || restored != "on" {
		t.Fatalf("pool after cancellation: jit=%s err=%v", restored, err)
	}
	sessions = nil
	for i := 0; i < 5; i++ {
		c, err := db.pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, c)
	}
	defer func() {
		for _, c := range sessions {
			c.Release()
		}
	}()
	for _, c := range sessions {
		var jit, plan string
		if err := c.QueryRow(ctx, "SHOW jit").Scan(&jit); err != nil {
			t.Fatal(err)
		}
		if err := c.QueryRow(ctx, "SHOW plan_cache_mode").Scan(&plan); err != nil {
			t.Fatal(err)
		}
		if jit != "on" || plan != "force_generic_plan" {
			t.Fatalf("transaction setting leaked: jit=%s plan=%s", jit, plan)
		}
	}
}

// The first SET is the console transaction's SET LOCAL. BEGIN is not SET.
type cancelAfterConsoleSet struct {
	cancel context.CancelFunc
	once   sync.Once
}

func (c *cancelAfterConsoleSet) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}
func (c *cancelAfterConsoleSet) TraceQueryEnd(_ context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if d.Err == nil && d.CommandTag.String() == "SET" {
		c.once.Do(c.cancel)
	}
}
