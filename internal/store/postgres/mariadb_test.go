package postgres

import (
	"context"
	"encoding/json"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/integrations/mariadb"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"testing"
	"time"
)

type mariaDBExecutor struct {
	snapshot     mariadb.Snapshot
	beforeReturn func()
	failed       bool
}

func (e *mariaDBExecutor) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, _ string) (sshcli.Result, error) {
	if e.beforeReturn != nil {
		e.beforeReturn()
	}
	at := time.Now().UTC()
	if e.failed {
		return sshcli.Result{StartedAt: at, EndedAt: at, Category: sshcli.ExecutionTimeout}, &sshcli.Failure{Category: sshcli.ExecutionTimeout}
	}
	b, _ := json.Marshal(e.snapshot)
	return sshcli.Result{StartedAt: at, EndedAt: at, Stdout: b}, nil
}
func TestIntegrationMariaDBHistoryFailurePreservationScopeAndRevocation(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(db.SetIntegration(ctx, p, h, target, "mariadb", true))
	n := uint64(0)
	port := uint64(3306)
	x := &mariaDBExecutor{snapshot: mariadb.Snapshot{Protocol: 1, Status: "ready", Version: "10.11.15-MariaDB-log", Identity: "database.example.invalid", ServerID: 1, LatencyMS: 2, Metrics: map[string]uint64{"Threads_connected": 2, "Threads_running": 1, "Max_used_connections": 4, "Connections": 10, "Aborted_connects": 0, "Uptime": 100, "max_connections": 200}, ActivityStatus: "ready", Replication: "ready", Channels: []mariadb.Channel{{Name: "east", Source: "192.0.2.4", Port: &port, IO: "Yes", SQL: "Yes", Lag: &n}}}}
	svc := collection.NewService(x, linux.Registry().Extend(mariadb.Specs()...), db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{mariadb.Collector}})
	first, err := svc.Collect(req, p, target)
	must(err)
	if first.SuccessCount != 1 {
		t.Fatalf("run %+v", first)
	}
	history, err := db.MariaDBHistory(ctx, p, h)
	must(err)
	if len(history.Samples) != 1 || history.Samples[0].RunID != first.ID || history.Samples[0].Snapshot.Role() != "Replica" {
		t.Fatalf("history %+v", history)
	}
	at := history.Samples[0].At
	// Complete empty snapshots cannot inherit prior channel rows.
	x.snapshot.Channels = nil
	second, err := svc.Collect(req, p, target)
	must(err)
	history, err = db.MariaDBHistory(ctx, p, h)
	must(err)
	if len(history.Samples) != 2 || history.Samples[0].RunID != second.ID || len(history.Samples[0].Snapshot.Channels) != 0 || history.Samples[0].Snapshot.Role() != "Unknown" {
		t.Fatal("mixed different snapshots", history)
	}
	x.failed = true
	_, err = svc.Collect(req, p, target)
	must(err)
	history, err = db.MariaDBHistory(ctx, p, h)
	must(err)
	if len(history.Samples) != 2 || history.Attempt.Outcome != "failed" || !history.Samples[1].At.Equal(at) {
		t.Fatal("failed collection altered evidence", history)
	}
	reopened, err := Open(ctx, db.pool.Config().ConnString())
	must(err)
	defer reopened.Close()
	after, err := reopened.MariaDBHistory(ctx, p, h)
	must(err)
	if len(after.Samples) != 2 || !after.Samples[1].At.Equal(at) {
		t.Fatal("reopen changed history")
	}
	alien := h
	alien.CustomerID = workspace.OperatorID
	other, err := db.MariaDBHistory(ctx, p, alien)
	if err == nil && len(other.Samples) != 0 {
		t.Fatal("cross customer history")
	}
	if _, err = db.pool.Exec(ctx, `UPDATE collection_run SET customer_id=$1 WHERE id=$2`, workspace.OperatorID, first.ID); err == nil {
		t.Fatal("SQL ownership constraint missing")
	}
	// Revocation after admission/execution must roll back pending results atomically.
	x.failed = false
	x.beforeReturn = func() { must(db.SetIntegration(ctx, p, h, target, "mariadb", false)) }
	rejected, err := svc.Collect(req, p, target)
	if err == nil {
		t.Fatal("pending observation committed after grant revoked")
	}
	var count int
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM observation WHERE run_id=$1`, rejected.ID).Scan(&count))
	if count != 0 {
		t.Fatal("revoked result partially persisted")
	}
	history, err = db.MariaDBHistory(ctx, p, h)
	must(err)
	if len(history.Samples) != 2 || !history.Samples[1].At.Equal(at) {
		t.Fatal("revocation destroyed prior evidence")
	}
}
