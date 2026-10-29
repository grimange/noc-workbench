package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/linux"
	auth "noc-workbench/internal/integrations/asteriskauth"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
	"testing"
	"time"
)

type authBatchExecutor struct {
	batch auth.Batch
	fail  bool
}

func (x *authBatchExecutor) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, id string) (sshcli.Result, error) {
	raw, _ := json.Marshal(x.batch)
	r := sshcli.Result{CommandID: id, StartedAt: x.batch.InspectedAt, EndedAt: x.batch.InspectedAt, Stdout: raw}
	if x.fail {
		return r, &sshcli.Failure{Category: sshcli.ChangedKey}
	}
	return r, nil
}
func TestIntegrationAuthPersistenceAndWindows(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	batch := auth.Batch{Source: "security", Status: "current", Security: true, InspectedAt: now, After: auth.Cursor{Identity: "1:2", Generation: 1, Offset: 10000, Anchor: strings.Repeat("a", 64)}, Bytes: 10000}
	for i := range 11 {
		account, ip := "100", "192.0.2.1"
		at := now.Add(-time.Minute)
		switch i {
		case 5:
			account = "200"
		case 6:
			ip = "192.0.2.2"
		case 7, 8:
			account = ""
		case 9:
			at = now.Add(-10 * time.Minute)
		case 10:
			at = now.Add(-30 * time.Minute)
		}
		batch.Events = append(batch.Events, auth.Event{Position: int64(i * 100), At: at, Type: "InvalidPassword", Account: account, IP: ip, Port: 5060, Technology: "SIP", Severity: "authentication_failure", Reason: "InvalidPassword"})
	}
	x := &authBatchExecutor{batch: batch}
	svc := collection.NewService(x, linux.Registry().Extend(auth.Specs()...), db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{auth.Collector}})
	if _, e := svc.Collect(req, p, target); e == nil {
		t.Fatal("implicit log authorization")
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk", true))
	must(db.SetIntegration(ctx, p, h, target, "asterisk_auth", true))
	run, e := svc.Collect(req, p, target)
	must(e)
	if run.SuccessCount != 1 {
		t.Fatalf("run %+v", run)
	}
	v, e := db.AuthEvents(ctx, p, h, target, auth.Filter{Minutes: 60}, now.Add(time.Second))
	must(e)
	if !v.Current || v.Failures5 != 9 || v.Failures15 != 10 || v.FailuresHour != 11 || v.Sources != 2 || len(v.Groups) != 5 {
		t.Fatalf("view %+v", v)
	}
	repeated := false
	for _, g := range v.Groups {
		if g.Account == "100" && g.IP == "192.0.2.1" {
			repeated = g.Repeated && g.Count == 7 && g.Count5 == 5
		}
	}
	if !repeated {
		t.Fatal(v.Groups)
	}
	cursors, e := db.AuthCursors(ctx, p, target)
	must(e)
	if cursors["security"] != batch.After {
		t.Fatal(cursors)
	}
	// A repeated stale batch cannot advance its cursor or count events again.
	if _, e = svc.Collect(req, p, target); e == nil {
		t.Fatal("stale batch accepted")
	}
	var n int
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM asterisk_auth_event`).Scan(&n))
	if n != 11 {
		t.Fatal(n)
	}
	// A new process sees the same committed cursor/history.
	reopened, e := Open(ctx, db.pool.Config().ConnString())
	must(e)
	defer reopened.Close()
	again, e := reopened.AuthCursors(ctx, p, target)
	must(e)
	if again["security"] != batch.After {
		t.Fatal("restart cursor")
	}
	// An ingestion failure rolls back both cursor and events. Recovery can replay intact.
	x.batch.Before = batch.After
	x.batch.After.Offset += 100
	x.batch.Events = []auth.Event{{Position: 10000, At: now, Type: "InvalidAccountID", Account: "300", IP: "2001:db8::1", Severity: "authentication_failure", Reason: "InvalidAccountID"}}
	x.batch.Bytes = 100
	x.batch.InspectedAt = now.Add(time.Second)
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM asterisk_auth_event`).Scan(&n))
	tx, e := db.pool.Begin(ctx)
	must(e)
	pending, e := db.BeginCollection(req, p, target)
	must(e)
	parsed, _ := auth.ParseBatch(marshalAuth(t, x.batch))
	result := collection.Result{CollectorID: auth.Collector, Version: "1", CommandID: "asterisk.auth.v1", Observations: parsed}
	must(persistAuth(ctx, tx, p, pending, result))
	tx.Rollback(ctx)
	again, e = db.AuthCursors(ctx, p, target)
	must(e)
	if again["security"] != batch.After {
		t.Fatal("cursor escaped rollback")
	}
	// Clear interrupted in-flight runs through normal restart recovery.
	must(db.RecoverCollections(ctx))
	_, e = svc.Collect(req, p, target)
	must(e)
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM asterisk_auth_event`).Scan(&n))
	if n != 12 {
		t.Fatal(n)
	}
	v, e = db.AuthEvents(ctx, p, h, target, auth.Filter{Minutes: 60, Account: "300"}, now.Add(2*time.Second))
	must(e)
	if len(v.Groups) != 1 || v.Groups[0].IP != "2001:db8::1" {
		t.Fatal(v)
	}
	stale, e := db.AuthEvents(ctx, p, h, target, auth.Filter{}, now.Add(4*time.Minute))
	must(e)
	if stale.Current || stale.Status != "stale" {
		t.Fatal(stale)
	}
	// Scope is enforced in API and direct SQL composite ownership constraints.
	alien := h
	alien.CustomerID = workspace.OperatorID
	if _, e = db.AuthEvents(ctx, p, alien, target, auth.Filter{}, now); e == nil {
		t.Fatal("cross customer API")
	}
	for _, table := range []string{"asterisk_auth_event", "asterisk_auth_status", "asterisk_auth_cursor"} {
		if _, e = db.pool.Exec(ctx, fmt.Sprintf(`UPDATE %s SET customer_id=$1`, table), workspace.OperatorID); e == nil {
			t.Fatal("cross customer SQL", table)
		}
	}
	if _, e = db.AuthEvents(ctx, workspace.Principal{}, h, target, auth.Filter{}, now); e == nil {
		t.Fatal("anonymous")
	}
	// Reauthorization keeps the canonical source checkpoint, while grants remain exact.
	_, e = db.pool.Exec(ctx, `UPDATE connection_profile SET revision=revision+1 WHERE id=$1`, target.ProfileID)
	must(e)
	target.ProfileVersion++
	if _, e = db.AuthCursors(ctx, p, target); e == nil {
		t.Fatal("new revision reused old authority")
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk", true))
	must(db.SetIntegration(ctx, p, h, target, "asterisk_auth", true))
	again, e = db.AuthCursors(ctx, p, target)
	must(e)
	if again["security"] != x.batch.After {
		t.Fatal("revision reset cursor", again)
	}
	x.batch.Before = x.batch.After
	x.batch.Events = nil
	x.batch.Bytes = 0
	x.batch.InspectedAt = now.Add(2 * time.Second)
	_, e = svc.Collect(req, p, target)
	must(e)
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM asterisk_auth_event`).Scan(&n))
	if n != 12 {
		t.Fatal("revision duplicated events", n)
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk_auth", false))
	if _, e = svc.Collect(req, p, target); e == nil {
		t.Fatal("revoked collection")
	}
}
func marshalAuth(t *testing.T, b auth.Batch) []byte {
	t.Helper()
	v, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	return v
}

func TestIntegrationAuthEmptyAndUnavailableCoverage(t *testing.T) {
	db, scope, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(db.SetIntegration(ctx, p, scope, target, "asterisk", true))
	must(db.SetIntegration(ctx, p, scope, target, "asterisk_auth", true))
	x := &authBatchExecutor{batch: auth.Batch{Source: "security", Status: "current", Security: true, InspectedAt: time.Now().UTC().Add(-time.Second), After: auth.Cursor{Identity: "1:2", Generation: 1, Anchor: strings.Repeat("a", 64)}}}
	svc := collection.NewService(x, linux.Registry().Extend(auth.Specs()...), db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{auth.Collector}})
	_, err := svc.Collect(req, p, target)
	must(err)
	view, err := db.AuthEvents(ctx, p, scope, target, auth.Filter{}, time.Now().UTC())
	must(err)
	if !view.Current || view.FailuresHour != 0 {
		t.Fatalf("successful empty coverage: %+v", view)
	}
	for _, status := range []string{"missing_source", "permission_denied", "no_configured_source", "unsupported_configuration"} {
		x.batch = auth.Batch{Status: status, InspectedAt: time.Now().UTC().Add(-time.Second)}
		_, err = svc.Collect(req, p, target)
		must(err)
		view, err = db.AuthEvents(ctx, p, scope, target, auth.Filter{}, time.Now().UTC())
		must(err)
		if view.Current || view.Status != status {
			t.Fatalf("failed source must not look empty/current: %+v", view)
		}
	}
	x.fail = true
	_, err = svc.Collect(req, p, target)
	must(err)
	view, err = db.AuthEvents(ctx, p, scope, target, auth.Filter{}, time.Now().UTC())
	must(err)
	if view.Current || view.Status != "transport_unavailable" {
		t.Fatalf("host-key failure: %+v", view)
	}
	cursors, err := db.AuthCursors(ctx, p, target)
	must(err)
	if cursors["security"].Identity != "1:2" || cursors["security"].Offset != 0 {
		t.Fatal("failed source advanced cursor", cursors)
	}
}
