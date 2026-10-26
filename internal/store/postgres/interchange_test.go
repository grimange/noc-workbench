package postgres

import (
	"bytes"
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"noc-workbench/internal/interchange"
	"noc-workbench/internal/workspace"
	"testing"
	"time"
)

func TestIntegrationInterchange(t *testing.T) {
	ctx := context.Background()
	dsn := isolatedDSN(t)
	s, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { s.Close() }()
	p := workspace.Principal{ID: workspace.OperatorID}
	scope := workspace.Scope{All: true}
	// Archived preferred endpoints may coexist with an active preferred endpoint.
	// They must not be transiently made active during reconstruction.
	count := func() int {
		t.Helper()
		var n int
		if e := s.pool.QueryRow(ctx, "SELECT count(*) FROM customer").Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	empty, e := s.ExportInventory(ctx, p, scope)
	if e != nil || len(empty.Records) != 0 {
		t.Fatal(empty, e)
	}
	d, e := interchange.Parse(interchange.Example)
	if e != nil {
		t.Fatal(e)
	}

	for _, endpoint := range d.Records {
		if endpoint.Type == "asset_endpoint" && endpoint.Fields["preferred"] == true {
			fields := map[string]any{}
			for k, v := range endpoint.Fields {
				fields[k] = v
			}
			fields["status"] = "archived"
			fields["host"] = "archived.example.invalid"
			d.Records = append(d.Records, interchange.Record{Type: "asset_endpoint", ID: interchange.Pseudonym(endpoint.ID), Fields: fields})
			break
		}
	}
	result, e := s.ImportInventory(ctx, p, scope, d, true)
	if e != nil || result.Create != len(d.Records) || count() != 0 {
		t.Fatal(result, e, "preview changed DB")
	}
	result, e = s.ImportInventory(ctx, p, scope, d, false)
	if e != nil || result.Create != len(d.Records) || count() != 2 {
		t.Fatal(result, e)
	}
	result, e = s.ImportInventory(ctx, p, scope, d, false)
	if e != nil || result.Create != 0 || result.Reuse != len(d.Records) {
		t.Fatal(result, e)
	}
	// Sensitive source strings, including columns absent from the interchange, must never leave export.
	if _, e = s.pool.Exec(ctx, "UPDATE customer SET notes='synthetic-sensitive-note',display_name='synthetic-sensitive-customer-'||short_code"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, "UPDATE cluster SET tags='synthetic-sensitive-tags'"); e != nil {
		t.Fatal(e)
	}
	exported, e := s.ExportInventory(ctx, p, scope)
	if e != nil {
		t.Fatal(e)
	}
	a, e := interchange.Encode(exported)
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.ExportInventory(ctx, p, scope)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := interchange.Encode(again)
	if !bytes.Equal(a, b) || bytes.Contains(a, []byte("sensitive")) {
		t.Fatal("disclosure or nondeterminism")
	}
	// Full portable graph reconstructs in an independent fresh schema.
	target, e := Open(ctx, isolatedDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	clean, e := interchange.Parse(a)
	if e != nil {
		t.Fatal(e)
	}
	r, e := target.ImportInventory(ctx, p, scope, clean, false)
	if e != nil || r.Create != len(d.Records) {
		t.Fatal(r, e)
	}
	for _, def := range interchange.Definitions {
		var x, y int
		s.pool.QueryRow(ctx, "SELECT count(*) FROM "+def.Table).Scan(&x)
		target.pool.QueryRow(ctx, "SELECT count(*) FROM "+def.Table).Scan(&y)
		if x != y {
			t.Fatal("lost relationships", def.Table, x, y)
		}
	}
	// Conflicting UUID must not overwrite customer or metadata.
	if _, e = s.ImportInventory(ctx, p, scope, d, false); e == nil {
		t.Fatal("conflict overwritten")
	}
	if _, e = s.ImportInventory(ctx, p, workspace.Scope{}, d, false); e == nil {
		t.Fatal("scope bypass")
	}
	if _, e = s.ExportInventory(ctx, workspace.Principal{}, scope); e == nil {
		t.Fatal("principal bypass")
	}
	// A late natural-key duplicate rolls back all preceding records, in preview and commit.
	bad, e := interchange.Parse(interchange.Example)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range bad.Records {
		if r.Type == "cluster_membership" {
			r.ID = interchange.Pseudonym(r.ID)
			bad.Records = append(bad.Records, r)
			break
		}
	}
	for _, dry := range []bool{true, false} {
		fresh, e := Open(ctx, isolatedDSN(t))
		if e != nil {
			t.Fatal(e)
		}
		_, e = fresh.ImportInventory(ctx, p, scope, bad, dry)
		if e == nil {
			t.Fatal("duplicate membership accepted")
		}
		var n int
		fresh.pool.QueryRow(ctx, "SELECT count(*) FROM customer").Scan(&n)
		fresh.Close()
		if n != 0 {
			t.Fatal("partial import survived rollback")
		}
	}
	// Restart the application-side store without changing the database.
	s.Close()
	s, e = Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	if count() != 2 {
		t.Fatal("restart lost inventory")
	}
	var history int
	if e = s.pool.QueryRow(ctx, "SELECT count(*) FROM schema_migration").Scan(&history); e != nil || history != 5 {
		t.Fatal("migration regression", e)
	}
	// Database collision found during dry-run, even when graph alone is valid.
	conflict, _ := interchange.Parse(a)
	for i := range conflict.Records {
		if conflict.Records[i].Type == "customer" {
			conflict.Records[i].Fields["short_code"] = "EXAMPLE_A"
			break
		}
	}
	if _, e = s.ImportInventory(ctx, p, scope, conflict, true); e == nil {
		t.Fatal("natural key conflict missed")
	}
}
func TestIntegrationArchivalAssignmentSerialization(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, isolatedDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	d, _ := interchange.Parse(interchange.Example)
	p := workspace.Principal{ID: workspace.OperatorID}
	_, e = s.ImportInventory(ctx, p, workspace.Scope{All: true}, d, false)
	if e != nil {
		t.Fatal(e)
	}
	var asset, env string
	if e = s.pool.QueryRow(ctx, "SELECT id::text,environment_id::text FROM asset WHERE lifecycle='active' ORDER BY id LIMIT 1").Scan(&asset, &env); e != nil {
		t.Fatal(e)
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "UPDATE asset SET lifecycle='archived' WHERE id=$1", asset); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.pool.Exec(ctx, "INSERT INTO asset_endpoint(environment_id,asset_id,protocol,host,port)VALUES($1,$2,'ssh','serialization.example.invalid',2222)", env, asset)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatal("assignment did not wait for archival", err)
	case <-time.After(100 * time.Millisecond):
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("assignment survived committed archival")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("assignment stuck")
	}
	var n int
	if e = s.pool.QueryRow(ctx, "SELECT count(*) FROM asset_endpoint WHERE host='serialization.example.invalid'").Scan(&n); e != nil || n != 0 {
		t.Fatal("invalid assignment persisted", e)
	}
	// Verify the actual constraint class, not just any SQL failure.
	_, e = s.pool.Exec(ctx, "INSERT INTO asset_endpoint(environment_id,asset_id,protocol,host,port)VALUES($1,$2,'ssh','serialization.example.invalid',2222)", env, asset)
	if e == nil {
		t.Fatal("archived assignment accepted")
	}
	var pe *pgconn.PgError
	if !errors.As(e, &pe) || pe.Code != "23514" {
		t.Fatalf("expected lifecycle constraint, got %v", e)
	}
}
