package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/inventory"
)

func TestIntegrationInventoryRoundTripAndConstraints(t *testing.T) {
	ctx := context.Background()
	dsn := isolatedDSN(t)
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	create := func(name, code string) inventory.Customer {
		t.Helper()
		c, e := s.CreateCustomer(ctx, inventory.Customer{DisplayName: name, ShortCode: code, Status: "active", Notes: "Synthetic fixture only"})
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	a := create("Synthetic Customer A", "SYN_A")
	b := create("Synthetic Customer B", "SYN_B")
	if !inventory.ValidID(a.ID) || a.CreatedAt.IsZero() {
		t.Fatal("missing identity/timestamps")
	}
	for _, c := range []inventory.Customer{{DisplayName: "synthetic customer a", ShortCode: "UNUSED", Status: "active"}, {DisplayName: "Other", ShortCode: "syn_a", Status: "active"}, {DisplayName: "", ShortCode: "AA", Status: "active"}} {
		if _, err := s.CreateCustomer(ctx, c); err == nil {
			t.Fatal("invalid/duplicate customer accepted")
		}
	}
	a.DisplayName = "Synthetic Customer A updated"
	a.Notes = "Updated synthetic context"
	a, err = s.UpdateCustomer(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	bad := a
	bad.ShortCode = b.ShortCode
	if _, err = s.UpdateCustomer(ctx, bad); err == nil {
		t.Fatal("conflicting update accepted")
	}
	got, err := s.Customer(ctx, a.ID)
	if err != nil || got.ShortCode != a.ShortCode || got.Notes != a.Notes {
		t.Fatal("failed update changed data")
	}
	var envs []inventory.Environment
	for i, kind := range []string{"lab", "test", "production"} {
		e, err := s.CreateEnvironment(ctx, inventory.Environment{CustomerID: a.ID, Name: kind, Kind: kind, Status: "active"})
		if err != nil {
			t.Fatalf("environment %d: %v", i, err)
		}
		envs = append(envs, e)
	}
	if _, err := s.CreateEnvironment(ctx, inventory.Environment{CustomerID: a.ID, Name: "LAB", Kind: "test", Status: "active"}); err == nil {
		t.Fatal("duplicate scoped name accepted")
	}
	if _, err := s.CreateEnvironment(ctx, inventory.Environment{CustomerID: b.ID, Name: "lab", Kind: "lab", Status: "active"}); err != nil {
		t.Fatal("same name under different owner rejected", err)
	}
	e := envs[0]
	e.Name = "Renamed lab"
	e.Status = "archived"
	e, err = s.UpdateEnvironment(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Environment(ctx, b.ID, e.ID); !errors.Is(err, inventory.ErrNotFound) {
		t.Fatal("cross-customer read", err)
	}
	attack := e
	attack.CustomerID = b.ID
	if _, err := s.UpdateEnvironment(ctx, attack); !errors.Is(err, inventory.ErrNotFound) {
		t.Fatal("cross-customer update", err)
	}
	items, err := s.ListCustomers(ctx)
	if err != nil || len(items) != 2 || items[0].EnvironmentCount != 3 {
		t.Fatalf("list/count: %+v %v", items, err)
	}
	// Bypass repository validation: PostgreSQL must enforce all invariants itself.
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO customer(display_name,short_code) VALUES('', 'ZZ')`, nil},
		{`INSERT INTO customer(display_name,short_code,status) VALUES('Invalid','ZZ','deleted')`, nil},
		{`INSERT INTO customer(display_name,short_code) VALUES('synthetic customer b','ZZ')`, nil},
		{`INSERT INTO environment(customer_id,name,kind) VALUES('00000000-0000-4000-8000-000000000099','Orphan','lab')`, nil},
		{`INSERT INTO environment(customer_id,name,kind) VALUES($1,'Invalid','other')`, []any{a.ID}},
		{`INSERT INTO environment(customer_id,name,kind) VALUES($1,'LAB','lab')`, []any{b.ID}},
		{`UPDATE environment SET customer_id=$1 WHERE id=$2`, []any{b.ID, e.ID}},
		{`DELETE FROM customer WHERE id=$1`, []any{a.ID}},
	} {
		if _, err := s.pool.Exec(ctx, q.sql, q.args...); err == nil {
			t.Fatalf("direct SQL invariant accepted: %s", q.sql)
		}
	}
	// A multi-statement transaction aborts without leaking a preceding valid write.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE customer SET notes='must roll back' WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE environment SET customer_id=$1 WHERE id=$2`, b.ID, e.ID); err == nil {
		t.Fatal("invalid transaction accepted")
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatal("aborted transaction committed")
	}
	got, _ = s.Customer(ctx, a.ID)
	if got.Notes != a.Notes {
		t.Fatal("transaction partially committed")
	}
	a.Status = "archived"
	a, err = s.UpdateCustomer(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateEnvironment(ctx, inventory.Environment{CustomerID: a.ID, Name: "Blocked", Kind: "lab", Status: "active"}); !errors.Is(err, inventory.ErrArchived) {
		t.Fatal("archived owner allowed create", err)
	}
	if _, err := s.UpdateEnvironment(ctx, e); !errors.Is(err, inventory.ErrArchived) {
		t.Fatal("archived owner allowed edit", err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE environment SET name='Blocked SQL' WHERE id=$1`, e.ID); err == nil {
		t.Fatal("direct SQL ignored archive policy")
	}
	// Reopen pool/migrate: all IDs, ownership and archival states survive.
	s.Close()
	s, err = Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	got, err = s.Customer(ctx, a.ID)
	if err != nil || got.Status != "archived" || got.Notes != a.Notes {
		t.Fatal("customer restart persistence", err)
	}
	saved, err := s.Environment(ctx, a.ID, e.ID)
	if err != nil || saved.Name != e.Name || saved.Status != "archived" {
		t.Fatal("environment restart persistence", err)
	}
	list, err := s.ListEnvironments(ctx, a.ID)
	if err != nil || len(list) != 3 {
		t.Fatal("environment list", err)
	}
	a.Status = "active"
	if _, err := s.UpdateCustomer(ctx, a); err != nil {
		t.Fatal("restore", err)
	}
	saved.Status = "active"
	if _, err := s.UpdateEnvironment(ctx, saved); err != nil {
		t.Fatal("restore environment", err)
	}
	if _, err := s.Customer(ctx, "not-a-uuid"); !errors.Is(err, inventory.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestIntegrationInventoryM0UpgradePreservesData(t *testing.T) {
	ctx := context.Background()
	dsn := isolatedDSN(t)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err = conn.Exec(ctx, `CREATE TABLE schema_migration(version text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"migrations/001_sessions.sql", "migrations/002_operator_settings.sql"} {
		b, _ := migrationFiles.ReadFile(name)
		if _, err = conn.Exec(ctx, string(b)); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if _, err = conn.Exec(ctx, `INSERT INTO schema_migration(version,checksum) VALUES($1,$2)`, name, hex.EncodeToString(sum[:])); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = conn.Exec(ctx, `INSERT INTO operator_setting(id,note) VALUES(1,'Synthetic pre-upgrade workspace')`); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	csrf := strings.Repeat("b", 64)
	if _, err = conn.Exec(ctx, `INSERT INTO operator_session(token_hash,csrf_token,expires_at) VALUES($1,$2,$3)`, token, csrf, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if note, err := s.GetNote(ctx); err != nil || note != "Synthetic pre-upgrade workspace" {
		t.Fatal("M0 setting lost", err)
	}
	if session, err := s.Session(ctx, token); err != nil || session.CSRFToken != csrf {
		t.Fatal("M0 session lost", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal("repeat startup", err)
	}
	if _, err := s.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic upgraded customer", ShortCode: "UP", Status: "active"}); err != nil {
		t.Fatal("inventory unavailable after upgrade", err)
	}
}
