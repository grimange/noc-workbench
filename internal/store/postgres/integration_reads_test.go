package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	ami "noc-workbench/internal/integrations/asteriskami"
	"noc-workbench/internal/workspace"
)

// Status and binding discovery must work in a read-only PostgreSQL session.
// SELECT FOR SHARE would fail even when no other transaction is competing.
func TestIntegrationPermissionSnapshotReadOnly(t *testing.T) {
	db, scope, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	for _, name := range []string{"asterisk", "asterisk_activity", "asterisk_media"} {
		if err := db.SetIntegration(ctx, p, scope, target, name, true); err != nil {
			t.Fatal(err)
		}
	}
	config := db.pool.Config().Copy()
	config.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	reader := &Store{pool: pool}
	if err := reader.IntegrationAllowed(ctx, p, target, "asterisk"); err != nil {
		t.Fatal(err)
	}
	b := ami.Binding{Target: target}
	if err := amiOptionalGrants(ctx, pool, &b); err != nil || !b.Activity || !b.Media {
		t.Fatalf("binding snapshot: %+v %v", b, err)
	}
	stale := target
	stale.ProfileVersion++
	alien := target
	alien.AssetID = workspace.OperatorID
	for _, tc := range []struct {
		name  string
		check func() error
	}{
		{"anonymous", func() error { return reader.IntegrationAllowed(ctx, workspace.Principal{}, target, "asterisk") }},
		{"stale", func() error { return reader.IntegrationAllowed(ctx, p, stale, "asterisk") }},
		{"foreign asset", func() error { return reader.IntegrationAllowed(ctx, p, alien, "asterisk") }},
		{"unsupported", func() error { return reader.IntegrationAllowed(ctx, p, target, "arbitrary") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(); !errors.Is(err, workspace.ErrDenied) {
				t.Fatalf("expected denial: %v", err)
			}
		})
	}
	if err := db.SetIntegration(ctx, p, scope, target, "asterisk", false); err != nil {
		t.Fatal(err)
	}
	if err := reader.IntegrationAllowed(ctx, p, target, "asterisk"); !errors.Is(err, workspace.ErrDenied) {
		t.Fatalf("revoked: %v", err)
	}
}

// Execution and event persistence retain the transactional revocation fence.
func TestIntegrationPermissionTransactionRetainsLocks(t *testing.T) {
	db, scope, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	if err := db.SetIntegration(ctx, p, scope, target, "asterisk", true); err != nil {
		t.Fatal(err)
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := integrationAllowed(ctx, tx, p, target, "asterisk"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"collection_integration", "connection_profile"} {
		var id string
		query := "SELECT profile_id::text FROM collection_integration WHERE profile_id=$1 AND integration='asterisk' FOR UPDATE NOWAIT"
		if table == "connection_profile" {
			query = "SELECT id::text FROM connection_profile WHERE id=$1 FOR UPDATE NOWAIT"
		}
		err := db.pool.QueryRow(ctx, query, target.ProfileID).Scan(&id)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55P03" {
			t.Fatalf("%s missing execution fence: %v", table, err)
		}
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := db.pool.QueryRow(ctx, "SELECT id::text FROM connection_profile WHERE id=$1 FOR UPDATE NOWAIT", target.ProfileID).Scan(&id); err != nil {
		t.Fatal("lock not released:", err)
	}
}
