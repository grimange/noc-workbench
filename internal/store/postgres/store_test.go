package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Each integration test owns a randomly named schema, never the caller's tables.
// Refuse external endpoints even when an environment variable was supplied.
func isolatedDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("NOC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PostgreSQL integration skipped: NOC_TEST_DATABASE_URL is not set")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatal("integration database must be a PostgreSQL URL")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		t.Fatal("integration database must use loopback")
	}
	for key := range u.Query() {
		if key != "sslmode" {
			t.Fatalf("unsupported integration URL parameter %q", key)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("connect integration database:", err)
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "nw_test_" + hex.EncodeToString(suffix[:])
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err = conn.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	conn.Close(ctx)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, "DROP SCHEMA "+ident+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

func TestIntegrationEmptyMigrationPersistenceAndSessions(t *testing.T) {
	dsn := isolatedDSN(t)
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.pool.QueryRow(ctx, "SELECT count(*) FROM schema_migration").Scan(&count); err != nil || count != 3 {
		t.Fatalf("migrations=%d err=%v", count, err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal("repeat migration", err)
	}
	if err = s.SetNote(ctx, "synthetic workspace"); err != nil {
		t.Fatal(err)
	}
	session := Session{TokenHash: strings.Repeat("a", 64), CSRFToken: strings.Repeat("b", 64), ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
	if err = s.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, err := s.GetNote(ctx); err != nil || got != "synthetic workspace" {
		t.Fatalf("restart note=%q err=%v", got, err)
	}
	if got, err := s.Session(ctx, session.TokenHash); err != nil || got.CSRFToken != session.CSRFToken || !got.ExpiresAt.Equal(session.ExpiresAt) {
		t.Fatalf("persisted session=%+v err=%v", got, err)
	}
	if err = s.DeleteSession(ctx, session.TokenHash); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(ctx, session.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("logout got %v", err)
	}
	session.ExpiresAt = time.Now().Add(-time.Hour)
	if err = s.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(ctx, session.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired got %v", err)
	}
	if err = s.SetNote(ctx, strings.Repeat("x", 4097)); err == nil {
		t.Fatal("oversized note accepted")
	}
}

func TestIntegrationUpgradeAndChecksum(t *testing.T) {
	dsn := isolatedDSN(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	first, err := migrationFiles.ReadFile("migrations/001_sessions.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, `CREATE TABLE schema_migration(version text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, string(first)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(first)
	if _, err = conn.Exec(ctx, "INSERT INTO schema_migration(version,checksum) VALUES ($1,$2)", "migrations/001_sessions.sql", hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal("upgrade", err)
	}
	defer s.Close()
	if err = s.SetNote(ctx, "upgraded"); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, "UPDATE schema_migration SET checksum='modified' WHERE version='migrations/001_sessions.sql'"); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err == nil {
		t.Fatal("modified migration accepted")
	}
}

func TestIntegrationConcurrentMigrationsAndRollback(t *testing.T) {
	dsn := isolatedDSN(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := Open(ctx, dsn)
			if err != nil {
				t.Error(err)
				return
			}
			s.Close()
		}()
	}
	wg.Wait()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Deliberately conflict with an unapplied migration; verify its changes and
	// tracking row roll back together, leaving the previous version intact.
	if _, err = s.pool.Exec(ctx, "DELETE FROM schema_migration WHERE version >= 'migrations/002_operator_settings.sql'"); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err == nil {
		t.Fatal("conflicting table accepted")
	}
	var n int
	if err = s.pool.QueryRow(ctx, "SELECT count(*) FROM schema_migration").Scan(&n); err != nil || n != 1 {
		t.Fatalf("rollback migration count=%d err=%v", n, err)
	}
}

func TestUnavailableAndRedaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Open(ctx, "postgres://operator:synthetic-secret@127.0.0.1:1/noc?sslmode=disable")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("startup was not bounded")
	}
	if strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("secret in error")
	}
	if _, err = Open(context.Background(), "://invalid"); err == nil {
		t.Fatal("invalid config accepted")
	}
}

func TestIntegrationUnknownMigrationRejected(t *testing.T) {
	for _, checksum := range []string{"", "unknown-checksum"} {
		t.Run("checksum="+checksum, func(t *testing.T) {
			dsn := isolatedDSN(t)
			ctx := context.Background()
			s, err := Open(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err := s.pool.Exec(ctx, "INSERT INTO schema_migration(version, checksum) VALUES ($1, $2)", "migrations/999_unknown.sql", checksum); err != nil {
				t.Fatal(err)
			}
			if err := s.Migrate(ctx); err == nil {
				t.Fatal("unknown migration accepted")
			}
			s.Close()
			if reopened, err := Open(ctx, dsn); err == nil {
				reopened.Close()
				t.Fatal("startup accepted unknown migration")
			}
		})
	}
}
