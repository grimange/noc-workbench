package postgres

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrate applies immutable embedded migrations in one transaction. The
// transaction-scoped lock serializes simultaneous application startups.
func (s *Store) Migrate(ctx context.Context) error {
	if err := s.migrate(ctx); err != nil {
		return errors.New("application database migration failed")
	}
	return nil
}

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(758291034)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migration (version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return err
	}
	files, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	known := make(map[string]string, len(files))
	for _, name := range files {
		b, err := migrationFiles.ReadFile(name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		known[name] = hex.EncodeToString(sum[:])
	}
	rows, err := tx.Query(ctx, "SELECT version,checksum FROM schema_migration ORDER BY version")
	if err != nil {
		return err
	}
	applied := map[string]bool{}
	for rows.Next() {
		var name, checksum string
		if err := rows.Scan(&name, &checksum); err != nil {
			rows.Close()
			return err
		}
		expected, exists := known[name]
		if !exists || expected != checksum {
			rows.Close()
			return errors.New("unknown or modified migration")
		}
		applied[name] = true
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}
	missing := false
	for _, name := range files {
		if !applied[name] {
			missing = true
		} else if missing {
			return errors.New("non-contiguous migration history")
		}
	}
	for _, name := range files {
		if applied[name] {
			continue
		}
		b, _ := migrationFiles.ReadFile(name)
		if _, err = tx.Exec(ctx, string(b)); err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO schema_migration(version,checksum) VALUES ($1,$2)", name, known[name]); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
