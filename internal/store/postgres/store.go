// Package postgres owns local application persistence. It never connects to a
// monitored host or remote customer database.
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound    = errors.New("record not found")
	ErrUnavailable = errors.New("application database unavailable")
)

type Store struct{ pool *pgxpool.Pool }

type Session struct {
	TokenHash string
	CSRFToken string
	ExpiresAt time.Time
}

// Open bounds startup to ten seconds, including retries and migrations. Caller
// deadlines can shorten this budget. Connection errors intentionally omit the
// driver error because connection strings may contain secrets.
func Open(ctx context.Context, dsn string) (*Store, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid application database configuration")
	}
	cfg.MaxConns = 5
	cfg.MinConns = 0
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.ConnConfig.ConnectTimeout = time.Second
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, ErrUnavailable
	}
	s := &Store{pool: pool}
	for {
		if pool.Ping(ctx) == nil {
			break
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			pool.Close()
			return nil, ErrUnavailable
		case <-timer.C:
		}
	}
	if err := s.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() { s.pool.Close() }
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, session Session) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "DELETE FROM operator_session WHERE expires_at <= CURRENT_TIMESTAMP"); err != nil {
		return ErrUnavailable
	}
	if _, err = tx.Exec(ctx, "INSERT INTO operator_session(token_hash, csrf_token, expires_at) VALUES ($1,$2,$3)", session.TokenHash, session.CSRFToken, session.ExpiresAt); err != nil {
		return ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) Session(ctx context.Context, tokenHash string) (Session, error) {
	var session Session
	err := s.pool.QueryRow(ctx, "SELECT token_hash, csrf_token, expires_at FROM operator_session WHERE token_hash=$1 AND expires_at>CURRENT_TIMESTAMP", tokenHash).Scan(&session.TokenHash, &session.CSRFToken, &session.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, ErrUnavailable
	}
	return session, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := s.pool.Exec(ctx, "DELETE FROM operator_session WHERE token_hash=$1", tokenHash); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) SetNote(ctx context.Context, note string) error {
	if len(note) > 4096 {
		return errors.New("operator note exceeds 4096 bytes")
	}
	if _, err := s.pool.Exec(ctx, "INSERT INTO operator_setting(id,note) VALUES (1,$1) ON CONFLICT(id) DO UPDATE SET note=EXCLUDED.note", note); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) GetNote(ctx context.Context) (string, error) {
	var note string
	err := s.pool.QueryRow(ctx, "SELECT note FROM operator_setting WHERE id=1").Scan(&note)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", ErrUnavailable
	}
	return note, nil
}
