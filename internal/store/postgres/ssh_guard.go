package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *Store) BeginSSH(ctx context.Context, p workspace.Principal, t sshcli.Target) (string, error) {
	if p.ID != workspace.OperatorID {
		return "", workspace.ErrDenied
	}
	// A failed RETURNING must not autocommit an unacknowledged guard. The
	// remote deadline controls acquisition; persistence has its own bounded budget.
	if ctx.Err() != nil {
		return "", sshcli.LocalFailure(ctx.Err())
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return "", sshcli.LocalFailure(e)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	var token string
	e = tx.QueryRow(ctx, `INSERT INTO ssh_execution_guard(profile_id,principal_id,revision) SELECT id,$1,revision FROM connection_profile WHERE id=$2 AND endpoint_id=$3 AND asset_id=$4 AND revision=$5 AND state IN ('connection_verified','pending_host_key_verification') RETURNING token::text`, p.ID, t.ProfileID, t.EndpointID, t.AssetID, t.ProfileVersion).Scan(&token)
	if e != nil {
		var pe *pgconn.PgError
		if errors.As(e, &pe) && pe.Code == "23505" {
			return "", &sshcli.Failure{Category: sshcli.GuardConflict, Cause: e}
		}
		if errors.Is(e, pgx.ErrNoRows) {
			return "", &sshcli.Failure{Category: sshcli.PermissionDenied, Cause: e}
		}
		return "", sshcli.LocalFailure(e)
	}
	if ctx.Err() != nil {
		return "", sshcli.LocalFailure(ctx.Err())
	}
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return s.commitSSHGuard(save, tx, t.ProfileID, token)
}

func (s *Store) commitSSHGuard(ctx context.Context, tx pgx.Tx, profile, token string) (string, error) {
	commitErr := tx.Commit(ctx)
	if commitErr == nil {
		return token, nil
	}
	// Contact has not started. Retire only this acquisition's known token with
	// its own bounded acknowledgement. Even successful cleanup cannot authorize
	// execution; a late/unknown commit still fails closed and may require review.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if token != "" {
		_ = s.EndSSH(cleanup, profile, token)
	}
	return "", &sshcli.Failure{Category: sshcli.GuardUncertain, Cause: commitErr}
}
func (s *Store) SSHAllowed(ctx context.Context, t sshcli.Target, token string) error {
	var allowed bool
	e := s.pool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM ssh_execution_guard WHERE profile_id=$1 AND (token::text<>$2 OR revision<>$3))`, t.ProfileID, token, t.ProfileVersion).Scan(&allowed)
	if e != nil {
		return sshcli.LocalFailure(e)
	}
	if !allowed {
		return &sshcli.Failure{Category: sshcli.GuardConflict}
	}
	return nil
}

// A token is required to finish network work; explicit review uses an empty
// token only after its approved identity has been cleared in the same authority.
func (s *Store) EndSSH(ctx context.Context, id, token string) error {
	_, e := s.pool.Exec(ctx, `DELETE FROM ssh_execution_guard g WHERE profile_id=$1 AND (token::text=$2 OR ($2='' AND EXISTS(SELECT 1 FROM connection_profile p WHERE p.id=g.profile_id AND p.state='pending_authorization' AND coalesce(p.details->>'ApprovedKey','')='')))`, id, token)
	if e != nil {
		return sshcli.LocalFailure(e)
	}
	return nil
}
func (s *Store) RecoverSSH(ctx context.Context) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	// Single application process: every marker at startup represents an uncertain
	// prior operation. Retain an audit event and require explicit review, even if
	// the previously trusted key reappears. No network reconciliation is attempted.
	_, e = tx.Exec(ctx, `WITH invalidated AS (
 UPDATE connection_profile p SET state=CASE WHEN p.state IN ('disabled','rejected') THEN p.state ELSE 'identity_changed' END,revision=p.revision+1,
 details=p.details || '{"ApprovedKey":"","ApprovedFingerprint":"","ApprovedBy":"","ApprovedAt":null,"Evidence":"","VerifiedAt":null,"LastCategory":"trust_recovery_required"}'::jsonb,updated_at=clock_timestamp()
 FROM ssh_execution_guard g WHERE p.id=g.profile_id RETURNING p.id,p.revision,p.state)
 INSERT INTO connection_audit(profile_id,principal_id,revision,operation,state,category) SELECT i.id,g.principal_id,i.revision,'verify',i.state,'trust_recovery_required' FROM invalidated i JOIN ssh_execution_guard g ON g.profile_id=i.id`)
	if e != nil {
		return ErrUnavailable
	}
	if _, e = tx.Exec(ctx, `DELETE FROM ssh_execution_guard`); e != nil || tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
