package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
)

type integrationQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Store) IntegrationAllowed(ctx context.Context, p workspace.Principal, t sshcli.Target, name string) error {
	return integrationAllowed(ctx, s.pool, p, t, name)
}
func integrationAllowed(ctx context.Context, q integrationQuery, p workspace.Principal, t sshcli.Target, name string) error {
	if p.ID != workspace.OperatorID || name != "asterisk" {
		return workspace.ErrDenied
	}
	var yes bool
	e := q.QueryRow(ctx, `SELECT true FROM collection_integration i JOIN connection_profile p ON p.id=i.profile_id WHERE i.profile_id=$1 AND i.asset_id=$2 AND i.endpoint_id=$3 AND i.integration=$4 AND i.enabled AND i.profile_revision=$5 AND p.revision=$5 AND p.state='connection_verified' FOR SHARE OF i,p`, t.ProfileID, t.AssetID, t.EndpointID, name, t.ProfileVersion).Scan(&yes)
	if e != nil || !yes {
		return workspace.ErrDenied
	}
	return nil
}
func (s *Store) SetIntegration(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, name string, enabled bool) error {
	if collectionAccess(p, h) != nil || name != "asterisk" || h.AssetID != t.AssetID {
		return workspace.ErrDenied
	}
	r, e := s.Enrollment(ctx, t.EndpointID, t.ProfileID)
	if e != nil || r.Target() != t || r.CustomerID != h.CustomerID || r.EnvironmentID != h.EnvironmentID {
		return workspace.ErrDenied
	}
	if enabled && r.State != "connection_verified" {
		return workspace.ErrDenied
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	if e = lockEnrollmentOwners(ctx, tx, r); e != nil {
		return e
	}
	var revision int64
	if e = tx.QueryRow(ctx, `SELECT revision FROM connection_profile WHERE id=$1 FOR UPDATE`, t.ProfileID).Scan(&revision); e != nil || revision != t.ProfileVersion {
		return workspace.ErrDenied
	}
	_, e = tx.Exec(ctx, `INSERT INTO collection_integration(profile_id,customer_id,environment_id,asset_id,endpoint_id,integration,profile_revision,enabled,actor) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(profile_id,integration) DO UPDATE SET profile_revision=excluded.profile_revision,enabled=excluded.enabled,actor=excluded.actor,updated_at=clock_timestamp(),revision=collection_integration.revision+1`, t.ProfileID, h.CustomerID, h.EnvironmentID, t.AssetID, t.EndpointID, name, t.ProfileVersion, enabled, p.ID)
	if e != nil {
		return ErrUnavailable
	}
	return tx.Commit(ctx)
}
func collectorsAllowed(ctx context.Context, q integrationQuery, p workspace.Principal, t sshcli.Target, ids []string) error {
	for _, id := range ids {
		if strings.HasPrefix(id, "asterisk.") {
			return integrationAllowed(ctx, q, p, t, "asterisk")
		}
	}
	return nil
}

// Scheduling requires successful capability evidence from the opted-in current
// enrollment revision. Manual inspection establishes capabilities first.
func (s *Store) integrationCapabilities(ctx context.Context, p workspace.Principal, t sshcli.Target, ids []string) error {
	for _, id := range ids {
		if !strings.HasPrefix(id, "asterisk.") {
			continue
		}
		var yes bool
		e := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM observation WHERE asset_id=$1 AND endpoint_id=$2 AND profile_id=$3 AND profile_revision=$4 AND key='asterisk.version' AND quality='valid')`, t.AssetID, t.EndpointID, t.ProfileID, t.ProfileVersion).Scan(&yes)
		if e != nil || !yes {
			return workspace.ErrDenied
		}
		e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collector_result c JOIN collection_run r ON r.id=c.run_id WHERE r.asset_id=$1 AND r.endpoint_id=$2 AND r.profile_id=$3 AND r.profile_revision=$4 AND c.collector_id=$5 AND c.outcome='success')`, t.AssetID, t.EndpointID, t.ProfileID, t.ProfileVersion, id).Scan(&yes)
		if e != nil || !yes {
			return workspace.ErrDenied
		}
	}
	return nil
}
