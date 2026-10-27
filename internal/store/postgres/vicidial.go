package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/integrations/vicidial"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

var _ vicidial.Repository = (*Store)(nil)

const vicidialColumns = `id::text,customer_id::text,environment_id::text,cluster_id::text,name,version,revision_source,notes,actor::text,enabled,verified_at,revision,created_at,updated_at`

func vicidialAccess(p workspace.Principal, h vicidial.Scope) error {
	scope, e := (workspace.LocalOperatorPolicy{}).Scope(p, workspace.Organize)
	if e != nil || !vicidial.ValidScope(h) || !scope.Allows(h.CustomerID, h.EnvironmentID) {
		return workspace.ErrDenied
	}
	return nil
}
func scanVICIdial(row pgx.Row) (v vicidial.Integration, e error) {
	e = row.Scan(&v.ID, &v.CustomerID, &v.EnvironmentID, &v.ClusterID, &v.Name, &v.Version, &v.RevisionSource, &v.Notes, &v.Actor, &v.Enabled, &v.VerifiedAt, &v.Revision, &v.CreatedAt, &v.UpdatedAt)
	return v, topologyError(e)
}
func (s *Store) VICIdialIntegration(ctx context.Context, p workspace.Principal, h vicidial.Scope) (vicidial.Integration, error) {
	if e := vicidialAccess(p, h); e != nil {
		return vicidial.Integration{}, e
	}
	return scanVICIdial(s.pool.QueryRow(ctx, `SELECT `+vicidialColumns+` FROM vicidial_integration WHERE customer_id=$1 AND environment_id=$2 AND cluster_id=$3 ORDER BY revision DESC LIMIT 1`, h.CustomerID, h.EnvironmentID, h.ClusterID))
}
func (s *Store) SaveVICIdialIntegration(ctx context.Context, p workspace.Principal, h vicidial.Scope, v vicidial.Integration) (vicidial.Integration, error) {
	if e := vicidialAccess(p, h); e != nil {
		return v, e
	}
	var e error
	v, e = vicidial.Validate(v, time.Now().UTC())
	if e != nil {
		return v, e
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return v, inventory.ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	// Same parent lock order as the database guard and canonical topology writes.
	var status string
	if e = tx.QueryRow(ctx, `SELECT c.status FROM customer c JOIN environment e ON e.customer_id=c.id JOIN cluster cl ON cl.environment_id=e.id WHERE c.id=$1 AND e.id=$2 AND cl.id=$3 FOR SHARE OF c`, h.CustomerID, h.EnvironmentID, h.ClusterID).Scan(&status); e != nil {
		return v, topologyError(e)
	}
	if e = tx.QueryRow(ctx, `SELECT status FROM environment WHERE id=$1 FOR SHARE`, h.EnvironmentID).Scan(&status); e != nil {
		return v, topologyError(e)
	}
	if e = tx.QueryRow(ctx, `SELECT lifecycle FROM cluster WHERE id=$1 FOR UPDATE`, h.ClusterID).Scan(&status); e != nil {
		return v, topologyError(e)
	}
	old, e := scanVICIdial(tx.QueryRow(ctx, `SELECT `+vicidialColumns+` FROM vicidial_integration WHERE cluster_id=$1 ORDER BY revision DESC LIMIT 1`, h.ClusterID))
	if e != nil && !errors.Is(e, inventory.ErrNotFound) {
		return v, e
	}
	if v.Revision != old.Revision || (v.ID != "" && v.ID != old.ID) {
		return v, inventory.FieldErrors{"revision": "The installation changed. Reload before saving."}
	}
	if old.Revision == 0 {
		v, e = scanVICIdial(tx.QueryRow(ctx, `INSERT INTO vicidial_integration(customer_id,environment_id,cluster_id,name,version,revision_source,notes,actor,enabled,verified_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+vicidialColumns, h.CustomerID, h.EnvironmentID, h.ClusterID, v.Name, v.Version, v.RevisionSource, v.Notes, p.ID, v.Enabled, v.VerifiedAt))
	} else {
		v, e = scanVICIdial(tx.QueryRow(ctx, `INSERT INTO vicidial_integration(id,revision,customer_id,environment_id,cluster_id,name,version,revision_source,notes,actor,enabled,verified_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING `+vicidialColumns, old.ID, old.Revision+1, h.CustomerID, h.EnvironmentID, h.ClusterID, v.Name, v.Version, v.RevisionSource, v.Notes, p.ID, v.Enabled, v.VerifiedAt, old.CreatedAt))
	}
	if e != nil {
		return v, e
	}
	if e = tx.Commit(ctx); e != nil {
		return v, topologyError(e)
	}
	return v, nil
}
