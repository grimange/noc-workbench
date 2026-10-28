package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
	"time"
)

const enrollmentColumns = `id::text,customer_id::text,environment_id::text,asset_id::text,endpoint_id::text,revision,state,details`

func scanEnrollment(row pgx.Row) (r connections.Record, err error) {
	var raw []byte
	err = row.Scan(&r.ID, &r.CustomerID, &r.EnvironmentID, &r.AssetID, &r.EndpointID, &r.Revision, &r.State, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, inventory.ErrNotFound
	}
	if err != nil {
		return r, ErrUnavailable
	}
	if json.Unmarshal(raw, &r.Details) != nil {
		return r, ErrUnavailable
	}
	return r, nil
}
func (s *Store) Enrollment(ctx context.Context, endpoint, id string) (connections.Record, error) {
	if !inventory.ValidID(endpoint) || !inventory.ValidID(id) {
		return connections.Record{}, inventory.ErrNotFound
	}
	return scanEnrollment(s.pool.QueryRow(ctx, `SELECT `+enrollmentColumns+` FROM connection_profile WHERE endpoint_id=$1 AND id=$2`, endpoint, id))
}
func (s *Store) Enrollments(ctx context.Context, env, asset string) ([]connections.Record, error) {
	if !inventory.ValidID(env) || !inventory.ValidID(asset) {
		return nil, inventory.ErrNotFound
	}
	rows, e := s.pool.Query(ctx, `SELECT `+enrollmentColumns+` FROM connection_profile WHERE environment_id=$1 AND asset_id=$2 ORDER BY created_at,id LIMIT 100`, env, asset)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	all := []connections.Record{}
	for rows.Next() {
		r, e := scanEnrollment(rows)
		if e != nil {
			return nil, e
		}
		all = append(all, r)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return all, nil
}

// lockEnrollmentOwners shares locks with inventory lifecycle updates and holds
// them through CAS+audit commit. Network IO is always outside this transaction.
func lockEnrollmentOwners(ctx context.Context, tx pgx.Tx, r connections.Record) error {
	var c, e, a, ep, protocol, host string
	var port int
	var endpointTime time.Time
	if err := tx.QueryRow(ctx, `SELECT status FROM customer WHERE id=$1 FOR SHARE`, r.CustomerID).Scan(&c); err != nil {
		return connections.ErrConflict
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM environment WHERE id=$1 AND customer_id=$2 FOR SHARE`, r.EnvironmentID, r.CustomerID).Scan(&e); err != nil {
		return connections.ErrConflict
	}
	if err := tx.QueryRow(ctx, `SELECT lifecycle FROM asset WHERE id=$1 AND environment_id=$2 FOR SHARE`, r.AssetID, r.EnvironmentID).Scan(&a); err != nil {
		return connections.ErrConflict
	}
	if err := tx.QueryRow(ctx, `SELECT status,protocol,host,port,updated_at FROM asset_endpoint WHERE id=$1 AND environment_id=$2 AND asset_id=$3 FOR SHARE`, r.EndpointID, r.EnvironmentID, r.AssetID).Scan(&ep, &protocol, &host, &port, &endpointTime); err != nil {
		return connections.ErrConflict
	}
	// Disabled/rejected can always be recorded to revoke access after archival.
	if r.State == "disabled" || r.State == "rejected" {
		return nil
	}
	if !endpointTime.Equal(r.Details.EndpointUpdatedAt) {
		return connections.ErrConflict
	}
	if c != "active" || e != "active" || a != "active" || ep != "active" || protocol != "ssh" || host != r.Details.Host || port != int(r.Details.Port) {
		return connections.ErrConflict
	}
	return nil
}
func (s *Store) CreateEnrollment(ctx context.Context, p workspace.Principal, r connections.Record) (connections.Record, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return r, ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	if e = lockEnrollmentOwners(ctx, tx, r); e != nil {
		return r, e
	}
	// Serialize per asset to enforce a bounded collection even with concurrent forms.
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1891))`, r.AssetID); e != nil {
		return r, ErrUnavailable
	}
	var count int
	if tx.QueryRow(ctx, `SELECT count(*) FROM connection_profile WHERE asset_id=$1`, r.AssetID).Scan(&count) != nil {
		return r, ErrUnavailable
	}
	if count >= 100 {
		return r, workspace.ErrLimit
	}
	b, e := json.Marshal(r.Details)
	if e != nil {
		return r, ErrUnavailable
	}
	r, e = scanEnrollment(tx.QueryRow(ctx, `INSERT INTO connection_profile(customer_id,environment_id,asset_id,endpoint_id,state,details) VALUES($1,$2,$3,$4,'draft',$5) RETURNING `+enrollmentColumns, r.CustomerID, r.EnvironmentID, r.AssetID, r.EndpointID, b))
	if e != nil {
		return r, e
	}
	return commitEnrollment(ctx, tx, p, r, "create")
}
func (s *Store) SaveEnrollment(ctx context.Context, p workspace.Principal, r connections.Record, revision int64, action string) (connections.Record, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return r, ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	if e = lockEnrollmentOwners(ctx, tx, r); e != nil {
		return r, e
	}
	b, e := json.Marshal(r.Details)
	if e != nil {
		return r, ErrUnavailable
	}
	r, e = scanEnrollment(tx.QueryRow(ctx, `UPDATE connection_profile SET details=$1,state=$2,revision=revision+1,updated_at=clock_timestamp() WHERE id=$3 AND endpoint_id=$4 AND revision=$5 RETURNING `+enrollmentColumns, b, r.State, r.ID, r.EndpointID, revision))
	if e != nil {
		if errors.Is(e, inventory.ErrNotFound) {
			return r, connections.ErrConflict
		}
		return r, e
	}
	if r.State == "connection_verified" && r.Details.BaselineAuthorized && (action == "verify" || action == "baseline") {
		// A one-time baseline grant on an already verified enrollment does not
		// revoke separately approved adapters. Rebind only grants from the exact
		// preceding revision; older or disabled grants remain invalid.
		if action == "baseline" {
			if _, e = tx.Exec(ctx, `UPDATE collection_integration SET profile_revision=$2,revision=revision+1,updated_at=clock_timestamp() WHERE profile_id=$1 AND profile_revision=$3 AND enabled`, r.ID, r.Revision, revision); e != nil {
				return r, e
			}
		}
		if e = authorizeBaseline(ctx, tx, p, r); e != nil {
			return r, e
		}
	}
	return commitEnrollment(ctx, tx, p, r, action)
}
func commitEnrollment(ctx context.Context, tx pgx.Tx, p workspace.Principal, r connections.Record, action string) (connections.Record, error) {
	if _, e := tx.Exec(ctx, `INSERT INTO connection_audit(profile_id,principal_id,revision,operation,state,category) VALUES($1,$2,$3,$4,$5,$6)`, r.ID, p.ID, r.Revision, action, r.State, r.Details.LastCategory); e != nil {
		return r, ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return r, ErrUnavailable
	}
	return r, nil
}
