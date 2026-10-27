package postgres

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

const serverScope = `($1::boolean OR c.id::text=ANY($2::text[]) OR e.id::text=ANY($3::text[]))`
const serverFrom = ` FROM asset a JOIN environment e ON e.id=a.environment_id JOIN customer c ON c.id=e.customer_id `
const serverEligible = `a.kind='server' AND a.lifecycle='active' AND e.status='active' AND c.status='active'`
const serverColumns = `a.id::text,c.id::text,e.id::text,a.name,c.display_name,e.name,
 coalesce((SELECT ep.host FROM asset_endpoint ep WHERE ep.asset_id=a.id AND ep.environment_id=e.id AND ep.status='active' ORDER BY ep.preferred DESC,(ep.protocol='ssh') DESC,ep.id LIMIT 1),''),
 coalesce((SELECT jsonb_agg(jsonb_build_object('ID',k.id,'Name',k.name,'Lifecycle',k.lifecycle) ORDER BY lower(k.name),k.id) FROM (SELECT k.id,k.name,k.lifecycle FROM cluster_membership m JOIN cluster k ON k.id=m.cluster_id AND k.environment_id=m.environment_id WHERE m.asset_id=a.id AND m.environment_id=e.id ORDER BY lower(k.name),k.id LIMIT 1001) k),'[]'::jsonb)`

func scanServer(row pgx.Row) (v workspace.Server, err error) {
	var clusters []byte
	err = row.Scan(&v.ID, &v.CustomerID, &v.EnvironmentID, &v.Name, &v.Customer, &v.Environment, &v.Address, &clusters)
	if err != nil {
		return v, topologyError(err)
	}
	err = json.Unmarshal(clusters, &v.Clusters)
	if err == nil && len(v.Clusters) > 1000 {
		err = workspace.ErrLimit
	}
	return
}
func (s *Store) Servers(ctx context.Context, scope workspace.Scope, q string, offset int) ([]workspace.Server, bool, error) {
	if offset < 0 || offset > 1000000 || len(q) > 300 {
		return nil, false, workspace.ErrDenied
	}
	rows, err := s.pool.Query(ctx, `SELECT `+serverColumns+serverFrom+` WHERE `+serverScope+` AND `+serverEligible+` AND ($4='' OR to_tsvector('simple',a.name || ' ' || c.display_name || ' ' || coalesce((SELECT string_agg(ep.host,' ') FROM asset_endpoint ep WHERE ep.asset_id=a.id AND ep.environment_id=e.id AND ep.status='active'),'')) @@ to_tsquery('simple',$4)) ORDER BY lower(a.name),a.id LIMIT 26 OFFSET $5`, append(scopeArgs(scope), q, offset)...)
	if err != nil {
		return nil, false, topologyError(err)
	}
	defer rows.Close()
	var result []workspace.Server
	for rows.Next() {
		v, e := scanServer(rows)
		if e != nil {
			return nil, false, e
		}
		result = append(result, v)
	}
	more := len(result) > 25
	if more {
		result = result[:25]
	}
	return result, more, topologyError(rows.Err())
}
func (s *Store) ServerDetails(ctx context.Context, scope workspace.Scope, id string) (workspace.ServerDetail, error) {
	var d workspace.ServerDetail
	if !inventory.ValidID(id) {
		return d, inventory.ErrNotFound
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return d, err
	}
	defer tx.Rollback(ctx)
	d.Server, err = scanServer(tx.QueryRow(ctx, `SELECT `+serverColumns+serverFrom+` WHERE `+serverScope+` AND `+serverEligible+` AND a.id=$4`, append(scopeArgs(scope), id)...))
	if err != nil {
		return d, err
	}
	rows, err := tx.Query(ctx, `SELECT protocol,host,port,preferred,status FROM asset_endpoint WHERE asset_id=$1 AND environment_id=$2 ORDER BY preferred DESC,protocol,host,port LIMIT 1001`, id, d.EnvironmentID)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var v workspace.ServerEndpoint
		if err = rows.Scan(&v.Protocol, &v.Host, &v.Port, &v.Preferred, &v.Status); err != nil {
			rows.Close()
			return d, err
		}
		d.Endpoints = append(d.Endpoints, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return d, err
	}
	if len(d.Endpoints) > 1000 {
		return d, workspace.ErrLimit
	}
	rows, err = tx.Query(ctx, `SELECT s.id::text,i.id::text,s.name,s.service_type,i.name,h.binding_role,s.lifecycle,i.lifecycle FROM service_instance_host h JOIN service_instance i ON i.id=h.service_instance_id AND i.environment_id=h.environment_id JOIN service s ON s.id=i.service_id AND s.environment_id=i.environment_id WHERE h.asset_id=$1 AND h.environment_id=$2 ORDER BY lower(s.name),s.id,lower(i.name),i.id LIMIT 1001`, id, d.EnvironmentID)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var v workspace.ServerService
		if err = rows.Scan(&v.ID, &v.InstanceID, &v.Name, &v.Type, &v.Instance, &v.Role, &v.Lifecycle, &v.InstanceLifecycle); err != nil {
			rows.Close()
			return d, err
		}
		d.Services = append(d.Services, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return d, err
	}
	if len(d.Services) > 1000 {
		return d, workspace.ErrLimit
	}
	return d, tx.Commit(ctx)
}
