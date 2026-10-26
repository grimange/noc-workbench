package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"noc-workbench/internal/inventory"
)

var _ inventory.TopologyRepository = (*Store)(nil)

func topologyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return inventory.ErrNotFound
	}
	var p *pgconn.PgError
	if errors.As(err, &p) {
		if p.ConstraintName == "topology_active" {
			return inventory.ErrInactive
		}
		if p.Code == "23505" {
			return inventory.FieldErrors{"record": "This name, key, endpoint or relationship is already in use (including archived records). Check preferred endpoints as well."}
		}
		if p.Code == "23503" {
			return inventory.FieldErrors{"record": "Choose related records from this environment."}
		}
		if p.Code == "23514" {
			return inventory.FieldErrors{"record": "Invalid topology fields or immutable ownership."}
		}
	}
	return inventory.ErrUnavailable
}

const clusterColumns = `id::text,environment_id::text,name,type,tags,lifecycle,created_at,updated_at`

func scanCluster(row pgx.Row) (v inventory.Cluster, err error) {
	err = row.Scan(&v.ID, &v.EnvironmentID, &v.Name, &v.Type, &v.Tags, &v.Lifecycle, &v.CreatedAt, &v.UpdatedAt)
	return v, topologyError(err)
}
func (s *Store) ListClusters(ctx context.Context, env string) ([]inventory.Cluster, error) {
	if !inventory.ValidID(env) {
		return nil, inventory.ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+clusterColumns+` FROM cluster WHERE environment_id=$1 ORDER BY created_at,id`, env)
	if err != nil {
		return nil, topologyError(err)
	}
	defer rows.Close()
	items := []inventory.Cluster{}
	for rows.Next() {
		v, err := scanCluster(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, topologyError(rows.Err())
}
func (s *Store) GetCluster(ctx context.Context, env, id string) (inventory.Cluster, error) {
	if !inventory.ValidID(env) || !inventory.ValidID(id) {
		return inventory.Cluster{}, inventory.ErrNotFound
	}
	return scanCluster(s.pool.QueryRow(ctx, `SELECT `+clusterColumns+` FROM cluster WHERE environment_id=$1 AND id=$2`, env, id))
}
func (s *Store) SaveCluster(ctx context.Context, v inventory.Cluster) (inventory.Cluster, error) {
	v, err := inventory.ValidateCluster(v)
	if err != nil {
		return v, err
	}
	if v.ID == "" {
		return scanCluster(s.pool.QueryRow(ctx, `INSERT INTO cluster(environment_id,name,type,tags,lifecycle) VALUES($1,$2,$3,$4,$5) RETURNING `+clusterColumns, v.EnvironmentID, v.Name, v.Type, v.Tags, v.Lifecycle))
	}
	return scanCluster(s.pool.QueryRow(ctx, `UPDATE cluster SET name=$2,type=$3,tags=$4,lifecycle=$5,updated_at=CURRENT_TIMESTAMP WHERE environment_id=$1 AND id=$6 RETURNING `+clusterColumns, v.EnvironmentID, v.Name, v.Type, v.Tags, v.Lifecycle, v.ID))
}

const assetColumns = `id::text,environment_id::text,name,kind,tags,lifecycle,created_at,updated_at`

func scanAsset(row pgx.Row) (v inventory.Asset, err error) {
	err = row.Scan(&v.ID, &v.EnvironmentID, &v.Name, &v.Kind, &v.Tags, &v.Lifecycle, &v.CreatedAt, &v.UpdatedAt)
	return v, topologyError(err)
}
func (s *Store) ListAssets(ctx context.Context, env string) ([]inventory.Asset, error) {
	if !inventory.ValidID(env) {
		return nil, inventory.ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+assetColumns+` FROM asset WHERE environment_id=$1 ORDER BY created_at,id`, env)
	if err != nil {
		return nil, topologyError(err)
	}
	defer rows.Close()
	items := []inventory.Asset{}
	for rows.Next() {
		v, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, topologyError(rows.Err())
}
func (s *Store) GetAsset(ctx context.Context, env, id string) (inventory.Asset, error) {
	if !inventory.ValidID(env) || !inventory.ValidID(id) {
		return inventory.Asset{}, inventory.ErrNotFound
	}
	return scanAsset(s.pool.QueryRow(ctx, `SELECT `+assetColumns+` FROM asset WHERE environment_id=$1 AND id=$2`, env, id))
}
func (s *Store) SaveAsset(ctx context.Context, v inventory.Asset) (inventory.Asset, error) {
	v, err := inventory.ValidateAsset(v)
	if err != nil {
		return v, err
	}
	if v.ID == "" {
		return scanAsset(s.pool.QueryRow(ctx, `INSERT INTO asset(environment_id,name,kind,tags,lifecycle) VALUES($1,$2,$3,$4,$5) RETURNING `+assetColumns, v.EnvironmentID, v.Name, v.Kind, v.Tags, v.Lifecycle))
	}
	return scanAsset(s.pool.QueryRow(ctx, `UPDATE asset SET name=$2,kind=$3,tags=$4,lifecycle=$5,updated_at=CURRENT_TIMESTAMP WHERE environment_id=$1 AND id=$6 RETURNING `+assetColumns, v.EnvironmentID, v.Name, v.Kind, v.Tags, v.Lifecycle, v.ID))
}

const endpointColumns = `id::text,environment_id::text,asset_id::text,protocol,host,port,preferred,status,created_at,updated_at`

func scanEndpoint(row pgx.Row) (v inventory.Endpoint, err error) {
	err = row.Scan(&v.ID, &v.EnvironmentID, &v.AssetID, &v.Protocol, &v.Host, &v.Port, &v.Preferred, &v.Status, &v.CreatedAt, &v.UpdatedAt)
	return v, topologyError(err)
}
func (s *Store) ListEndpoints(ctx context.Context, env string) ([]inventory.Endpoint, error) {
	if !inventory.ValidID(env) {
		return nil, inventory.ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+endpointColumns+` FROM asset_endpoint WHERE environment_id=$1 ORDER BY created_at,id`, env)
	if err != nil {
		return nil, topologyError(err)
	}
	defer rows.Close()
	items := []inventory.Endpoint{}
	for rows.Next() {
		v, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, topologyError(rows.Err())
}
func (s *Store) GetEndpoint(ctx context.Context, env, id string) (inventory.Endpoint, error) {
	if !inventory.ValidID(env) || !inventory.ValidID(id) {
		return inventory.Endpoint{}, inventory.ErrNotFound
	}
	return scanEndpoint(s.pool.QueryRow(ctx, `SELECT `+endpointColumns+` FROM asset_endpoint WHERE environment_id=$1 AND id=$2`, env, id))
}
func (s *Store) SaveEndpoint(ctx context.Context, v inventory.Endpoint) (inventory.Endpoint, error) {
	v, err := inventory.ValidateEndpoint(v)
	if err != nil {
		return v, err
	}
	if v.ID == "" {
		return scanEndpoint(s.pool.QueryRow(ctx, `INSERT INTO asset_endpoint(environment_id,asset_id,protocol,host,port,preferred,status) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING `+endpointColumns, v.EnvironmentID, v.AssetID, v.Protocol, v.Host, v.Port, v.Preferred, v.Status))
	}
	return scanEndpoint(s.pool.QueryRow(ctx, `UPDATE asset_endpoint SET asset_id=$2,protocol=$3,host=$4,port=$5,preferred=$6,status=$7,updated_at=CURRENT_TIMESTAMP WHERE environment_id=$1 AND id=$8 RETURNING `+endpointColumns, v.EnvironmentID, v.AssetID, v.Protocol, v.Host, v.Port, v.Preferred, v.Status, v.ID))
}

const membershipColumns = `id::text,environment_id::text,cluster_id::text,asset_id::text,role,created_at,updated_at`

func scanMembership(row pgx.Row) (v inventory.Membership, err error) {
	err = row.Scan(&v.ID, &v.EnvironmentID, &v.ClusterID, &v.AssetID, &v.Role, &v.CreatedAt, &v.UpdatedAt)
	return v, topologyError(err)
}
func (s *Store) ListMemberships(ctx context.Context, env string) ([]inventory.Membership, error) {
	if !inventory.ValidID(env) {
		return nil, inventory.ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+membershipColumns+` FROM cluster_membership WHERE environment_id=$1 ORDER BY created_at,id`, env)
	if err != nil {
		return nil, topologyError(err)
	}
	defer rows.Close()
	items := []inventory.Membership{}
	for rows.Next() {
		v, err := scanMembership(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, topologyError(rows.Err())
}
func (s *Store) GetMembership(ctx context.Context, env, id string) (inventory.Membership, error) {
	if !inventory.ValidID(env) || !inventory.ValidID(id) {
		return inventory.Membership{}, inventory.ErrNotFound
	}
	return scanMembership(s.pool.QueryRow(ctx, `SELECT `+membershipColumns+` FROM cluster_membership WHERE environment_id=$1 AND id=$2`, env, id))
}
func (s *Store) SaveMembership(ctx context.Context, v inventory.Membership) (inventory.Membership, error) {
	v, err := inventory.ValidateMembership(v)
	if err != nil {
		return v, err
	}
	if v.ID == "" {
		return scanMembership(s.pool.QueryRow(ctx, `INSERT INTO cluster_membership(environment_id,cluster_id,asset_id,role) VALUES($1,$2,$3,$4) RETURNING `+membershipColumns, v.EnvironmentID, v.ClusterID, v.AssetID, v.Role))
	}
	return scanMembership(s.pool.QueryRow(ctx, `UPDATE cluster_membership SET cluster_id=$2,asset_id=$3,role=$4,updated_at=CURRENT_TIMESTAMP WHERE environment_id=$1 AND id=$5 RETURNING `+membershipColumns, v.EnvironmentID, v.ClusterID, v.AssetID, v.Role, v.ID))
}
func (s *Store) RemoveMembership(ctx context.Context, env, id string) error {
	if !inventory.ValidID(env) || !inventory.ValidID(id) {
		return inventory.ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM cluster_membership WHERE environment_id=$1 AND id=$2`, env, id)
	if err != nil {
		return topologyError(err)
	}
	if tag.RowsAffected() != 1 {
		return inventory.ErrNotFound
	}
	return nil
}

const serviceColumns = `id::text,environment_id::text,COALESCE(cluster_id::text,''),name,service_type,lifecycle,created_at,updated_at`

func scanService(row pgx.Row) (v inventory.Service, err error) {
	err = row.Scan(&v.ID, &v.EnvironmentID, &v.ClusterID, &v.Name, &v.ServiceType, &v.Lifecycle, &v.CreatedAt, &v.UpdatedAt)
	return v, topologyError(err)
}
func (s *Store) ListServices(ctx context.Context, env string) ([]inventory.Service, error) {
	if !inventory.ValidID(env) {
		return nil, inventory.ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+serviceColumns+` FROM service WHERE environment_id=$1 ORDER BY created_at,id`, env)
	if err != nil {
		return nil, topologyError(err)
	}
	defer rows.Close()
	items := []inventory.Service{}
	for rows.Next() {
		v, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, topologyError(rows.Err())
}
func (s *Store) GetService(ctx context.Context, env, id string) (inventory.Service, error) {
	if !inventory.ValidID(env) || !inventory.ValidID(id) {
		return inventory.Service{}, inventory.ErrNotFound
	}
	return scanService(s.pool.QueryRow(ctx, `SELECT `+serviceColumns+` FROM service WHERE environment_id=$1 AND id=$2`, env, id))
}
func (s *Store) SaveService(ctx context.Context, v inventory.Service) (inventory.Service, error) {
	v, err := inventory.ValidateService(v)
	if err != nil {
		return v, err
	}
	if v.ID == "" {
		return scanService(s.pool.QueryRow(ctx, `INSERT INTO service(environment_id,cluster_id,name,service_type,lifecycle) VALUES($1,NULLIF($2,'')::uuid,$3,$4,$5) RETURNING `+serviceColumns, v.EnvironmentID, v.ClusterID, v.Name, v.ServiceType, v.Lifecycle))
	}
	return scanService(s.pool.QueryRow(ctx, `UPDATE service SET cluster_id=NULLIF($2,'')::uuid,name=$3,service_type=$4,lifecycle=$5,updated_at=CURRENT_TIMESTAMP WHERE environment_id=$1 AND id=$6 RETURNING `+serviceColumns, v.EnvironmentID, v.ClusterID, v.Name, v.ServiceType, v.Lifecycle, v.ID))
}

const instanceColumns = `id::text,environment_id::text,service_id::text,name,role,instance_key,lifecycle,created_at,updated_at`

func scanInstance(row pgx.Row) (v inventory.Instance, err error) {
	err = row.Scan(&v.ID, &v.EnvironmentID, &v.ServiceID, &v.Name, &v.Role, &v.InstanceKey, &v.Lifecycle, &v.CreatedAt, &v.UpdatedAt)
	return v, topologyError(err)
}
func (s *Store) ListInstances(ctx context.Context, env string) ([]inventory.Instance, error) {
	if !inventory.ValidID(env) {
		return nil, inventory.ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+instanceColumns+` FROM service_instance WHERE environment_id=$1 ORDER BY created_at,id`, env)
	if err != nil {
		return nil, topologyError(err)
	}
	defer rows.Close()
	items := []inventory.Instance{}
	for rows.Next() {
		v, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, topologyError(rows.Err())
}
func (s *Store) GetInstance(ctx context.Context, env, id string) (inventory.Instance, error) {
	if !inventory.ValidID(env) || !inventory.ValidID(id) {
		return inventory.Instance{}, inventory.ErrNotFound
	}
	return scanInstance(s.pool.QueryRow(ctx, `SELECT `+instanceColumns+` FROM service_instance WHERE environment_id=$1 AND id=$2`, env, id))
}
func (s *Store) SaveInstance(ctx context.Context, v inventory.Instance) (inventory.Instance, error) {
	v, err := inventory.ValidateInstance(v)
	if err != nil {
		return v, err
	}
	if v.ID == "" {
		return scanInstance(s.pool.QueryRow(ctx, `INSERT INTO service_instance(environment_id,service_id,name,role,instance_key,lifecycle) VALUES($1,$2,$3,$4,$5,$6) RETURNING `+instanceColumns, v.EnvironmentID, v.ServiceID, v.Name, v.Role, v.InstanceKey, v.Lifecycle))
	}
	return scanInstance(s.pool.QueryRow(ctx, `UPDATE service_instance SET service_id=$2,name=$3,role=$4,instance_key=$5,lifecycle=$6,updated_at=CURRENT_TIMESTAMP WHERE environment_id=$1 AND id=$7 RETURNING `+instanceColumns, v.EnvironmentID, v.ServiceID, v.Name, v.Role, v.InstanceKey, v.Lifecycle, v.ID))
}

const bindingColumns = `id::text,environment_id::text,service_instance_id::text,asset_id::text,binding_role,created_at,updated_at`

func scanBinding(row pgx.Row) (v inventory.Binding, err error) {
	err = row.Scan(&v.ID, &v.EnvironmentID, &v.InstanceID, &v.AssetID, &v.BindingRole, &v.CreatedAt, &v.UpdatedAt)
	return v, topologyError(err)
}
func (s *Store) ListBindings(ctx context.Context, env string) ([]inventory.Binding, error) {
	if !inventory.ValidID(env) {
		return nil, inventory.ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+bindingColumns+` FROM service_instance_host WHERE environment_id=$1 ORDER BY created_at,id`, env)
	if err != nil {
		return nil, topologyError(err)
	}
	defer rows.Close()
	items := []inventory.Binding{}
	for rows.Next() {
		v, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, topologyError(rows.Err())
}
func (s *Store) GetBinding(ctx context.Context, env, id string) (inventory.Binding, error) {
	if !inventory.ValidID(env) || !inventory.ValidID(id) {
		return inventory.Binding{}, inventory.ErrNotFound
	}
	return scanBinding(s.pool.QueryRow(ctx, `SELECT `+bindingColumns+` FROM service_instance_host WHERE environment_id=$1 AND id=$2`, env, id))
}
func (s *Store) SaveBinding(ctx context.Context, v inventory.Binding) (inventory.Binding, error) {
	v, err := inventory.ValidateBinding(v)
	if err != nil {
		return v, err
	}
	if v.ID == "" {
		return scanBinding(s.pool.QueryRow(ctx, `INSERT INTO service_instance_host(environment_id,service_instance_id,asset_id,binding_role) VALUES($1,$2,$3,$4) RETURNING `+bindingColumns, v.EnvironmentID, v.InstanceID, v.AssetID, v.BindingRole))
	}
	return scanBinding(s.pool.QueryRow(ctx, `UPDATE service_instance_host SET service_instance_id=$2,asset_id=$3,binding_role=$4,updated_at=CURRENT_TIMESTAMP WHERE environment_id=$1 AND id=$5 RETURNING `+bindingColumns, v.EnvironmentID, v.InstanceID, v.AssetID, v.BindingRole, v.ID))
}
func (s *Store) RemoveBinding(ctx context.Context, env, id string) error {
	if !inventory.ValidID(env) || !inventory.ValidID(id) {
		return inventory.ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM service_instance_host WHERE environment_id=$1 AND id=$2`, env, id)
	if err != nil {
		return topologyError(err)
	}
	if tag.RowsAffected() != 1 {
		return inventory.ErrNotFound
	}
	return nil
}
