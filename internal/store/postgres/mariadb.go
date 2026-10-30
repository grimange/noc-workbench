package postgres

import (
	"context"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/integrations/mariadb"
	"noc-workbench/internal/workspace"
)

// MariaDBHistory selects complete bounded snapshots rather than joining latest
// channel rows from different runs. Existing run FKs enforce canonical ownership.
func (s *Store) MariaDBHistory(ctx context.Context, p workspace.Principal, h collection.HistoryScope) (mariadb.History, error) {
	var out mariadb.History
	if collectionAccess(p, h) != nil {
		return out, workspace.ErrDenied
	}
	rows, e := s.pool.Query(ctx, `SELECT r.id::text,c.started_at,c.outcome,c.diagnostics FROM collection_run r JOIN collector_result c ON c.run_id=r.id WHERE r.customer_id=$1 AND r.environment_id=$2 AND r.asset_id=$3 AND c.collector_id='mariadb.health' ORDER BY c.started_at DESC,r.id DESC LIMIT 12`, h.CustomerID, h.EnvironmentID, h.AssetID)
	if e != nil {
		return out, ErrUnavailable
	}
	var ids []string
	for rows.Next() {
		var id string
		var a mariadb.Attempt
		if rows.Scan(&id, &a.At, &a.Outcome, &a.Codes) != nil {
			rows.Close()
			return out, ErrUnavailable
		}
		if len(ids) == 0 {
			out.Attempt = a
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, ErrUnavailable
	}
	if len(ids) == 0 {
		return out, nil
	}
	rows, e = s.pool.Query(ctx, `SELECT o.run_id::text,o.profile_id::text,o.endpoint_id::text,o.profile_revision,o.observed_at,o.received_at,o.ttl_seconds,o.resource,o.text_value FROM observation o JOIN collection_run r ON r.id=o.run_id WHERE r.customer_id=$1 AND r.environment_id=$2 AND r.asset_id=$3 AND r.id=ANY($4::uuid[]) AND o.collector_id='mariadb.health' AND o.key='mariadb.snapshot' ORDER BY o.observed_at DESC,o.run_id,o.resource LIMIT 781`, h.CustomerID, h.EnvironmentID, h.AssetID, ids)
	if e != nil {
		return out, ErrUnavailable
	}
	defer rows.Close()
	grouped := map[string][]collection.Observation{}
	samples := map[string]mariadb.Sample{}
	count := 0
	for rows.Next() {
		count++
		if count > 780 {
			return out, ErrUnavailable
		}
		var v mariadb.Sample
		var resource, value string
		if rows.Scan(&v.RunID, &v.ProfileID, &v.EndpointID, &v.ProfileVersion, &v.At, &v.Received, &v.TTL, &resource, &value) != nil {
			return out, ErrUnavailable
		}
		samples[v.RunID] = v
		grouped[v.RunID] = append(grouped[v.RunID], collection.Observation{Key: mariadb.Key, Resource: resource, Value: collection.Text(value)})
	}
	if rows.Err() != nil {
		return out, ErrUnavailable
	}
	for _, id := range ids {
		obs := grouped[id]
		if len(obs) == 0 {
			continue
		}
		snap, e := mariadb.Decode(obs)
		if e != nil {
			return out, ErrUnavailable
		}
		v := samples[id]
		v.Snapshot = snap
		out.Samples = append(out.Samples, v)
	}
	return out, nil
}
