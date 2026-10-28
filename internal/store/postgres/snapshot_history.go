package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/workspace"
	"strconv"
)

// RecentCollectorEvidence reads two supported snapshots per family, never contacts a
// target. Ownership is checked before the bounded, parameterized query.
func (s *Store) RecentCollectorEvidence(ctx context.Context, p workspace.Principal, h collection.HistoryScope, collector, key string) ([]collection.Evidence, error) {
	if e := collectionAccess(p, h); e != nil {
		return nil, e
	}
	if len(collector) > 128 || len(key) > 128 {
		return nil, workspace.ErrDenied
	}
	rows, e := s.pool.Query(ctx, `WITH ranked AS (SELECT o.run_id,o.resource,o.observed_at at,row_number() OVER (PARTITION BY o.resource ORDER BY o.observed_at DESC,o.run_id DESC) position FROM observation o JOIN collection_run r ON r.id=o.run_id WHERE r.customer_id=$1 AND r.environment_id=$2 AND o.asset_id=$3 AND o.collector_id=$4 AND o.key=$5 AND position('/' in o.resource)=0 AND CASE WHEN o.key=$5 THEN o.text_value::jsonb->>'status' END='supported'), recent AS (SELECT * FROM ranked WHERE position<=2) SELECT o.id::text,o.run_id::text,o.asset_id::text,o.endpoint_id::text,o.profile_id::text,o.profile_revision,o.collector_id,o.collector_version,o.command_id,o.key,o.resource,o.kind,coalesce(o.text_value,''),coalesce(o.integer_value::text,''),coalesce(o.number_value,0),o.unit,o.transport,o.quality,o.observed_at,o.received_at,o.ttl_seconds FROM observation o JOIN recent n ON n.run_id=o.run_id AND (o.resource=n.resource OR o.resource LIKE n.resource||'/%') WHERE o.collector_id=$4 AND o.key=$5 ORDER BY n.at DESC,o.resource LIMIT 4097`, h.CustomerID, h.EnvironmentID, h.AssetID, collector, key)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var out []collection.Evidence
	for rows.Next() {
		var o collection.Evidence
		var integer string
		o.SubjectType = "asset"
		if rows.Scan(&o.ID, &o.RunID, &o.AssetID, &o.EndpointID, &o.ProfileID, &o.ProfileVersion, &o.CollectorID, &o.CollectorVersion, &o.CommandID, &o.Key, &o.Resource, &o.Value.Kind, &o.Value.Text, &integer, &o.Value.Number, &o.Unit, &o.Transport, &o.Quality, &o.ObservedAt, &o.ReceivedAt, &o.TTLSeconds) != nil {
			return nil, ErrUnavailable
		}
		if integer != "" {
			o.Value.Integer, e = strconv.ParseUint(integer, 10, 64)
			if e != nil {
				return nil, ErrUnavailable
			}
		}
		out = append(out, o)
	}
	if rows.Err() != nil || len(out) > 4096 {
		return nil, ErrUnavailable
	}
	return out, nil
}

// LatestCollectorAttempt retains the most recent failed/partial attempt even
// when a later, unrelated collector ran. It returns no raw command output.
func (s *Store) LatestCollectorAttempt(ctx context.Context, p workspace.Principal, h collection.HistoryScope, collector string) (*collection.Run, error) {
	if e := collectionAccess(p, h); e != nil {
		return nil, e
	}
	if len(collector) > 128 {
		return nil, workspace.ErrDenied
	}
	r, e := scanRun(s.pool.QueryRow(ctx, `SELECT `+runColumns+` FROM collection_run WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 AND $4=ANY(collector_ids) AND ended_at IS NOT NULL AND evidence_recorded_at IS NOT NULL ORDER BY started_at DESC,id DESC LIMIT 1`, h.CustomerID, h.EnvironmentID, h.AssetID, collector))
	if e == pgx.ErrNoRows {
		return nil, nil
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	var c collection.Result
	var codes []string
	e = s.pool.QueryRow(ctx, `SELECT collector_id,version,command_id,outcome,transport_outcome,started_at,ended_at,observation_count,diagnostics FROM collector_result WHERE run_id=$1 AND collector_id=$2`, r.ID, collector).Scan(&c.CollectorID, &c.Version, &c.CommandID, &c.Outcome, &c.TransportOutcome, &c.StartedAt, &c.EndedAt, &c.ObservationCount, &codes)
	if e != nil {
		return nil, ErrUnavailable
	}
	for _, code := range codes {
		c.Diagnostics = append(c.Diagnostics, collection.Diagnostic{Code: code})
	}
	r.Results = []collection.Result{c}
	return &r, nil
}
