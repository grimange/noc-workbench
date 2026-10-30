package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/health"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

// ServerEvidence reads at most one page in a fixed number of queries, in one
// snapshot. It returns bounded monitoring and installation evidence, never API data.
func (s *Store) ServerEvidence(ctx context.Context, scope workspace.Scope, ids []string, at time.Time) ([]health.Input, []connections.Record, error) {
	if len(ids) > 25 || at.IsZero() {
		return nil, nil, workspace.ErrDenied
	}
	for _, id := range ids {
		if !inventory.ValidID(id) {
			return nil, nil, workspace.ErrDenied
		}
	}
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return nil, nil, e
	}
	defer tx.Rollback(ctx)
	inputs := map[string]*health.Input{}
	rows, e := tx.Query(ctx, `SELECT a.id::text,c.id::text,e.id::text,a.lifecycle='active' AND e.status='active' AND c.status='active',EXISTS(SELECT 1 FROM connection_profile cp WHERE cp.asset_id=a.id AND cp.state='connection_verified') AND NOT EXISTS(SELECT 1 FROM connection_profile cp WHERE cp.asset_id=a.id AND cp.state<>'connection_verified'),CASE WHEN EXISTS(SELECT 1 FROM connection_profile cp WHERE cp.asset_id=a.id AND cp.state='identity_changed') THEN 'SSH host-key trust problem' WHEN EXISTS(SELECT 1 FROM connection_profile cp WHERE cp.asset_id=a.id AND cp.state='credential_expired') THEN 'SSH authentication / authorization problem' ELSE '' END`+serverFrom+` WHERE `+serverScope+` AND a.kind='server' AND a.id=ANY($4::uuid[])`, append(scopeArgs(scope), ids)...)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var id, c, en, diagnostic string
		var active, trusted bool
		if e = rows.Scan(&id, &c, &en, &active, &trusted, &diagnostic); e != nil {
			rows.Close()
			return nil, nil, e
		}
		inputs[id] = &health.Input{Scope: collection.HistoryScope{AssetID: id, CustomerID: c, EnvironmentID: en}, At: at, Active: active, Trusted: trusted, AuthorizationDiagnostic: diagnostic, Authority: map[string]int64{}}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	// Restrict every following query to the authorized IDs returned above.
	allowed := []string{}
	for id := range inputs {
		allowed = append(allowed, id)
	}
	rows, e = tx.Query(ctx, `SELECT `+enrollmentColumns+` FROM connection_profile cp WHERE cp.asset_id=ANY($1::uuid[]) AND cp.state='connection_verified' AND EXISTS(SELECT 1 FROM asset_endpoint ep WHERE ep.id=cp.endpoint_id AND ep.asset_id=cp.asset_id AND ep.environment_id=cp.environment_id AND ep.status='active' AND ep.protocol='ssh' AND ep.host=cp.details->>'Host' AND ep.port=(cp.details->>'Port')::integer AND ep.updated_at=(cp.details->>'EndpointUpdatedAt')::timestamptz) ORDER BY cp.id LIMIT 2501`, allowed)
	if e != nil {
		return nil, nil, e
	}
	records := []connections.Record{}
	for rows.Next() {
		r, err := scanEnrollment(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		records = append(records, r)
		inputs[r.AssetID].Authority[r.ID] = r.Revision
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	if len(records) > 2500 {
		return nil, nil, workspace.ErrLimit
	}
	rows, e = tx.Query(ctx, `SELECT DISTINCT ON(a.id,p.selector) a.id::text,p.id::text,p.revision,p.version,p.selector,p.ttl_seconds,p.rule,p.threshold,p.enabled,p.created_at,p.actor::text FROM asset a JOIN evaluation_policy p ON (p.asset_id=a.id OR p.asset_id IS NULL) WHERE a.id=ANY($1::uuid[]) AND p.selector IN ('linux.baseline','linux.baseline.status','linux.baseline.cpu_percent','linux.load.1m','linux.mem.available_bytes','linux.mem.total_bytes','linux.baseline.units','linux.filesystem.identifier','linux.filesystem.total_bytes','linux.filesystem.used_bytes','linux.filesystem.available_bytes','linux.filesystem.utilization_percent','linux.load','linux.memory','linux.filesystems','linux.services','linux.service.runtime','vicidial.discovery','vicidial.discovery.snapshot') AND p.created_at<=$2 ORDER BY a.id,p.selector,p.asset_id NULLS LAST,p.revision DESC LIMIT 476`, allowed, at)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var id string
		var p health.Policy
		if e = rows.Scan(&id, &p.ID, &p.Revision, &p.Version, &p.Selector, &p.TTLSeconds, &p.Rule, &p.Threshold, &p.Enabled, &p.CreatedAt, &p.Actor); e != nil {
			rows.Close()
			return nil, nil, e
		}
		inputs[id].Policies = append(inputs[id].Policies, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	// Policy bound: 19 selectors × 25 assets.
	// Latest attempt remains separate from the earlier successful observations.
	rows, e = tx.Query(ctx, `SELECT `+runColumns+` FROM (SELECT r.* FROM unnest($1::uuid[]) aid CROSS JOIN LATERAL (SELECT * FROM collection_run WHERE asset_id=aid AND started_at<=$2 ORDER BY started_at DESC,id DESC LIMIT 3) r) r ORDER BY asset_id,started_at DESC,id DESC`, allowed, at)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		in := inputs[r.Target.AssetID]
		in.RecentAttempts = append(in.RecentAttempts, r)
		if in.LatestAttempt == nil && !r.EndedAt.IsZero() {
			in.LatestAttempt = &r
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	rows, e = tx.Query(ctx, `SELECT `+runColumns+` FROM (SELECT DISTINCT ON(r.asset_id) r.* FROM collection_run r JOIN collector_result cr ON cr.run_id=r.id AND cr.collector_id='linux.services' AND cr.outcome='success' WHERE r.asset_id=ANY($1::uuid[]) AND r.ended_at<=$2 AND r.evidence_recorded_at<=$2 ORDER BY r.asset_id,r.started_at DESC,r.id DESC) r`, allowed, at)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		inputs[r.Target.AssetID].LastSuccess = &r
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	runIDs := []string{}
	for _, in := range inputs {
		for _, r := range in.RecentAttempts {
			runIDs = append(runIDs, r.ID)
		}
	}
	rows, e = tx.Query(ctx, `SELECT run_id::text,collector_id,outcome,transport_outcome FROM collector_result WHERE run_id::text=ANY($1::text[]) AND collector_id IN ('linux.services','linux.baseline','linux.memory','linux.filesystems')`, runIDs)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var id, collector, outcome, transport string
		if e = rows.Scan(&id, &collector, &outcome, &transport); e != nil {
			rows.Close()
			return nil, nil, e
		}
		for _, in := range inputs {
			for i := range in.RecentAttempts {
				if in.RecentAttempts[i].ID == id {
					in.RecentAttempts[i].Results = append(in.RecentAttempts[i].Results, collection.Result{CollectorID: collector, Outcome: outcome, TransportOutcome: transport})
				}
			}
			if in.LatestAttempt != nil && in.LatestAttempt.ID == id {
				in.LatestAttempt.Results = append(in.LatestAttempt.Results, collection.Result{CollectorID: collector, Outcome: outcome, TransportOutcome: transport})
			}
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	// Per asset: 32 unit chunks + status/CPU/load + 2 memory + 5 root
	// filesystem fields + 8 runtime identities + discovery = 51 observations.
	rows, e = tx.Query(ctx, `SELECT DISTINCT ON(o.asset_id,o.key,o.resource_hash) o.id::text,o.run_id::text,o.asset_id::text,o.endpoint_id::text,o.profile_id::text,o.profile_revision,o.collector_id,o.collector_version,o.command_id,o.key,o.resource,o.kind,coalesce(o.text_value,''),coalesce(o.integer_value::text,''),coalesce(o.number_value,0),o.unit,o.transport,o.quality,o.observed_at,o.received_at,o.ttl_seconds FROM observation o JOIN collection_run r ON r.id=o.run_id WHERE o.asset_id=ANY($1::uuid[]) AND (o.key IN ('linux.load.1m','linux.service.runtime','vicidial.discovery.snapshot','linux.baseline.status','linux.baseline.cpu_percent','linux.baseline.units','linux.mem.available_bytes','linux.mem.total_bytes') OR (o.resource='/' AND o.key IN ('linux.filesystem.identifier','linux.filesystem.total_bytes','linux.filesystem.used_bytes','linux.filesystem.available_bytes','linux.filesystem.utilization_percent'))) AND o.observed_at<=$2 AND o.received_at<=$2 AND o.recorded_at<=$2 AND r.ended_at<=$2 AND r.evidence_recorded_at<=$2 ORDER BY o.asset_id,o.key,o.resource_hash,o.observed_at DESC,o.id DESC LIMIT 1276`, allowed, at)
	if e != nil {
		return nil, nil, e
	}
	count := 0
	for rows.Next() {
		var o collection.Evidence
		var integer string
		o.SubjectType = "asset"
		if e = rows.Scan(&o.ID, &o.RunID, &o.AssetID, &o.EndpointID, &o.ProfileID, &o.ProfileVersion, &o.CollectorID, &o.CollectorVersion, &o.CommandID, &o.Key, &o.Resource, &o.Value.Kind, &o.Value.Text, &integer, &o.Value.Number, &o.Unit, &o.Transport, &o.Quality, &o.ObservedAt, &o.ReceivedAt, &o.TTLSeconds); e != nil {
			rows.Close()
			return nil, nil, e
		}
		if integer != "" {
			o.Value.Integer, _ = strconv.ParseUint(integer, 10, 64)
		}
		inputs[o.AssetID].Evidence = append(inputs[o.AssetID].Evidence, o)
		count++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	if count > 1275 {
		return nil, nil, workspace.ErrLimit
	}
	out := []health.Input{}
	for _, id := range ids {
		if in := inputs[id]; in != nil {
			out = append(out, *in)
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, nil, e
	}
	return out, records, nil
}
