package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/health"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

// ServerEvidence reads at most one page in a fixed number of queries, in one
// snapshot. It returns only runtime and installation evidence, never API data.
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
	rows, e := tx.Query(ctx, `SELECT a.id::text,c.id::text,e.id::text,a.lifecycle='active' AND e.status='active' AND c.status='active',EXISTS(SELECT 1 FROM connection_profile cp WHERE cp.asset_id=a.id AND cp.state='connection_verified') AND NOT EXISTS(SELECT 1 FROM connection_profile cp WHERE cp.asset_id=a.id AND cp.state<>'connection_verified') AND NOT EXISTS(SELECT 1 FROM ssh_execution_guard g JOIN connection_profile cp ON cp.id=g.profile_id WHERE cp.asset_id=a.id)`+serverFrom+` WHERE `+serverScope+` AND a.kind='server' AND a.id::text=ANY($4::text[])`, append(scopeArgs(scope), ids)...)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var id, c, en string
		var active, trusted bool
		if e = rows.Scan(&id, &c, &en, &active, &trusted); e != nil {
			rows.Close()
			return nil, nil, e
		}
		inputs[id] = &health.Input{Scope: collection.HistoryScope{AssetID: id, CustomerID: c, EnvironmentID: en}, At: at, Active: active, Trusted: trusted, Authority: map[string]int64{}}
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
	rows, e = tx.Query(ctx, `SELECT `+enrollmentColumns+` FROM connection_profile cp WHERE cp.asset_id::text=ANY($1::text[]) AND cp.state='connection_verified' AND NOT EXISTS(SELECT 1 FROM ssh_execution_guard g WHERE g.profile_id=cp.id) AND EXISTS(SELECT 1 FROM asset_endpoint ep WHERE ep.id=cp.endpoint_id AND ep.asset_id=cp.asset_id AND ep.environment_id=cp.environment_id AND ep.status='active' AND ep.protocol='ssh' AND ep.host=cp.details->>'Host' AND ep.port=(cp.details->>'Port')::integer AND ep.updated_at=(cp.details->>'EndpointUpdatedAt')::timestamptz) ORDER BY cp.id LIMIT 2501`, allowed)
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
	rows, e = tx.Query(ctx, `SELECT DISTINCT ON(a.id,p.selector) a.id::text,p.id::text,p.revision,p.version,p.selector,p.ttl_seconds,p.rule,p.threshold,p.enabled,p.created_at,p.actor::text FROM asset a JOIN evaluation_policy p ON (p.asset_id=a.id OR p.asset_id IS NULL) WHERE a.id::text=ANY($1::text[]) AND p.selector IN ('linux.services','linux.service.runtime','vicidial.discovery','vicidial.discovery.snapshot') AND p.created_at<=$2 ORDER BY a.id,p.selector,p.asset_id NULLS LAST,p.revision DESC LIMIT 101`, allowed, at)
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
	// Latest attempt remains separate from the earlier successful observations.
	rows, e = tx.Query(ctx, `SELECT `+runColumns+` FROM (SELECT DISTINCT ON(asset_id) * FROM collection_run WHERE asset_id::text=ANY($1::text[]) AND 'linux.services'=ANY(collector_ids) AND started_at<=$2 ORDER BY asset_id,started_at DESC,id DESC) r`, allowed, at)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		inputs[r.Target.AssetID].LatestAttempt = &r
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	rows, e = tx.Query(ctx, `SELECT `+runColumns+` FROM (SELECT DISTINCT ON(r.asset_id) r.* FROM collection_run r JOIN collector_result cr ON cr.run_id=r.id AND cr.collector_id='linux.services' AND cr.outcome='success' WHERE r.asset_id::text=ANY($1::text[]) AND r.ended_at<=$2 AND r.evidence_recorded_at<=$2 ORDER BY r.asset_id,r.started_at DESC,r.id DESC) r`, allowed, at)
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
		if in.LatestAttempt != nil {
			runIDs = append(runIDs, in.LatestAttempt.ID)
		}
	}
	rows, e = tx.Query(ctx, `SELECT run_id::text,outcome,transport_outcome FROM collector_result WHERE run_id::text=ANY($1::text[]) AND collector_id='linux.services'`, runIDs)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var id, outcome, transport string
		if e = rows.Scan(&id, &outcome, &transport); e != nil {
			rows.Close()
			return nil, nil, e
		}
		for _, in := range inputs {
			if in.LatestAttempt != nil && in.LatestAttempt.ID == id {
				in.LatestAttempt.Results = []collection.Result{{CollectorID: "linux.services", Outcome: outcome, TransportOutcome: transport}}
			}
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	rows, e = tx.Query(ctx, `SELECT DISTINCT ON(o.asset_id,o.key,o.resource_hash) o.id::text,o.run_id::text,o.asset_id::text,o.endpoint_id::text,o.profile_id::text,o.profile_revision,o.collector_id,o.collector_version,o.command_id,o.key,o.resource,o.kind,coalesce(o.text_value,''),o.unit,o.transport,o.quality,o.observed_at,o.received_at,o.ttl_seconds FROM observation o JOIN collection_run r ON r.id=o.run_id WHERE o.asset_id::text=ANY($1::text[]) AND o.key IN ('linux.service.runtime','vicidial.discovery.snapshot') AND o.observed_at<=$2 AND o.received_at<=$2 AND o.recorded_at<=$2 AND r.ended_at<=$2 AND r.evidence_recorded_at<=$2 ORDER BY o.asset_id,o.key,o.resource_hash,o.observed_at DESC,o.id DESC LIMIT 226`, allowed, at)
	if e != nil {
		return nil, nil, e
	}
	count := 0
	for rows.Next() {
		var o collection.Evidence
		o.SubjectType = "asset"
		if e = rows.Scan(&o.ID, &o.RunID, &o.AssetID, &o.EndpointID, &o.ProfileID, &o.ProfileVersion, &o.CollectorID, &o.CollectorVersion, &o.CommandID, &o.Key, &o.Resource, &o.Value.Kind, &o.Value.Text, &o.Unit, &o.Transport, &o.Quality, &o.ObservedAt, &o.ReceivedAt, &o.TTLSeconds); e != nil {
			rows.Close()
			return nil, nil, e
		}
		inputs[o.AssetID].Evidence = append(inputs[o.AssetID].Evidence, o)
		count++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	if count > 225 {
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
