package postgres

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"noc-workbench/internal/workspace"
)

func (s *Store) SaveEvaluationPolicy(ctx context.Context, p workspace.Principal, h collection.HistoryScope, v health.Policy) (health.Policy, error) {
	if e := collectionAccess(p, h); e != nil {
		return v, e
	}
	if v.Version != "" && v.Version != health.Version {
		return v, health.ErrPolicy
	}
	expected := v.Revision
	v.Revision = expected + 1
	v.Version = health.Version
	if v.Validate() != nil || expected < 0 {
		return v, health.ErrPolicy
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return v, ErrUnavailable
	}
	defer tx.Rollback(ctx)
	// Lock one asset to serialize revisions and cap retained policy history.
	var active bool
	e = tx.QueryRow(ctx, `SELECT a.lifecycle='active' AND e.status='active' AND c.status='active' FROM asset a JOIN environment e ON e.id=a.environment_id JOIN customer c ON c.id=e.customer_id WHERE a.id=$1 AND e.id=$2 AND c.id=$3 FOR UPDATE OF a`, h.AssetID, h.EnvironmentID, h.CustomerID).Scan(&active)
	if e != nil || !active {
		return v, workspace.ErrDenied
	}
	var count int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM evaluation_policy WHERE asset_id=$1`, h.AssetID).Scan(&count); e != nil {
		return v, ErrUnavailable
	}
	if count >= 4096 {
		return v, health.ErrPolicy
	}
	var current int64
	var id string
	e = tx.QueryRow(ctx, `SELECT id::text,revision FROM evaluation_policy WHERE asset_id=$1 AND selector=$2 ORDER BY revision DESC LIMIT 1`, h.AssetID, v.Selector).Scan(&id, &current)
	if e != nil && e != pgx.ErrNoRows {
		return v, ErrUnavailable
	}
	if current != expected {
		return v, health.ErrPolicy
	}
	e = tx.QueryRow(ctx, `INSERT INTO evaluation_policy(id,revision,customer_id,environment_id,asset_id,selector,version,ttl_seconds,rule,threshold,enabled,actor) VALUES(coalesce(nullif($1,'')::uuid,gen_random_uuid()),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id::text,created_at`, id, v.Revision, h.CustomerID, h.EnvironmentID, h.AssetID, v.Selector, v.Version, v.TTLSeconds, v.Rule, v.Threshold, v.Enabled, p.ID).Scan(&v.ID, &v.CreatedAt)
	if e != nil || tx.Commit(ctx) != nil {
		return v, ErrUnavailable
	}
	v.Actor = p.ID
	return v, nil
}

// EvaluationEvidence takes one repeatable-read snapshot. Samples must have been
// observed, received AND recorded as terminal evidence by the selected time.
// These are database event timestamps, not historical MVCC/commit snapshots;
// retrieval sees only committed rows in its current repeatable-read snapshot.
// Retention is not reversed: absence is explicitly unknown, never backfilled.
func (s *Store) EvaluationEvidence(ctx context.Context, p workspace.Principal, h collection.HistoryScope, at time.Time) (health.Input, error) {
	in := health.Input{Scope: h, At: at}
	if e := collectionAccess(p, h); e != nil {
		return in, e
	}
	if at.IsZero() {
		return in, health.ErrEvidence
	}
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return in, ErrUnavailable
	}
	defer tx.Rollback(ctx)
	in, e = evaluationEvidenceTx(ctx, tx, h, at)
	if e != nil {
		return in, e
	}
	if tx.Commit(ctx) != nil {
		return in, ErrUnavailable
	}
	return in, nil
}
func evaluationEvidenceTx(ctx context.Context, tx pgx.Tx, h collection.HistoryScope, at time.Time) (health.Input, error) {
	in := health.Input{Scope: h, At: at}
	var e error
	e = tx.QueryRow(ctx, `SELECT a.lifecycle='active' AND e.status='active' AND c.status='active',EXISTS(SELECT 1 FROM connection_profile cp WHERE cp.asset_id=a.id AND cp.state='connection_verified') AND NOT EXISTS(SELECT 1 FROM connection_profile cp WHERE cp.asset_id=a.id AND cp.state<>'connection_verified'),coalesce((SELECT interval_seconds FROM collection_schedule WHERE asset_id=a.id AND enabled AND authorized),0) FROM asset a JOIN environment e ON e.id=a.environment_id JOIN customer c ON c.id=e.customer_id WHERE a.id=$1 AND e.id=$2 AND c.id=$3`, h.AssetID, h.EnvironmentID, h.CustomerID).Scan(&in.Active, &in.Trusted, &in.IntervalSeconds)
	if e != nil {
		return in, workspace.ErrDenied
	}
	in.Authority = map[string]int64{}
	authorityRows, err := tx.Query(ctx, `SELECT cp.id::text,cp.revision FROM connection_profile cp JOIN asset_endpoint ep ON ep.id=cp.endpoint_id WHERE cp.asset_id=$1 AND cp.state='connection_verified' AND ep.status='active' AND cp.details->>'EndpointUpdatedAt' IS NOT NULL AND (cp.details->>'EndpointUpdatedAt')::timestamptz=ep.updated_at`, h.AssetID)
	if err != nil {
		return in, ErrUnavailable
	}
	for authorityRows.Next() {
		var id string
		var rev int64
		if authorityRows.Scan(&id, &rev) != nil {
			authorityRows.Close()
			return in, ErrUnavailable
		}
		in.Authority[id] = rev
	}
	err = authorityRows.Err()
	authorityRows.Close()
	if err != nil {
		return in, ErrUnavailable
	}
	rows, e := tx.Query(ctx, `SELECT DISTINCT ON(selector) id::text,revision,version,selector,ttl_seconds,rule,threshold,enabled,created_at,actor::text,CASE WHEN asset_id IS NULL THEN 'canonical' ELSE 'asset' END FROM evaluation_policy WHERE (asset_id=$1 OR asset_id IS NULL) AND selector NOT IN ('vicidial.api.version','vicidial.api.campaigns','vicidial.api.agents') AND created_at<=$2 ORDER BY selector,asset_id NULLS LAST,revision DESC LIMIT 65`, h.AssetID, at)
	if e != nil {
		return in, ErrUnavailable
	}
	for rows.Next() {
		var v health.Policy
		if rows.Scan(&v.ID, &v.Revision, &v.Version, &v.Selector, &v.TTLSeconds, &v.Rule, &v.Threshold, &v.Enabled, &v.CreatedAt, &v.Actor, &v.Scope) != nil {
			rows.Close()
			return in, ErrUnavailable
		}
		in.Policies = append(in.Policies, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return in, ErrUnavailable
	}
	for i := 0; i < 2; i++ {
		condition := ""
		if i == 1 {
			condition = " AND state='completed' AND ended_at<=$4 AND evidence_recorded_at<=$4"
		}
		r, err := scanRun(tx.QueryRow(ctx, `SELECT `+strings.Replace(runColumns, "ended_at", "CASE WHEN evidence_recorded_at<=$4 THEN ended_at ELSE NULL END", 1)+` FROM collection_run WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 AND started_at<=$4`+condition+` ORDER BY started_at DESC,id DESC LIMIT 1`, h.CustomerID, h.EnvironmentID, h.AssetID, at))
		if err != nil && err != pgx.ErrNoRows {
			return in, ErrUnavailable
		}
		if err == nil {
			if i == 0 {
				in.LatestAttempt = &r
			} else {
				in.LastSuccess = &r
			}
		}
	}
	if in.LatestAttempt != nil && !in.LatestAttempt.EndedAt.IsZero() && !in.LatestAttempt.EndedAt.After(at) {
		rr, err := tx.Query(ctx, `SELECT collector_id,version,command_id,outcome,transport_outcome,started_at,ended_at,observation_count,diagnostics FROM collector_result WHERE run_id=$1 ORDER BY collector_id LIMIT 10`, in.LatestAttempt.ID)
		if err != nil {
			return in, ErrUnavailable
		}
		for rr.Next() {
			var c collection.Result
			var ds []string
			if rr.Scan(&c.CollectorID, &c.Version, &c.CommandID, &c.Outcome, &c.TransportOutcome, &c.StartedAt, &c.EndedAt, &c.ObservationCount, &ds) != nil {
				rr.Close()
				return in, ErrUnavailable
			}
			for _, code := range ds {
				c.Diagnostics = append(c.Diagnostics, collection.Diagnostic{Code: code})
			}
			in.LatestAttempt.Results = append(in.LatestAttempt.Results, c)
		}
		err = rr.Err()
		rr.Close()
		if err != nil {
			return in, ErrUnavailable
		}
	}
	rows, e = tx.Query(ctx, `SELECT DISTINCT ON(o.key,o.resource_hash) o.id::text,o.run_id::text,o.asset_id::text,o.endpoint_id::text,o.profile_id::text,o.profile_revision,o.collector_id,o.collector_version,o.command_id,o.key,o.resource,o.kind,coalesce(o.text_value,''),coalesce(o.integer_value::text,''),coalesce(o.number_value,0),o.unit,o.transport,o.quality,o.observed_at,o.received_at,o.ttl_seconds FROM observation o JOIN collection_run r ON r.id=o.run_id WHERE r.customer_id=$1 AND r.environment_id=$2 AND o.asset_id=$3 AND o.collector_id NOT IN ('mariadb.health','asterisk.auth','asterisk.activity','asterisk.media') AND o.observed_at<=$4 AND o.received_at<=$4 AND o.recorded_at<=$4 AND r.ended_at<=$4 AND r.evidence_recorded_at<=$4 ORDER BY o.key,o.resource_hash,o.observed_at DESC,o.id DESC LIMIT 2049`, h.CustomerID, h.EnvironmentID, h.AssetID, at)
	if e != nil {
		return in, ErrUnavailable
	}
	for rows.Next() {
		var o collection.Evidence
		var integer string
		o.SubjectType = "asset"
		if rows.Scan(&o.ID, &o.RunID, &o.AssetID, &o.EndpointID, &o.ProfileID, &o.ProfileVersion, &o.CollectorID, &o.CollectorVersion, &o.CommandID, &o.Key, &o.Resource, &o.Value.Kind, &o.Value.Text, &integer, &o.Value.Number, &o.Unit, &o.Transport, &o.Quality, &o.ObservedAt, &o.ReceivedAt, &o.TTLSeconds) != nil {
			rows.Close()
			return in, ErrUnavailable
		}
		if integer != "" {
			o.Value.Integer, e = strconv.ParseUint(integer, 10, 64)
			if e != nil {
				rows.Close()
				return in, ErrUnavailable
			}
		}
		in.Evidence = append(in.Evidence, o)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return in, ErrUnavailable
	}
	return in, nil
}
