package postgres

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/alerts"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
	"sort"
	"strconv"
	"time"
)

func lockAlertAsset(ctx context.Context, tx pgx.Tx, h collection.HistoryScope) error {
	var id string
	if tx.QueryRow(ctx, `SELECT a.id::text FROM asset a JOIN environment e ON e.id=a.environment_id WHERE a.id=$1 AND e.id=$2 AND e.customer_id=$3 FOR UPDATE OF a`, h.AssetID, h.EnvironmentID, h.CustomerID).Scan(&id) != nil {
		return workspace.ErrDenied
	}
	return nil
}
func (s *Store) SaveAlertRule(ctx context.Context, p workspace.Principal, h collection.HistoryScope, r alerts.Rule) (alerts.Rule, error) {
	if e := collectionAccess(p, h); e != nil {
		return r, e
	}
	if !inventory.ValidID(r.PolicyID) {
		return r, alerts.ErrRule
	}
	expected := r.Revision
	r.Revision++
	if r.Validate() != nil || expected < 0 {
		return r, alerts.ErrRule
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return r, ErrUnavailable
	}
	defer tx.Rollback(ctx)
	if e = lockAlertAsset(ctx, tx, h); e != nil {
		return r, e
	}
	var current, policyRev int64
	var count int
	if tx.QueryRow(ctx, `SELECT count(*) FROM alert_rule WHERE asset_id=$1`, h.AssetID).Scan(&count) != nil {
		return r, ErrUnavailable
	}
	if count >= 4096 {
		return r, alerts.ErrRule
	}
	e = tx.QueryRow(ctx, `SELECT id::text,revision FROM alert_rule WHERE asset_id=$1 AND policy_id=$2 ORDER BY revision DESC LIMIT 1`, h.AssetID, r.PolicyID).Scan(&r.ID, &current)
	if e != nil && e != pgx.ErrNoRows {
		return r, ErrUnavailable
	}
	if current != expected {
		return r, alerts.ErrRule
	}
	if tx.QueryRow(ctx, `SELECT revision FROM evaluation_policy WHERE id=$1 AND asset_id=$2 AND rule IN ('memory_available_low','filesystem_used_high') ORDER BY revision DESC LIMIT 1`, r.PolicyID, h.AssetID).Scan(&policyRev) != nil {
		return r, alerts.ErrRule
	}
	e = tx.QueryRow(ctx, `INSERT INTO alert_rule(id,revision,customer_id,environment_id,asset_id,policy_id,policy_revision,severity,debounce_seconds,enabled,actor) VALUES(coalesce(nullif($1,'')::uuid,gen_random_uuid()),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id::text,created_at`, r.ID, r.Revision, h.CustomerID, h.EnvironmentID, h.AssetID, r.PolicyID, policyRev, r.Severity, r.DebounceSeconds, r.Enabled, p.ID).Scan(&r.ID, &r.CreatedAt)
	if e != nil {
		return r, ErrUnavailable
	}
	if _, e = tx.Exec(ctx, `INSERT INTO alert_cursor(asset_id) VALUES($1) ON CONFLICT DO NOTHING`, h.AssetID); e != nil {
		return r, ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return r, ErrUnavailable
	}
	r.Actor = p.ID
	return r, nil
}
func readRules(ctx context.Context, tx pgx.Tx, asset string) ([]alerts.Rule, error) {
	rows, e := tx.Query(ctx, `SELECT DISTINCT ON(id) id::text,revision,policy_id::text,severity,debounce_seconds,enabled,actor::text,created_at FROM alert_rule WHERE asset_id=$1 ORDER BY id,revision DESC LIMIT 33`, asset)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var out []alerts.Rule
	for rows.Next() {
		var r alerts.Rule
		if rows.Scan(&r.ID, &r.Revision, &r.PolicyID, &r.Severity, &r.DebounceSeconds, &r.Enabled, &r.Actor, &r.CreatedAt) != nil {
			return nil, ErrUnavailable
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	if len(out) > 32 {
		return nil, alerts.ErrRule
	}
	return out, nil
}
func (s *Store) AlertView(ctx context.Context, p workspace.Principal, h collection.HistoryScope) (alerts.View, error) {
	var out alerts.View
	if e := collectionAccess(p, h); e != nil {
		return out, e
	}
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return out, ErrUnavailable
	}
	defer tx.Rollback(ctx)
	var id string
	if tx.QueryRow(ctx, `SELECT a.id::text FROM asset a JOIN environment e ON e.id=a.environment_id WHERE a.id=$1 AND e.id=$2 AND e.customer_id=$3`, h.AssetID, h.EnvironmentID, h.CustomerID).Scan(&id) != nil {
		return out, workspace.ErrDenied
	}
	out.Rules, e = readRules(ctx, tx, h.AssetID)
	if e != nil {
		return out, e
	}
	rows, e := tx.Query(ctx, `SELECT snapshot FROM alert_instance WHERE asset_id=$1 ORDER BY updated_at DESC,id LIMIT 100`, h.AssetID)
	if e != nil {
		return out, ErrUnavailable
	}
	for rows.Next() {
		var raw []byte
		var v alerts.Instance
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &v) != nil {
			rows.Close()
			return out, ErrUnavailable
		}
		out.Alerts = append(out.Alerts, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, ErrUnavailable
	}
	rows, e = tx.Query(ctx, `SELECT id,kind,actor::text,at,snapshot FROM alert_event WHERE asset_id=$1 ORDER BY id DESC LIMIT 100`, h.AssetID)
	if e != nil {
		return out, ErrUnavailable
	}
	for rows.Next() {
		var raw []byte
		var v alerts.Event
		if rows.Scan(&v.ID, &v.Kind, &v.Actor, &v.At, &raw) != nil || json.Unmarshal(raw, &v.Snapshot) != nil {
			rows.Close()
			return out, ErrUnavailable
		}
		out.Events = append(out.Events, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || tx.Commit(ctx) != nil {
		return out, ErrUnavailable
	}
	return out, nil
}
func (s *Store) AcknowledgeAlert(ctx context.Context, p workspace.Principal, h collection.HistoryScope, id string) error {
	if e := collectionAccess(p, h); e != nil {
		return e
	}
	if !inventory.ValidID(id) {
		return workspace.ErrDenied
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(ctx)
	if e = lockAlertAsset(ctx, tx, h); e != nil {
		return e
	}
	var raw []byte
	var v alerts.Instance
	if tx.QueryRow(ctx, `SELECT snapshot FROM alert_instance WHERE id=$1 AND asset_id=$2 FOR UPDATE`, id, h.AssetID).Scan(&raw) != nil || json.Unmarshal(raw, &v) != nil {
		return workspace.ErrDenied
	}
	if v.State != "active" || v.AcknowledgedAt != nil {
		return nil
	}
	var at time.Time
	if tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at) != nil {
		return ErrUnavailable
	}
	v.AcknowledgedAt = &at
	v.AcknowledgedBy = p.ID
	v.UpdatedAt = at
	if e = writeAlert(ctx, tx, h.AssetID, v, "acknowledged", p.ID); e != nil {
		return e
	}
	if tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
func writeAlert(ctx context.Context, tx pgx.Tx, asset string, v alerts.Instance, kind, actor string) error {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 32768 {
		return alerts.ErrRule
	}
	if _, e = tx.Exec(ctx, `UPDATE alert_instance SET rule_revision=$2,state=$3,evidence_state=$4,snapshot=$5,evaluated_at=$6,updated_at=$7 WHERE id=$1`, v.ID, v.RuleRevision, v.State, v.EvidenceState, raw, v.EvaluatedAt, v.UpdatedAt); e != nil {
		return ErrUnavailable
	}
	if kind != "" {
		if _, e = tx.Exec(ctx, `INSERT INTO alert_event(alert_id,asset_id,kind,actor,at,snapshot) VALUES($1,$2,$3,$4,$5,$6)`, v.ID, asset, kind, actor, v.UpdatedAt, raw); e != nil {
			return ErrUnavailable
		}
	}
	return nil
}
func (s *Store) MonitoringScopes(ctx context.Context, p workspace.Principal) ([]collection.HistoryScope, error) {
	if p.ID != workspace.OperatorID {
		return nil, workspace.ErrDenied
	}
	// Claim twenty oldest cursors atomically. Failed assets rotate as well, so a
	// corrupt or unavailable resource cannot starve other scopes.
	rows, e := s.pool.Query(ctx, `WITH due AS (SELECT asset_id FROM alert_cursor ORDER BY evaluated_at,asset_id LIMIT 20 FOR UPDATE SKIP LOCKED), bumped AS (UPDATE alert_cursor c SET evaluated_at=clock_timestamp() FROM due WHERE c.asset_id=due.asset_id RETURNING c.asset_id) SELECT e.customer_id::text,a.environment_id::text,a.id::text FROM bumped b JOIN asset a ON a.id=b.asset_id JOIN environment e ON e.id=a.environment_id ORDER BY a.id`)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var out []collection.HistoryScope
	for rows.Next() {
		var h collection.HistoryScope
		if rows.Scan(&h.CustomerID, &h.EnvironmentID, &h.AssetID) != nil {
			return nil, ErrUnavailable
		}
		out = append(out, h)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
func (s *Store) EvaluateAlerts(ctx context.Context, h collection.HistoryScope, at time.Time) error {
	// Asset lock serializes rule/policy edits, acknowledgments and evaluators.
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(ctx)
	if e = lockAlertAsset(ctx, tx, h); e != nil {
		return e
	}
	in, e := evaluationEvidenceTx(ctx, tx, h, at)
	if e != nil {
		return e
	}
	evaluated, e := health.Evaluate(in)
	if e != nil {
		return e
	}
	rules, e := readRules(ctx, tx, h.AssetID)
	if e != nil {
		return e
	}
	for _, rule := range rules {
		candidates := map[string]health.Reading{}
		for _, r := range evaluated.Readings {
			if r.PolicyID == rule.PolicyID {
				candidates[r.Evidence.Resource] = r
			}
		}
		previous := map[string]alerts.Instance{}
		rows, e := tx.Query(ctx, `SELECT snapshot FROM alert_instance WHERE rule_id=$1 ORDER BY resource_hash LIMIT 2049`, rule.ID)
		if e != nil {
			return ErrUnavailable
		}
		for rows.Next() {
			var raw []byte
			var v alerts.Instance
			if rows.Scan(&raw) != nil || json.Unmarshal(raw, &v) != nil {
				rows.Close()
				return ErrUnavailable
			}
			previous[v.Resource] = v
			if _, ok := candidates[v.Resource]; !ok {
				candidates[v.Resource] = health.Reading{PolicyID: rule.PolicyID, Freshness: "unknown"}
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil || len(previous) > 2048 {
			return ErrUnavailable
		}
		resources := make([]string, 0, len(candidates))
		for resource := range candidates {
			resources = append(resources, resource)
		}
		sort.Strings(resources)
		for _, resource := range resources {
			reading := candidates[resource]
			reading.Evidence.Resource = resource
			prior := previous[resource]
			// Repeated/out-of-order evaluation has no durable side effects.
			if !at.After(prior.EvaluatedAt) {
				continue
			}
			next, kind, e := alerts.Reduce(prior, rule, reading, at)
			if e != nil {
				return e
			}
			if next.State == "" {
				continue
			}
			if prior.ID == "" {
				raw, _ := json.Marshal(next)
				e = tx.QueryRow(ctx, `INSERT INTO alert_instance(asset_id,rule_id,rule_revision,resource,state,evidence_state,snapshot,evaluated_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id::text`, h.AssetID, rule.ID, rule.Revision, resource, next.State, next.EvidenceState, raw, at, next.UpdatedAt).Scan(&next.ID)
				if e != nil {
					return ErrUnavailable
				}
			}
			if e = writeAlert(ctx, tx, h.AssetID, next, kind, workspace.OperatorID); e != nil {
				return e
			}
		}
	}
	if tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) ObservationSeries(ctx context.Context, p workspace.Principal, h collection.HistoryScope, key, resource string, from, to time.Time) (alerts.Series, error) {
	out := alerts.Series{From: from, To: to, Key: key, Resource: resource}
	if e := collectionAccess(p, h); e != nil {
		return out, e
	}
	if !health.SupportedSelector(key) || key == "linux.filesystem.identifier" || len(resource) > 4096 || from.IsZero() || !to.After(from) || to.Sub(from) > 7*24*time.Hour {
		return out, alerts.ErrRule
	}
	var exists bool
	if s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM asset a JOIN environment e ON e.id=a.environment_id WHERE a.id=$1 AND e.id=$2 AND e.customer_id=$3)`, h.AssetID, h.EnvironmentID, h.CustomerID).Scan(&exists) != nil {
		return out, ErrUnavailable
	}
	if !exists {
		return out, workspace.ErrDenied
	}
	rows, e := s.pool.Query(ctx, `SELECT o.id::text,o.run_id::text,o.key,o.resource,o.unit,coalesce(o.integer_value::text,o.number_value::text),o.collector_id,o.transport,o.observed_at,o.ttl_seconds,EXISTS(SELECT 1 FROM collection_run bad WHERE bad.asset_id=o.asset_id AND bad.state IN ('failed','cancelled','interrupted','partial') AND bad.started_at>coalesce((SELECT max(prev.observed_at) FROM observation prev WHERE prev.asset_id=o.asset_id AND prev.key=o.key AND prev.resource=o.resource AND prev.observed_at<o.observed_at),$4) AND bad.started_at<=o.observed_at) FROM observation o JOIN collection_run r ON r.id=o.run_id WHERE r.customer_id=$1 AND r.environment_id=$2 AND o.asset_id=$3 AND o.observed_at>=$4 AND o.observed_at<=$5 AND o.received_at<=$5 AND o.recorded_at<=$5 AND r.evidence_recorded_at<=$5 AND r.ended_at<=$5 AND o.key=$6 AND o.resource=$7 AND o.kind<>'text' AND o.quality='valid' ORDER BY o.observed_at,o.id LIMIT 1001`, h.CustomerID, h.EnvironmentID, h.AssetID, from, to, key, resource)
	if e != nil {
		return out, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var v alerts.Sample
		if rows.Scan(&v.ID, &v.RunID, &v.Key, &v.Resource, &v.Unit, &v.Value, &v.Collector, &v.Transport, &v.At, &v.TTLSeconds, &v.Gap) != nil {
			return out, ErrUnavailable
		}
		if len(out.Samples) > 0 {
			prev := out.Samples[len(out.Samples)-1]
			v.Gap = v.Gap || v.At.Sub(prev.At) >= time.Duration(prev.TTLSeconds)*time.Second
		}
		if _, e = strconv.ParseFloat(v.Value, 64); e != nil {
			return out, ErrUnavailable
		}
		out.Samples = append(out.Samples, v)
	}
	if rows.Err() != nil {
		return out, ErrUnavailable
	}
	if len(out.Samples) > 1000 {
		return alerts.Series{}, alerts.ErrRule
	}
	return out, nil
}

// MonitoringAssets is a bounded read; passive dashboard access never advances
// evaluation cursors or performs collection.
func (s *Store) MonitoringAssets(ctx context.Context, p workspace.Principal) ([]collection.HistoryScope, error) {
	if p.ID != workspace.OperatorID {
		return nil, workspace.ErrDenied
	}
	rows, e := s.pool.Query(ctx, `SELECT e.customer_id::text,a.environment_id::text,a.id::text FROM asset a JOIN environment e ON e.id=a.environment_id ORDER BY a.name,a.id LIMIT 50`)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var out []collection.HistoryScope
	for rows.Next() {
		var h collection.HistoryScope
		if rows.Scan(&h.CustomerID, &h.EnvironmentID, &h.AssetID) != nil {
			return nil, ErrUnavailable
		}
		out = append(out, h)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}

// MaintainAlerts retains ninety days of transitions, deleting at most 1000
// expired events and 100 resolved identities per pass. Unresolved conditions
// and their acknowledgment survive independently of historical event expiry.
func (s *Store) MaintainAlerts(ctx context.Context, at time.Time) error {
	if at.IsZero() {
		return alerts.ErrRule
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(ctx)
	cutoff := at.Add(-90 * 24 * time.Hour)
	if _, e = tx.Exec(ctx, `DELETE FROM alert_event WHERE id IN (SELECT id FROM alert_event WHERE at<$1 ORDER BY at,id LIMIT 1000)`, cutoff); e != nil {
		return ErrUnavailable
	}
	if _, e = tx.Exec(ctx, `DELETE FROM alert_instance target WHERE target.state='resolved' AND target.updated_at<$1 AND NOT EXISTS(SELECT 1 FROM alert_event keep WHERE keep.alert_id=target.id) AND target.id IN (SELECT a.id FROM alert_instance a WHERE a.state='resolved' AND a.updated_at<$1 AND NOT EXISTS(SELECT 1 FROM alert_event e WHERE e.alert_id=a.id) ORDER BY a.updated_at,a.id LIMIT 100)`, cutoff); e != nil {
		return ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
