package postgres

import (
	"context"
	"noc-workbench/internal/alerts"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"noc-workbench/internal/workspace"
	"time"
)

// SourceEvaluation reuses the canonical pure evaluator and immutable policies.
// API observations establish freshness/quality, never campaign health.
func (s *Store) SourceEvaluation(ctx context.Context, p workspace.Principal, v collection.Source, at time.Time) (health.Input, error) {
	in := health.Input{Scope: collection.HistoryScope{CustomerID: v.CustomerID, EnvironmentID: v.EnvironmentID, SourceID: v.ID}, At: at}
	if at.IsZero() {
		return in, health.ErrEvidence
	}
	h, e := s.SourceHistory(ctx, p, v, at)
	if e != nil {
		return in, e
	}
	in.Evidence = h.Latest
	for i := range h.Runs {
		if h.Runs[i].CollectionSource.Revision == v.Revision {
			in.LatestAttempt = &h.Runs[i]
			break
		}
	}
	for i := range h.Runs {
		if h.Runs[i].CollectionSource.Revision == v.Revision && h.Runs[i].SuccessCount > 0 && !h.Runs[i].EndedAt.After(at) {
			in.LastSuccess = &h.Runs[i]
			break
		}
	}
	// Current authority is contextual only: revoked authority never erases history.
	_, e = s.CollectionSource(ctx, p, v.ID, v.Revision)
	in.Active = e == nil
	in.Trusted = e == nil
	rows, e := s.pool.Query(ctx, `SELECT DISTINCT ON(selector) id::text,revision,version,selector,ttl_seconds,rule,threshold,enabled,created_at,actor::text FROM evaluation_policy WHERE asset_id IS NULL AND selector IN ('vicidial.api.version','vicidial.api.campaigns','vicidial.api.agents') AND created_at<=$1 ORDER BY selector,revision DESC`, at)
	if e != nil {
		return in, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var policy health.Policy
		policy.Scope = "canonical"
		if rows.Scan(&policy.ID, &policy.Revision, &policy.Version, &policy.Selector, &policy.TTLSeconds, &policy.Rule, &policy.Threshold, &policy.Enabled, &policy.CreatedAt, &policy.Actor) != nil {
			return in, ErrUnavailable
		}
		in.Policies = append(in.Policies, policy)
	}
	if rows.Err() != nil {
		return in, ErrUnavailable
	}
	return in, nil
}

// SourceSeries queries actual samples only, without interpolation/downsampling.
// A failure between samples or an expired TTL starts a new chart segment.
func (s *Store) SourceSeries(ctx context.Context, p workspace.Principal, v collection.Source, key string, from, to time.Time) (alerts.Series, error) {
	out := alerts.Series{Key: key, From: from, To: to}
	if sourceAccess(p, v) != nil || v.ID == "" {
		return out, workspace.ErrDenied
	}
	valid := key == "vicidial.campaigns.configured_count" || key == "vicidial.campaigns.active_count" || key == "vicidial.agents.visible_logged_in_count" || key == "vicidial.agents.visible_in_call_count" || key == "vicidial.agents.visible_paused_count"
	if !valid || from.IsZero() || !to.After(from) || to.Sub(from) > 7*24*time.Hour {
		return out, health.ErrEvidence
	}
	rows, e := s.pool.Query(ctx, `SELECT o.id::text,r.id::text,o.observed_at,o.integer_value::text,o.unit,o.collector_id,o.transport,o.ttl_seconds,EXISTS(SELECT 1 FROM collection_run f WHERE f.source_id=r.source_id AND f.failure_count>0 AND f.started_at<o.observed_at AND f.started_at>coalesce((SELECT max(pr.observed_at) FROM observation pr WHERE pr.source_id=o.source_id AND pr.key=o.key AND pr.observed_at<o.observed_at),$5)) FROM observation o JOIN collection_run r ON r.id=o.run_id WHERE o.source_id=$1 AND r.customer_id=$2 AND r.environment_id=$3 AND r.cluster_id=$4 AND o.observed_at>=$5 AND o.observed_at<=$6 AND o.received_at<=$6 AND o.recorded_at<=$6 AND r.evidence_recorded_at<=$6 AND o.key=$7 AND o.source_revision=$8 AND o.quality='valid' AND o.kind='integer' ORDER BY o.observed_at,o.id LIMIT 1001`, v.ID, v.CustomerID, v.EnvironmentID, v.ClusterID, from, to, key, v.Revision)
	if e != nil {
		return out, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var sample alerts.Sample
		if rows.Scan(&sample.ID, &sample.RunID, &sample.At, &sample.Value, &sample.Unit, &sample.Collector, &sample.Transport, &sample.TTLSeconds, &sample.Gap) != nil {
			return out, ErrUnavailable
		}
		sample.Key = key
		if len(out.Samples) > 0 {
			prev := out.Samples[len(out.Samples)-1]
			sample.Gap = sample.Gap || !sample.At.Before(prev.At.Add(time.Duration(prev.TTLSeconds)*time.Second))
		}
		out.Samples = append(out.Samples, sample)
	}
	if rows.Err() != nil {
		return out, ErrUnavailable
	}
	if len(out.Samples) > 1000 {
		return alerts.Series{}, health.ErrEvidence
	}
	return out, nil
}
