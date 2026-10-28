package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/workspace"
)

// RuntimeAttempt excludes unrelated collections, including passive installation
// refreshes. Runs without committed observations remain visible as attempts.
func (s *Store) RuntimeAttempt(ctx context.Context, p workspace.Principal, h collection.HistoryScope) (*collection.Run, error) {
	if e := collectionAccess(p, h); e != nil {
		return nil, e
	}
	r, e := scanRun(s.pool.QueryRow(ctx, `SELECT `+runColumns+` FROM collection_run WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 AND 'linux.services'=ANY(collector_ids) ORDER BY started_at DESC,id DESC LIMIT 1`, h.CustomerID, h.EnvironmentID, h.AssetID))
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	var outcome, transport string
	e = s.pool.QueryRow(ctx, `SELECT outcome,transport_outcome FROM collector_result WHERE run_id=$1 AND collector_id='linux.services'`, r.ID).Scan(&outcome, &transport)
	if e == nil {
		r.Results = []collection.Result{{CollectorID: "linux.services", Outcome: outcome, TransportOutcome: transport}}
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return nil, ErrUnavailable
	}
	return &r, nil
}

// RuntimeSuccess excludes unrelated collectors and retains the original end time.
func (s *Store) RuntimeSuccess(ctx context.Context, p workspace.Principal, h collection.HistoryScope) (*collection.Run, error) {
	if e := collectionAccess(p, h); e != nil {
		return nil, e
	}
	r, e := scanRun(s.pool.QueryRow(ctx, `SELECT `+runColumns+` FROM collection_run r WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 AND evidence_recorded_at IS NOT NULL AND EXISTS(SELECT 1 FROM collector_result cr WHERE cr.run_id=r.id AND cr.collector_id='linux.services' AND cr.outcome='success') ORDER BY started_at DESC,id DESC LIMIT 1`, h.CustomerID, h.EnvironmentID, h.AssetID))
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	return &r, nil
}
