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
	return &r, nil
}
