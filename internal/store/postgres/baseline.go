package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/workspace"
)

// Baseline authorization and the first schedule are committed with enrollment
// verification. Maintenance controls and existing history are untouched.
func authorizeBaseline(ctx context.Context, tx pgx.Tx, p workspace.Principal, r connections.Record) error {
	if p.ID != workspace.OperatorID || r.State != "connection_verified" || !r.Details.BaselineAuthorized {
		return workspace.ErrDenied
	}
	names := []string{"baseline", "runtime_services"}
	if r.Details.StandardMonitoring {
		names = append(names, "asterisk", "vicidial_discovery")
	}
	for _, name := range names {
		e := grantMonitoring(ctx, tx, p, r, name, true)
		if e != nil {
			return e
		}
	}
	_, e := tx.Exec(ctx, `INSERT INTO collection_schedule(customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,endpoint_revision,principal_id,collector_ids,interval_seconds,budget_seconds,enabled,authorized,next_due)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,ARRAY['linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems','linux.services','linux.baseline'],60,20,true,true,clock_timestamp())
 ON CONFLICT(asset_id) DO UPDATE SET endpoint_id=excluded.endpoint_id,profile_id=excluded.profile_id,profile_revision=excluded.profile_revision,endpoint_revision=excluded.endpoint_revision,principal_id=excluded.principal_id,collector_ids=ARRAY(SELECT DISTINCT id FROM unnest(excluded.collector_ids || CASE WHEN collection_schedule.profile_id=excluded.profile_id AND collection_schedule.profile_revision IN (excluded.profile_revision,excluded.profile_revision-1) THEN collection_schedule.collector_ids ELSE ARRAY[]::text[] END) id ORDER BY id),interval_seconds=60,budget_seconds=20,enabled=true,authorized=true,revision=collection_schedule.revision+1,retry_count=0,next_due=clock_timestamp(),state=CASE WHEN collection_schedule.paused THEN 'paused' ELSE 'idle' END,category=''`, r.CustomerID, r.EnvironmentID, r.AssetID, r.EndpointID, r.ID, r.Revision, r.Details.EndpointUpdatedAt, p.ID)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE collection_schedule SET budget_seconds=40 WHERE asset_id=$1 AND source_id IS NULL AND cardinality(collector_ids)>8 AND budget_seconds=20`, r.AssetID)
	return e
}
