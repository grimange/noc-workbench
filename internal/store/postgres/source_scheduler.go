package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/workspace"
	"time"
)

const sourceScheduleColumns = `s.id::text,s.customer_id::text,s.environment_id::text,s.cluster_id::text,s.source_id::text,s.source_revision,s.principal_id::text,s.revision,s.collector_ids,s.interval_seconds,s.budget_seconds,s.enabled,s.authorized,s.paused,s.next_due,s.last_dispatch,s.admitted_at,s.completed_at,s.retry_count,s.state,s.category,s.lag_seconds,s.skipped`

func scanSourceSchedule(row pgx.Row) (p scheduler.Profile, e error) {
	var last, admit, complete *time.Time
	e = row.Scan(&p.ID, &p.CustomerID, &p.EnvironmentID, &p.ClusterID, &p.CollectionSource.ID, &p.CollectionSource.Revision, &p.PrincipalID, &p.Revision, &p.Collectors, &p.Interval, &p.Budget, &p.Enabled, &p.Authorized, &p.Paused, &p.NextDue, &last, &admit, &complete, &p.RetryCount, &p.State, &p.Category, &p.LagSeconds, &p.Skipped)
	p.CollectionSource.CustomerID = p.CustomerID
	p.CollectionSource.EnvironmentID = p.EnvironmentID
	p.CollectionSource.ClusterID = p.ClusterID
	p.Clusters = []string{p.ClusterID}
	if last != nil {
		p.LastDispatch = *last
	}
	if admit != nil {
		p.AdmittedAt = *admit
	}
	if complete != nil {
		p.CompletedAt = *complete
	}
	return
}
func (s *Store) appendSourceSchedules(ctx context.Context, out *scheduler.Snapshot) error {
	rows, e := s.pool.Query(ctx, `SELECT `+sourceScheduleColumns+` FROM collection_schedule s WHERE s.source_id IS NOT NULL ORDER BY customer_id,cluster_id LIMIT 1001`)
	if e != nil {
		return ErrUnavailable
	}
	var profiles []scheduler.Profile
	for rows.Next() {
		p, e := scanSourceSchedule(rows)
		if e != nil {
			rows.Close()
			return ErrUnavailable
		}
		profiles = append(profiles, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(profiles)+len(out.Profiles) > scheduler.ProfileLimit {
		return ErrUnavailable
	}
	for _, p := range profiles {
		v, e := s.CollectionSource(ctx, workspace.Principal{ID: workspace.OperatorID}, p.CollectionSource.ID, p.CollectionSource.Revision)
		p.Eligible = e == nil
		if e == nil {
			p.CollectionSource = v
		}
		var paused bool
		if s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schedule_pause WHERE customer_id=$1 OR cluster_id=$2)`, p.CustomerID, p.ClusterID).Scan(&paused) != nil {
			return ErrUnavailable
		}
		p.Paused = p.Paused || paused
		out.Profiles = append(out.Profiles, p)
	}
	return nil
}
func (s *Store) saveSourceSchedule(ctx context.Context, actor workspace.Principal, p scheduler.Profile) (scheduler.Profile, error) {
	v := p.CollectionSource
	if scheduler.Validate(p) != nil || sourceAccess(actor, v) != nil || p.CustomerID != v.CustomerID || p.EnvironmentID != v.EnvironmentID || p.ClusterID != v.ClusterID || !inventory.ValidID(v.ID) {
		return p, scheduler.ErrInvalid
	}
	if p.Enabled && !p.Paused {
		current, e := s.CollectionSource(ctx, actor, v.ID, v.Revision)
		if e != nil {
			return p, e
		}
		v = current
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return p, ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	// The same owner lock serializes source revision changes and schedule opt-in.
	if _, e = tx.Exec(ctx, `SELECT id FROM cluster WHERE id=$1 FOR UPDATE`, v.ClusterID); e != nil {
		return p, ErrUnavailable
	}
	var current int64
	e = tx.QueryRow(ctx, `SELECT max(cs.revision) FROM collection_source cs WHERE cs.id=$1 AND cs.customer_id=$2 AND cs.environment_id=$3 AND cs.cluster_id=$4`, v.ID, v.CustomerID, v.EnvironmentID, v.ClusterID).Scan(&current)
	if e != nil || current != v.Revision {
		return p, scheduler.ErrInvalid
	}
	if p.ID == "" {
		p, e = scanSourceSchedule(tx.QueryRow(ctx, `INSERT INTO collection_schedule AS s(customer_id,environment_id,cluster_id,source_id,source_revision,principal_id,collector_ids,interval_seconds,budget_seconds,enabled,authorized,paused,next_due) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,clock_timestamp()+interval '1 day') RETURNING `+sourceScheduleColumns, v.CustomerID, v.EnvironmentID, v.ClusterID, v.ID, v.Revision, actor.ID, p.Collectors, p.Interval, p.Budget, p.Enabled, p.Authorized, p.Paused))
	} else {
		p, e = scanSourceSchedule(tx.QueryRow(ctx, `UPDATE collection_schedule s SET source_revision=$1,principal_id=$2,collector_ids=$3,interval_seconds=$4,budget_seconds=$5,enabled=$6,authorized=$7,paused=$8,revision=revision+1,retry_count=0,state=CASE WHEN NOT $6 THEN 'disabled' WHEN $8 THEN 'paused' ELSE 'idle' END,category='' WHERE id=$9 AND source_id=$10 AND revision=$11 AND customer_id=$12 AND environment_id=$13 AND cluster_id=$14 RETURNING `+sourceScheduleColumns, v.Revision, actor.ID, p.Collectors, p.Interval, p.Budget, p.Enabled, p.Authorized, p.Paused, p.ID, v.ID, p.Revision, v.CustomerID, v.EnvironmentID, v.ClusterID))
	}
	if e != nil {
		return p, scheduler.ErrInvalid
	}
	p.NextDue = scheduler.Initial(p, time.Now().UTC())
	if _, e = tx.Exec(ctx, `UPDATE collection_schedule SET next_due=$1 WHERE id=$2`, p.NextDue, p.ID); e != nil {
		return p, ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return p, ErrUnavailable
	}
	p.CollectionSource = v
	return p, nil
}

// Keep compile-time linkage to the neutral source model explicit.
var _ collection.SourceHistoryRepository = (*Store)(nil)
