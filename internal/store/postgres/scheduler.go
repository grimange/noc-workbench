package postgres

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

func scheduleAccess(p workspace.Principal) error {
	_, e := (workspace.LocalOperatorPolicy{}).Scope(p, workspace.ScheduleManage)
	return e
}

const scheduleColumns = `s.id::text,s.customer_id::text,s.environment_id::text,s.asset_id::text,s.endpoint_id::text,s.profile_id::text,s.profile_revision,s.principal_id::text,s.revision,s.collector_ids,s.interval_seconds,s.budget_seconds,s.enabled,s.authorized,s.paused,s.next_due,s.last_dispatch,s.admitted_at,s.completed_at,s.retry_count,s.state,s.category,s.lag_seconds,s.skipped`

func scanSchedule(row pgx.Row) (p scheduler.Profile, e error) {
	var last, admitted, completed *time.Time
	e = row.Scan(&p.ID, &p.CustomerID, &p.EnvironmentID, &p.AssetID, &p.Target.EndpointID, &p.Target.ProfileID, &p.Target.ProfileVersion, &p.PrincipalID, &p.Revision, &p.Collectors, &p.Interval, &p.Budget, &p.Enabled, &p.Authorized, &p.Paused, &p.NextDue, &last, &admitted, &completed, &p.RetryCount, &p.State, &p.Category, &p.LagSeconds, &p.Skipped)
	p.Target.AssetID = p.AssetID
	if last != nil {
		p.LastDispatch = *last
	}
	if admitted != nil {
		p.AdmittedAt = *admitted
	}
	if completed != nil {
		p.CompletedAt = *completed
	}
	return
}

// Snapshot queries are bounded by the database-enforced 1000-profile limit.
// Pauses consider every cluster membership, not only the fairness bucket.
func (s *Store) Schedules(ctx context.Context, actor workspace.Principal) (scheduler.Snapshot, error) {
	var out scheduler.Snapshot
	if e := scheduleAccess(actor); e != nil {
		return out, e
	}
	if s.pool.QueryRow(ctx, `SELECT paused,stopped FROM scheduler_control WHERE id`).Scan(&out.Paused, &out.Stopped) != nil {
		return out, ErrUnavailable
	}
	rows, e := s.pool.Query(ctx, `SELECT `+scheduleColumns+`,coalesce((SELECT min(m.cluster_id::text) FROM cluster_membership m WHERE m.asset_id=s.asset_id),''),
 (s.paused OR EXISTS(SELECT 1 FROM schedule_pause p WHERE p.customer_id=s.customer_id OR p.asset_id=s.asset_id OR p.cluster_id IN(SELECT cluster_id FROM cluster_membership WHERE asset_id=s.asset_id))),
 (c.status='active' AND e.status='active' AND a.lifecycle='active' AND ep.status='active' AND cp.state='connection_verified' AND cp.revision=s.profile_revision AND ep.updated_at=s.endpoint_revision AND (NOT EXISTS(SELECT 1 FROM unnest(s.collector_ids) cid WHERE cid LIKE 'asterisk.%') OR EXISTS(SELECT 1 FROM collection_integration i WHERE i.profile_id=s.profile_id AND i.integration='asterisk' AND i.enabled AND i.profile_revision=s.profile_revision)) AND (NOT ('linux.baseline'=ANY(s.collector_ids)) OR EXISTS(SELECT 1 FROM collection_integration i WHERE i.profile_id=s.profile_id AND i.integration='baseline' AND i.enabled AND i.profile_revision=s.profile_revision)) AND (NOT ('linux.services'=ANY(s.collector_ids)) OR EXISTS(SELECT 1 FROM collection_integration i WHERE i.profile_id=s.profile_id AND i.integration='runtime_services' AND i.enabled AND i.profile_revision=s.profile_revision)) AND NOT EXISTS(SELECT 1 FROM ssh_execution_guard WHERE profile_id=s.profile_id) AND NOT EXISTS(SELECT 1 FROM cluster_membership m JOIN cluster cl ON cl.id=m.cluster_id WHERE m.asset_id=s.asset_id AND cl.lifecycle<>'active'))
 ,ARRAY(SELECT cluster_id::text FROM cluster_membership WHERE asset_id=s.asset_id ORDER BY cluster_id LIMIT 1001) FROM collection_schedule s JOIN customer c ON c.id=s.customer_id JOIN environment e ON e.id=s.environment_id JOIN asset a ON a.id=s.asset_id JOIN asset_endpoint ep ON ep.id=s.endpoint_id JOIN connection_profile cp ON cp.id=s.profile_id ORDER BY s.customer_id,s.asset_id LIMIT 1001`)
	if e != nil {
		return out, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() { // scanSchedule also serves fixed-column repository reads.
		var p scheduler.Profile
		var last, admit, complete *time.Time
		var ownPaused, paused bool
		if rows.Scan(&p.ID, &p.CustomerID, &p.EnvironmentID, &p.AssetID, &p.Target.EndpointID, &p.Target.ProfileID, &p.Target.ProfileVersion, &p.PrincipalID, &p.Revision, &p.Collectors, &p.Interval, &p.Budget, &p.Enabled, &p.Authorized, &ownPaused, &p.NextDue, &last, &admit, &complete, &p.RetryCount, &p.State, &p.Category, &p.LagSeconds, &p.Skipped, &p.ClusterID, &paused, &p.Eligible, &p.Clusters) != nil {
			return out, ErrUnavailable
		}
		if len(p.Clusters) > 1000 {
			p.Eligible = false
			p.Category = "cluster_limit"
		}
		p.Paused = paused
		p.Target.AssetID = p.AssetID
		if last != nil {
			p.LastDispatch = *last
		}
		if admit != nil {
			p.AdmittedAt = *admit
		}
		if complete != nil {
			p.CompletedAt = *complete
		}
		out.Profiles = append(out.Profiles, p)
	}
	rows.Close()
	if rows.Err() != nil || len(out.Profiles) > scheduler.ProfileLimit {
		return scheduler.Snapshot{}, ErrUnavailable
	}
	if e := s.appendSourceSchedules(ctx, &out); e != nil {
		return out, e
	}
	pr, e := s.pool.Query(ctx, `SELECT kind,coalesce(customer_id,cluster_id,asset_id)::text FROM schedule_pause ORDER BY kind,coalesce(customer_id,cluster_id,asset_id) LIMIT 3001`)
	if e != nil {
		return out, ErrUnavailable
	}
	defer pr.Close()
	for pr.Next() {
		var c scheduler.Control
		c.Paused = true
		if pr.Scan(&c.Kind, &c.ID) != nil {
			return out, ErrUnavailable
		}
		out.Controls = append(out.Controls, c)
	}
	if pr.Err() != nil || len(out.Controls) > 3000 {
		return scheduler.Snapshot{}, ErrUnavailable
	}
	return out, nil
}
func (s *Store) SaveSchedule(ctx context.Context, actor workspace.Principal, p scheduler.Profile) (scheduler.Profile, error) {
	if e := scheduleAccess(actor); e != nil {
		return p, e
	}
	if p.CollectionSource.ID != "" {
		return s.saveSourceSchedule(ctx, actor, p)
	}
	if scheduler.Validate(p) != nil || !inventory.ValidID(p.CustomerID) || !inventory.ValidID(p.EnvironmentID) || !inventory.ValidID(p.AssetID) {
		return p, scheduler.ErrInvalid
	}
	// Withdrawal and pause must remain available after trust/owner invalidation.
	if p.ID != "" && (!p.Enabled || p.Paused) {
		out, e := scanSchedule(s.pool.QueryRow(ctx, `UPDATE collection_schedule s SET enabled=$1,authorized=$2,paused=$3,revision=revision+1,retry_count=0,state=CASE WHEN $1 THEN 'paused' ELSE 'disabled' END WHERE id=$4 AND revision=$5 AND customer_id=$6 AND environment_id=$7 AND asset_id=$8 RETURNING `+scheduleColumns, p.Enabled, p.Authorized, p.Paused, p.ID, p.Revision, p.CustomerID, p.EnvironmentID, p.AssetID))
		if e != nil {
			return p, scheduler.ErrInvalid
		}
		return out, nil
	}
	if p.Enabled && p.Authorized {
		if e := s.integrationCapabilities(ctx, actor, p.Target, p.Collectors); e != nil {
			return p, e
		}
		if e := collectorsAllowed(ctx, s.pool, actor, p.Target, p.Collectors); e != nil {
			return p, e
		}
	}
	rec, e := s.Enrollment(ctx, p.Target.EndpointID, p.Target.ProfileID)
	if e != nil || rec.CustomerID != p.CustomerID || rec.EnvironmentID != p.EnvironmentID || rec.AssetID != p.AssetID || rec.Target() != p.Target {
		return p, scheduler.ErrInvalid
	}
	if p.Enabled && (rec.State != "connection_verified") {
		return p, scheduler.ErrInvalid
	}
	p.PrincipalID = actor.ID
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return p, ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	if e = lockEnrollmentOwners(ctx, tx, rec); e != nil {
		return p, e
	}
	// The approval revision is captured, so editing an endpoint never silently
	// redirects an existing schedule. Re-enabling requires explicit operator intent.
	if p.ID == "" {
		p, e = scanSchedule(tx.QueryRow(ctx, `INSERT INTO collection_schedule AS s(customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,endpoint_revision,principal_id,collector_ids,interval_seconds,budget_seconds,enabled,authorized,paused,next_due) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,clock_timestamp()+interval '1 day' FROM connection_profile WHERE id=$5 AND revision=$6 RETURNING `+scheduleColumns, p.CustomerID, p.EnvironmentID, p.AssetID, p.Target.EndpointID, p.Target.ProfileID, p.Target.ProfileVersion, rec.Details.EndpointUpdatedAt, actor.ID, p.Collectors, p.Interval, p.Budget, p.Enabled, p.Authorized, p.Paused))
	} else {
		p, e = scanSchedule(tx.QueryRow(ctx, `UPDATE collection_schedule s SET endpoint_id=$1,profile_id=$2,profile_revision=$3,endpoint_revision=$4,principal_id=$5,collector_ids=$6,interval_seconds=$7,budget_seconds=$8,enabled=$9,authorized=$10,paused=$11,revision=revision+1,retry_count=0,state='idle',category='' WHERE id=$12 AND customer_id=$13 AND environment_id=$14 AND asset_id=$15 AND revision=$16 RETURNING `+scheduleColumns, p.Target.EndpointID, p.Target.ProfileID, p.Target.ProfileVersion, rec.Details.EndpointUpdatedAt, actor.ID, p.Collectors, p.Interval, p.Budget, p.Enabled, p.Authorized, p.Paused, p.ID, p.CustomerID, p.EnvironmentID, p.AssetID, p.Revision))
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
	return p, nil
}
func (s *Store) SetScheduleControl(ctx context.Context, actor workspace.Principal, c scheduler.Control, now time.Time) error {
	if e := scheduleAccess(actor); e != nil {
		return e
	}
	if c.Kind != "global" && c.Kind != "customer" && c.Kind != "cluster" && c.Kind != "asset" {
		return scheduler.ErrInvalid
	}
	if c.Kind != "global" && (!inventory.ValidID(c.ID) || c.Stopped) {
		return scheduler.ErrInvalid
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	// Same singleton lock order as collection admission. Stop is committed before
	// cancellation, and admission cannot pass this gate after the commit.
	if _, e = tx.Exec(ctx, `SELECT id FROM scheduler_control WHERE id FOR UPDATE`); e != nil {
		return ErrUnavailable
	}
	if c.Kind == "global" {
		if c.Action != "pause" && c.Action != "resume" && c.Action != "stop" && c.Action != "release" {
			return scheduler.ErrInvalid
		}
		_, e = tx.Exec(ctx, `UPDATE scheduler_control SET paused=CASE WHEN $1 IN ('pause','resume') THEN $1='pause' ELSE paused END,stopped=CASE WHEN $1 IN ('stop','release') THEN $1='stop' ELSE stopped END,revision=revision+1 WHERE id`, c.Action)
	} else {
		column := map[string]string{"customer": "customer_id", "cluster": "cluster_id", "asset": "asset_id"}[c.Kind]
		if c.Paused {
			var count int
			if tx.QueryRow(ctx, `SELECT count(*) FROM schedule_pause`).Scan(&count) != nil || count >= 3000 {
				return scheduler.ErrInvalid
			}
			_, e = tx.Exec(ctx, `INSERT INTO schedule_pause(kind,`+column+`) VALUES($1,$2) ON CONFLICT DO NOTHING`, c.Kind, c.ID)
		} else {
			_, e = tx.Exec(ctx, `DELETE FROM schedule_pause WHERE kind=$1 AND `+column+`=$2`, c.Kind, c.ID)
		}
	}
	if e != nil {
		return scheduler.ErrInvalid
	}
	// Coalesce missed work on both pause and resume. Applicable jobs are never
	// replayed; a resumed fleet is spread over one interval using stable hashing.
	_, e = tx.Exec(ctx, `UPDATE collection_schedule SET next_due=$1::timestamptz+interval '1 second'*(1+mod(abs(hashtextextended(id::text,revision)::numeric),interval_seconds-1)),retry_count=0,state=CASE WHEN $2 THEN 'paused' ELSE 'idle' END WHERE $3='global' OR ($3='customer' AND customer_id::text=$4) OR ($3='asset' AND asset_id::text=$4) OR ($3='cluster' AND (cluster_id::text=$4 OR asset_id IN(SELECT asset_id FROM cluster_membership WHERE cluster_id::text=$4)))`, now, c.Paused || c.Stopped || c.Action == "pause" || c.Action == "stop", c.Kind, c.ID)
	if e != nil || tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) RecoverSchedules(ctx context.Context, now time.Time) error {
	_, e := s.pool.Exec(ctx, `UPDATE collection_schedule SET next_due=$1::timestamptz+interval '1 second'*(1+mod(abs(hashtextextended(id::text,revision)::numeric),interval_seconds-1)),retry_count=0,state='recovered',skipped=skipped+1 WHERE enabled AND (next_due<=$1 OR state IN ('running','queued'))`, now)
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) ScheduleDecision(ctx context.Context, p scheduler.Profile, state string, now time.Time) error {
	if state != "queued" && state != "delayed" {
		return scheduler.ErrInvalid
	}
	tag, e := s.pool.Exec(ctx, `UPDATE collection_schedule SET state=$1,admitted_at=CASE WHEN $1='queued' THEN $2 ELSE admitted_at END,lag_seconds=greatest(0,extract(epoch FROM $2-next_due)),skipped=skipped+CASE WHEN $1='delayed' AND state<>'delayed' THEN 1 ELSE 0 END WHERE id=$3 AND revision=$4 AND state<>'running' AND next_due<=$2 AND enabled AND authorized AND NOT paused AND NOT EXISTS(SELECT 1 FROM scheduler_control WHERE paused OR stopped) AND NOT EXISTS(SELECT 1 FROM schedule_pause p WHERE p.customer_id=collection_schedule.customer_id OR p.asset_id=collection_schedule.asset_id OR p.cluster_id=collection_schedule.cluster_id OR p.cluster_id IN(SELECT cluster_id FROM cluster_membership WHERE asset_id=collection_schedule.asset_id))`, state, now, p.ID, p.Revision)
	if e != nil {
		return ErrUnavailable
	}
	if tag.RowsAffected() != 1 {
		return scheduler.ErrInvalid
	}
	return nil
}
func (s *Store) CompleteSchedule(ctx context.Context, p scheduler.Profile, r collection.Run, runErr error, now time.Time) error {
	state, category := r.State, r.Category
	noAttempt := r.ID == ""
	disable := false
	if noAttempt {
		state = "blocked"
		category = "authority_unavailable"
		disable = true
	}
	if errors.Is(runErr, collection.ErrBusy) {
		state = "delayed"
		category = "shared_capacity"
		disable = false
	}
	if noAttempt && (errors.Is(runErr, context.DeadlineExceeded) || errors.Is(runErr, context.Canceled)) {
		state = "delayed"
		category = "admission_timeout"
		disable = false
		if errors.Is(runErr, context.Canceled) {
			category = "admission_cancelled"
		}
	}
	if !noAttempt && runErr != nil {
		state = "failed"
		category = "collection_persistence_failure"
		disable = true
	}
	switch category {
	case "host_key_mismatch", "unknown_host_key", "permission_denied", "authentication_failed", "stale_profile", "credential_unavailable":
		disable = true
	}
	if state == "interrupted" || state == "" {
		state = "failed"
	}
	retry := runErr == nil && p.RetryCount == 0 && scheduler.Retryable(r)
	due := scheduler.Next(p, now)
	if retry || (noAttempt && !disable) {
		due = now.Add(5*time.Second + scheduler.Jitter(p.ID, p.Revision, 2*time.Second))
	}
	// Pause/resume updates row state under the global control lock. Completion
	// never rewrites that state or its coalesced due time. Actual collection
	// evidence is already independently committed by NW-010.
	_, e := s.pool.Exec(ctx, `UPDATE collection_schedule SET completed_at=$1,
 state=CASE WHEN state IN ('running','queued') THEN $2 ELSE state END,
 category=CASE WHEN state IN ('running','queued') THEN $3 ELSE category END,
 next_due=CASE WHEN state IN ('running','queued') AND ($4 OR $9) THEN $5 ELSE next_due END,
 retry_count=CASE WHEN state IN ('running','queued') AND $4 THEN 1 ELSE 0 END,
 enabled=CASE WHEN state IN ('running','queued') AND $10 THEN false ELSE enabled END
 WHERE id=$6 AND revision=$7 AND (last_dispatch=$8 OR ($9 AND state='queued'))`, now, state, category, retry, due, p.ID, p.Revision, r.StartedAt, noAttempt, disable)
	if e != nil {
		return ErrUnavailable
	}
	return nil
}

// Final scheduled admission occurs in the same transaction as the durable run.
func validateScheduleAdmission(ctx context.Context, tx pgx.Tx, rec connections.Record, req collection.Request) (scheduler.Profile, error) {
	p, e := scanSchedule(tx.QueryRow(ctx, `SELECT `+scheduleColumns+` FROM collection_schedule s WHERE s.id=$1 AND s.revision=$2 AND s.enabled AND s.authorized AND NOT s.paused AND s.next_due<=clock_timestamp() AND s.endpoint_revision=(SELECT updated_at FROM asset_endpoint WHERE id=s.endpoint_id) AND NOT EXISTS(SELECT 1 FROM schedule_pause p WHERE p.customer_id=s.customer_id OR p.asset_id=s.asset_id OR p.cluster_id IN(SELECT cluster_id FROM cluster_membership WHERE asset_id=s.asset_id)) AND NOT EXISTS(SELECT 1 FROM cluster_membership m JOIN cluster c ON c.id=m.cluster_id WHERE m.asset_id=s.asset_id AND c.lifecycle<>'active') FOR UPDATE`, req.ScheduleID, req.Revision))
	if e != nil || p.PrincipalID != workspace.OperatorID || p.Target != rec.Target() || !reflect.DeepEqual(p.Collectors, req.Collectors) || time.Duration(p.Budget)*time.Second != req.Budget {
		return p, scheduler.ErrInvalid
	}
	return p, nil
}

// Scope is loaded from inventory, never accepted from HTTP or a scheduling hint.
// Authority is revalidated transactionally again when the durable attempt begins.
func (s *Store) CollectionAdmissionScope(ctx context.Context, actor workspace.Principal, t sshcli.Target) (collection.AdmissionScope, error) {
	var out collection.AdmissionScope
	if actor.ID != workspace.OperatorID {
		return out, workspace.ErrDenied
	}
	err := s.pool.QueryRow(ctx, `SELECT customer_id::text,ARRAY(SELECT cluster_id::text FROM cluster_membership WHERE asset_id=p.asset_id ORDER BY cluster_id LIMIT 1001) FROM connection_profile p WHERE id=$1 AND asset_id=$2 AND endpoint_id=$3 AND revision=$4`, t.ProfileID, t.AssetID, t.EndpointID, t.ProfileVersion).Scan(&out.Customer, &out.Clusters)
	if err != nil || len(out.Clusters) > 1000 {
		return out, ErrUnavailable
	}
	return out, nil
}
