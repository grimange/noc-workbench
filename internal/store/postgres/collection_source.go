package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/workspace"
)

const sourceColumns = `id::text,customer_id::text,environment_id::text,cluster_id::text,credential_reference,revision,enabled`

func scanSource(row pgx.Row) (v collection.Source, e error) {
	e = row.Scan(&v.ID, &v.CustomerID, &v.EnvironmentID, &v.ClusterID, &v.CredentialReference, &v.Revision, &v.Enabled)
	return v, topologyError(e)
}
func sourceAccess(p workspace.Principal, v collection.Source) error {
	scope, e := (workspace.LocalOperatorPolicy{}).Scope(p, workspace.ScheduleManage)
	if e != nil || !scope.Allows(v.CustomerID, v.EnvironmentID) || !inventory.ValidID(v.CustomerID) || !inventory.ValidID(v.EnvironmentID) || !inventory.ValidID(v.ClusterID) {
		return workspace.ErrDenied
	}
	return nil
}

// SourceConfiguration is a passive lookup. It cannot authorize a connection.
func (s *Store) SourceConfiguration(ctx context.Context, p workspace.Principal, v collection.Source) (collection.Source, error) {
	if e := sourceAccess(p, v); e != nil {
		return v, e
	}
	return scanSource(s.pool.QueryRow(ctx, `SELECT `+sourceColumns+` FROM collection_source WHERE customer_id=$1 AND environment_id=$2 AND cluster_id=$3 AND adapter_id='vicidial.api' ORDER BY revision DESC LIMIT 1`, v.CustomerID, v.EnvironmentID, v.ClusterID))
}
func (s *Store) SaveSourceConfiguration(ctx context.Context, p workspace.Principal, v collection.Source) (collection.Source, error) {
	if e := sourceAccess(p, v); e != nil {
		return v, e
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return v, ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	var id string
	if e = tx.QueryRow(ctx, `SELECT cl.id::text FROM customer c JOIN environment en ON en.customer_id=c.id JOIN cluster cl ON cl.environment_id=en.id WHERE c.id=$1 AND en.id=$2 AND cl.id=$3 FOR SHARE OF c,en FOR UPDATE OF cl`, v.CustomerID, v.EnvironmentID, v.ClusterID).Scan(&id); e != nil {
		return v, topologyError(e)
	}
	var enabled bool
	if e = tx.QueryRow(ctx, `SELECT enabled FROM vicidial_integration WHERE cluster_id=$1 ORDER BY revision DESC LIMIT 1`, v.ClusterID).Scan(&enabled); e != nil || (v.Enabled && !enabled) {
		return v, workspace.ErrDenied
	}
	old, e := scanSource(tx.QueryRow(ctx, `SELECT `+sourceColumns+` FROM collection_source WHERE cluster_id=$1 AND adapter_id='vicidial.api' ORDER BY revision DESC LIMIT 1`, v.ClusterID))
	if e != nil && !errors.Is(e, inventory.ErrNotFound) {
		return v, e
	}
	if v.Revision != old.Revision || (v.ID != "" && v.ID != old.ID) {
		return v, inventory.FieldErrors{"revision": "Configuration changed; reload before saving."}
	}
	var identity any
	if old.ID != "" {
		identity = old.ID
	}
	v, e = scanSource(tx.QueryRow(ctx, `INSERT INTO collection_source(id,revision,customer_id,environment_id,cluster_id,adapter_id,credential_reference,enabled,actor) VALUES(coalesce($1::uuid,gen_random_uuid()),$2,$3,$4,$5,'vicidial.api',$6,$7,$8) RETURNING `+sourceColumns, identity, old.Revision+1, v.CustomerID, v.EnvironmentID, v.ClusterID, v.CredentialReference, v.Enabled, p.ID))
	if e != nil {
		return v, e
	}
	// Any configuration change withdraws old continuous-polling authority.
	if _, e = tx.Exec(ctx, `UPDATE collection_schedule SET enabled=false,authorized=false,revision=revision+1,state='disabled' WHERE source_id=$1`, v.ID); e != nil {
		return v, ErrUnavailable
	}
	if e = tx.Commit(ctx); e != nil {
		return v, ErrUnavailable
	}
	return v, nil
}
func (s *Store) CollectionSource(ctx context.Context, p workspace.Principal, id string, revision int64) (collection.Source, error) {
	if !inventory.ValidID(id) || revision < 1 {
		return collection.Source{}, workspace.ErrDenied
	}
	v, e := scanSource(s.pool.QueryRow(ctx, `SELECT `+sourceColumns+` FROM collection_source WHERE id=$1 ORDER BY revision DESC LIMIT 1`, id))
	if e != nil || v.Revision != revision || !v.Enabled || sourceAccess(p, v) != nil {
		return v, workspace.ErrDenied
	}
	var eligible bool
	e = s.pool.QueryRow(ctx, `SELECT c.status='active' AND en.status='active' AND cl.lifecycle='active' AND NOT sc.stopped AND (SELECT enabled FROM vicidial_integration WHERE cluster_id=cl.id ORDER BY revision DESC LIMIT 1) FROM customer c JOIN environment en ON en.customer_id=c.id JOIN cluster cl ON cl.environment_id=en.id CROSS JOIN scheduler_control sc WHERE c.id=$1 AND en.id=$2 AND cl.id=$3`, v.CustomerID, v.EnvironmentID, v.ClusterID).Scan(&eligible)
	if e != nil || !eligible {
		return v, workspace.ErrDenied
	}
	req := collection.Requested(ctx)
	if req.Source == "scheduled" {
		var allowed bool
		e = s.pool.QueryRow(ctx, `SELECT s.enabled AND s.authorized AND NOT s.paused AND s.revision=$1 AND s.source_revision=$2 AND NOT ctrl.paused AND NOT ctrl.stopped AND NOT EXISTS(SELECT 1 FROM schedule_pause p WHERE p.customer_id=s.customer_id OR p.cluster_id=s.cluster_id) FROM collection_schedule s CROSS JOIN scheduler_control ctrl WHERE s.id=$3 AND s.source_id=$4`, req.Revision, revision, req.ScheduleID, id).Scan(&allowed)
		if e != nil || !allowed {
			return v, workspace.ErrDenied
		}
	}
	return v, nil
}

const sourceRunColumns = `id::text,source_id::text,source_revision,customer_id::text,environment_id::text,cluster_id::text,principal_id::text,started_at,ended_at,state,category,success_count,failure_count,request_source,coalesce(schedule_id::text,''),coalesce(schedule_revision,0)`

func scanSourceRun(row pgx.Row) (r collection.Run, e error) {
	var end *time.Time
	e = row.Scan(&r.ID, &r.CollectionSource.ID, &r.CollectionSource.Revision, &r.CollectionSource.CustomerID, &r.CollectionSource.EnvironmentID, &r.CollectionSource.ClusterID, &r.PrincipalID, &r.StartedAt, &end, &r.State, &r.Category, &r.SuccessCount, &r.FailureCount, &r.Source, &r.ScheduleID, &r.ScheduleRevision)
	if end != nil {
		r.EndedAt = *end
	}
	return
}
func (s *Store) BeginSourceCollection(ctx context.Context, p workspace.Principal, v collection.Source, ids []string) (collection.Run, error) {
	current, e := s.CollectionSource(ctx, p, v.ID, v.Revision)
	if e != nil || current != v {
		return collection.Run{}, workspace.ErrDenied
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return collection.Run{}, ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	var paused, stopped bool
	if e = tx.QueryRow(ctx, `SELECT paused,stopped FROM scheduler_control WHERE id FOR SHARE`).Scan(&paused, &stopped); e != nil || stopped {
		return collection.Run{}, workspace.ErrDenied
	}
	// Lock the same hierarchy used by configuration/lifecycle mutations and
	// recheck the latest immutable revision inside the durable admission transaction.
	var authorized bool
	e = tx.QueryRow(ctx, `SELECT c.status='active' AND en.status='active' AND cl.lifecycle='active' FROM customer c JOIN environment en ON en.customer_id=c.id JOIN cluster cl ON cl.environment_id=en.id WHERE c.id=$1 AND en.id=$2 AND cl.id=$3 FOR SHARE OF c,en FOR UPDATE OF cl`, v.CustomerID, v.EnvironmentID, v.ClusterID).Scan(&authorized)
	if e != nil || !authorized {
		return collection.Run{}, workspace.ErrDenied
	}
	var latest int64
	if tx.QueryRow(ctx, `SELECT max(revision) FROM collection_source WHERE id=$1`, v.ID).Scan(&latest) != nil || latest != v.Revision {
		return collection.Run{}, workspace.ErrDenied
	}
	if tx.QueryRow(ctx, `SELECT enabled FROM vicidial_integration WHERE cluster_id=$1 ORDER BY revision DESC LIMIT 1`, v.ClusterID).Scan(&authorized) != nil || !authorized {
		return collection.Run{}, workspace.ErrDenied
	}
	var sid, srev any
	req := collection.Requested(ctx)
	if req.Source == "scheduled" {
		if paused {
			return collection.Run{}, workspace.ErrDenied
		}
		var enabled bool
		e = tx.QueryRow(ctx, `SELECT enabled AND authorized AND NOT paused AND source_revision=$1 AND revision=$2 AND collector_ids=$3::text[] AND next_due<=clock_timestamp() AND NOT EXISTS(SELECT 1 FROM schedule_pause WHERE customer_id=$4 OR cluster_id=$5) FROM collection_schedule WHERE id=$6 AND source_id=$7 FOR UPDATE`, v.Revision, req.Revision, ids, v.CustomerID, v.ClusterID, req.ScheduleID, v.ID).Scan(&enabled)
		if e != nil || !enabled {
			return collection.Run{}, workspace.ErrDenied
		}
		sid = req.ScheduleID
		srev = req.Revision
	} else if req.Source != "operator" {
		return collection.Run{}, workspace.ErrDenied
	}
	r, e := scanSourceRun(tx.QueryRow(ctx, `INSERT INTO collection_run(source_id,source_revision,customer_id,environment_id,cluster_id,principal_id,request_source,schedule_id,schedule_revision,collector_ids) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+sourceRunColumns, v.ID, v.Revision, v.CustomerID, v.EnvironmentID, v.ClusterID, p.ID, req.Source, sid, srev, ids))
	if e != nil {
		return r, ErrUnavailable
	}
	if req.Source == "scheduled" {
		var interval int
		if tx.QueryRow(ctx, `SELECT interval_seconds FROM collection_schedule WHERE id=$1`, sid).Scan(&interval) != nil {
			return r, ErrUnavailable
		}
		next := scheduler.Next(scheduler.Profile{ID: req.ScheduleID, Interval: interval}, r.StartedAt)
		_, e = tx.Exec(ctx, `UPDATE collection_schedule SET state='running',last_dispatch=$1,next_due=$3,lag_seconds=greatest(0,extract(epoch FROM $1-next_due)) WHERE id=$2`, r.StartedAt, sid, next)
	}
	if e != nil || tx.Commit(ctx) != nil {
		return r, ErrUnavailable
	}
	r.CollectionSource = v
	return r, nil
}
func (s *Store) FinishSourceCollection(ctx context.Context, p workspace.Principal, r collection.Run, ttl int) error {
	if p.ID != workspace.OperatorID || r.PrincipalID != p.ID || len(r.Results) < 1 || len(r.Results) > 3 || ttl < 1 || ttl > 86400 {
		return collection.ErrPersistence
	}
	r.Summarize()
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	var ids []string
	if e = tx.QueryRow(ctx, `SELECT collector_ids FROM collection_run WHERE id=$1 AND source_id=$2 AND source_revision=$3 AND principal_id=$4 AND state='running' FOR UPDATE`, r.ID, r.CollectionSource.ID, r.CollectionSource.Revision, p.ID).Scan(&ids); e != nil || len(ids) != len(r.Results) {
		return collection.ErrPersistence
	}
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	for _, c := range r.Results {
		if !seen[c.CollectorID] || len(c.Observations) > 3 || len(c.Diagnostics) > 16 {
			return collection.ErrPersistence
		}
		delete(seen, c.CollectorID)
		ds := []string{}
		for _, d := range c.Diagnostics {
			if !safeDiagnostic.MatchString(d.Code) {
				return collection.ErrPersistence
			}
			ds = append(ds, d.Code)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO collector_result(run_id,collector_id,version,command_id,outcome,transport_outcome,started_at,ended_at,observation_count,diagnostics) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.ID, c.CollectorID, c.Version, c.CommandID, c.Outcome, c.TransportOutcome, c.StartedAt, c.EndedAt, len(c.Observations), ds); e != nil {
			return ErrUnavailable
		}
		for _, o := range c.Observations {
			if o.SourceID != r.CollectionSource.ID || o.SourceRevision != r.CollectionSource.Revision || o.SubjectType != "cluster" || o.CollectorID != c.CollectorID || o.CollectorVersion != c.Version || o.CommandID != c.CommandID || o.AssetID != "" || o.ProfileID != "" || o.EndpointID != "" {
				return collection.ErrPersistence
			}
			var text, integer any
			switch o.Value.Kind {
			case "text":
				text = o.Value.Text
			case "integer":
				integer = strconv.FormatUint(o.Value.Integer, 10)
			default:
				return collection.ErrPersistence
			}
			_, e = tx.Exec(ctx, `INSERT INTO observation(run_id,source_id,source_revision,subject_type,collector_id,collector_version,command_id,key,resource,kind,text_value,integer_value,unit,transport,quality,observed_at,received_at,ttl_seconds) VALUES($1,$2,$3,'cluster',$4,$5,$6,$7,'',$8,$9,$10,$11,$12,$13,$14,$15,$16)`, r.ID, o.SourceID, o.SourceRevision, o.CollectorID, o.CollectorVersion, o.CommandID, o.Key, o.Value.Kind, text, integer, o.Unit, o.Transport, o.Quality, o.ObservedAt, o.ReceivedAt, ttl)
			if e != nil {
				return ErrUnavailable
			}
		}
	}
	tag, e := tx.Exec(ctx, `UPDATE collection_run SET ended_at=$1,state=$2,category=$3,success_count=$4,failure_count=$5 WHERE id=$6 AND state='running'`, r.EndedAt, r.State, r.Category, r.SuccessCount, r.FailureCount, r.ID)
	if e != nil || tag.RowsAffected() != 1 || tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) SourceHistory(ctx context.Context, p workspace.Principal, v collection.Source, at time.Time) (collection.History, error) {
	if e := sourceAccess(p, v); e != nil || !inventory.ValidID(v.ID) {
		return collection.History{}, workspace.ErrDenied
	}
	h := collection.History{}
	rows, e := s.pool.Query(ctx, `SELECT `+sourceRunColumns+` FROM collection_run WHERE source_id=$1 AND customer_id=$2 AND environment_id=$3 AND cluster_id=$4 AND started_at<=$5 ORDER BY started_at DESC,id DESC LIMIT 20`, v.ID, v.CustomerID, v.EnvironmentID, v.ClusterID, at)
	if e != nil {
		return h, ErrUnavailable
	}
	for rows.Next() {
		r, e := scanSourceRun(rows)
		if e != nil {
			rows.Close()
			return h, ErrUnavailable
		}
		if r.EndedAt.After(at) {
			r.State = "running"
			r.Category = ""
			r.SuccessCount = 0
			r.FailureCount = 0
			r.EndedAt = time.Time{}
		}
		h.Runs = append(h.Runs, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return h, ErrUnavailable
	}
	// Read bounded individual results so application failures remain distinct from transport.
	for i := range h.Runs {
		if h.Runs[i].EndedAt.IsZero() || h.Runs[i].EndedAt.After(at) {
			continue
		}
		results, err := s.pool.Query(ctx, `SELECT collector_id,version,command_id,outcome,transport_outcome,started_at,ended_at,observation_count,diagnostics FROM collector_result WHERE run_id=$1 ORDER BY collector_id LIMIT 3`, h.Runs[i].ID)
		if err != nil {
			return h, ErrUnavailable
		}
		for results.Next() {
			var result collection.Result
			var diagnostics []string
			if results.Scan(&result.CollectorID, &result.Version, &result.CommandID, &result.Outcome, &result.TransportOutcome, &result.StartedAt, &result.EndedAt, &result.ObservationCount, &diagnostics) != nil {
				results.Close()
				return h, ErrUnavailable
			}
			for _, code := range diagnostics {
				result.Diagnostics = append(result.Diagnostics, collection.Diagnostic{Code: code})
			}
			h.Runs[i].Results = append(h.Runs[i].Results, result)
		}
		err = results.Err()
		results.Close()
		if err != nil {
			return h, ErrUnavailable
		}
	}
	rows, e = s.pool.Query(ctx, `SELECT DISTINCT ON(o.key) o.id::text,o.run_id::text,o.source_revision,o.collector_id,o.collector_version,o.command_id,o.key,o.kind,coalesce(o.text_value,''),coalesce(o.integer_value::text,''),o.unit,o.transport,o.quality,o.observed_at,o.received_at,o.ttl_seconds FROM observation o JOIN collection_run r ON r.id=o.run_id WHERE o.source_id=$1 AND r.customer_id=$2 AND r.environment_id=$3 AND r.cluster_id=$4 AND o.observed_at<=$5 AND o.received_at<=$5 AND o.recorded_at<=$5 AND r.evidence_recorded_at<=$5 AND o.source_revision=$6 ORDER BY o.key,o.observed_at DESC,o.id DESC LIMIT 8`, v.ID, v.CustomerID, v.EnvironmentID, v.ClusterID, at, v.Revision)
	if e != nil {
		return h, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var o collection.Evidence
		var integer string
		o.SourceID = v.ID
		o.SubjectType = "cluster"
		if rows.Scan(&o.ID, &o.RunID, &o.SourceRevision, &o.CollectorID, &o.CollectorVersion, &o.CommandID, &o.Key, &o.Value.Kind, &o.Value.Text, &integer, &o.Unit, &o.Transport, &o.Quality, &o.ObservedAt, &o.ReceivedAt, &o.TTLSeconds) != nil {
			return h, ErrUnavailable
		}
		if integer != "" {
			o.Value.Integer, e = strconv.ParseUint(integer, 10, 64)
			if e != nil {
				return h, ErrUnavailable
			}
		}
		o.At(at)
		h.Latest = append(h.Latest, o)
	}
	if rows.Err() != nil {
		return h, ErrUnavailable
	}
	return h, nil
}
