package postgres

import (
	"context"
	"noc-workbench/internal/scheduler"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

func collectionAccess(p workspace.Principal, h collection.HistoryScope) error {
	if p.ID != workspace.OperatorID || !inventory.ValidID(h.CustomerID) || !inventory.ValidID(h.EnvironmentID) || !inventory.ValidID(h.AssetID) {
		return workspace.ErrDenied
	}
	return nil
}

const runColumns = `id::text,asset_id::text,endpoint_id::text,profile_id::text,profile_revision,endpoint_revision,principal_id::text,started_at,ended_at,state,category,success_count,failure_count,request_source,coalesce(schedule_id::text,''),coalesce(schedule_revision,0)`

func scanRun(row pgx.Row) (r collection.Run, err error) {
	var ended *time.Time
	err = row.Scan(&r.ID, &r.Target.AssetID, &r.Target.EndpointID, &r.Target.ProfileID, &r.Target.ProfileVersion, &r.EndpointRevision, &r.PrincipalID, &r.StartedAt, &ended, &r.State, &r.Category, &r.SuccessCount, &r.FailureCount, &r.Source, &r.ScheduleID, &r.ScheduleRevision)
	if ended != nil {
		r.EndedAt = *ended
	}
	return
}
func (s *Store) BeginCollection(ctx context.Context, p workspace.Principal, t sshcli.Target) (collection.Run, error) {
	if p.ID != workspace.OperatorID {
		return collection.Run{}, workspace.ErrDenied
	}
	r, e := s.Enrollment(ctx, t.EndpointID, t.ProfileID)
	if e != nil || r.Target() != t || r.State != "connection_verified" {
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
	if e = lockEnrollmentOwners(ctx, tx, r); e != nil {
		return collection.Run{}, e
	}
	req := collection.Requested(ctx)
	ids := []string{"linux.identity", "linux.uptime", "linux.load", "linux.memory", "linux.filesystems"}
	var scheduleID any
	var scheduleRevision any
	var profile scheduler.Profile
	if req.Source == "scheduled" {
		if paused {
			return collection.Run{}, workspace.ErrDenied
		}
		profile, e = validateScheduleAdmission(ctx, tx, r, req)
		if e != nil {
			return collection.Run{}, e
		}
		scheduleID = profile.ID
		scheduleRevision = profile.Revision
		ids = profile.Collectors
	} else if req.Source != "operator" {
		return collection.Run{}, workspace.ErrDenied
	}
	if req.Source == "operator" && len(req.Collectors) > 0 {
		ids = req.Collectors
	}
	if e = collectorsAllowed(ctx, tx, p, t, ids); e != nil {
		return collection.Run{}, e
	}
	out, e := scanRun(tx.QueryRow(ctx, `INSERT INTO collection_run(customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,endpoint_revision,principal_id,request_source,schedule_id,schedule_revision,collector_ids) SELECT customer_id,environment_id,asset_id,endpoint_id,id,revision,$1,$2,$5,$6,$7,$8 FROM connection_profile WHERE id=$3 AND revision=$4 AND state='connection_verified' AND NOT EXISTS(SELECT 1 FROM ssh_execution_guard WHERE profile_id=$3) RETURNING `+runColumns, r.Details.EndpointUpdatedAt, p.ID, r.ID, r.Revision, req.Source, scheduleID, scheduleRevision, ids))
	if e == nil && req.Source == "scheduled" {
		_, e = tx.Exec(ctx, `UPDATE collection_schedule SET last_dispatch=$1,next_due=$2,state='running',category='',lag_seconds=greatest(0,extract(epoch FROM $1-next_due)) WHERE id=$3`, out.StartedAt, scheduler.Next(profile, out.StartedAt), profile.ID)
	}
	if e != nil || tx.Commit(ctx) != nil {
		return out, ErrUnavailable
	}
	return out, nil
}

var safeDiagnostic = regexp.MustCompile(`^[a-z_]{1,80}$`)

func (s *Store) FinishCollection(ctx context.Context, p workspace.Principal, r collection.Run, ttl int) error {
	if p.ID != workspace.OperatorID || r.PrincipalID != p.ID || (len(r.Results) < 1 || len(r.Results) > 9) || ttl < 1 || ttl > 86400 {
		return collection.ErrPersistence
	}
	r.Summarize()
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	var target collection.Run
	target, e = scanRun(tx.QueryRow(ctx, `SELECT `+runColumns+` FROM collection_run WHERE id=$1 AND principal_id=$2 AND state='running' FOR UPDATE`, r.ID, p.ID))
	if e != nil || target.Target != r.Target {
		return collection.ErrPersistence
	}
	var expected []string
	if tx.QueryRow(ctx, `SELECT collector_ids FROM collection_run WHERE id=$1`, r.ID).Scan(&expected) != nil {
		return collection.ErrPersistence
	}
	got := []string{}
	for _, c := range r.Results {
		got = append(got, c.CollectorID)
	}
	sort.Strings(expected)
	sort.Strings(got)
	if !reflect.DeepEqual(expected, got) {
		return collection.ErrPersistence
	}
	for _, c := range r.Results {
		if len(c.Diagnostics) > 16 || len(c.Observations) > 2048 {
			return collection.ErrPersistence
		}
		diag := []string{}
		for _, d := range c.Diagnostics {
			if !safeDiagnostic.MatchString(d.Code) {
				return collection.ErrPersistence
			}
			diag = append(diag, d.Code)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO collector_result(run_id,collector_id,version,command_id,outcome,transport_outcome,started_at,ended_at,observation_count,diagnostics) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.ID, c.CollectorID, c.Version, c.CommandID, c.Outcome, c.TransportOutcome, c.StartedAt, c.EndedAt, len(c.Observations), diag); e != nil {
			return ErrUnavailable
		}
		for _, o := range c.Observations {
			if o.AssetID != r.Target.AssetID || o.EndpointID != r.Target.EndpointID || o.ProfileID != r.Target.ProfileID || o.ProfileVersion != r.Target.ProfileVersion || o.CollectorID != c.CollectorID || o.CollectorVersion != c.Version || o.CommandID != c.CommandID || o.SubjectType != "asset" {
				return collection.ErrPersistence
			}
			var text, integer, number any
			switch o.Value.Kind {
			case "text":
				text = o.Value.Text
			case "integer":
				integer = strconv.FormatUint(o.Value.Integer, 10)
			case "number":
				number = o.Value.Number
			default:
				return collection.ErrPersistence
			}
			_, e = tx.Exec(ctx, `INSERT INTO observation(run_id,asset_id,endpoint_id,profile_id,profile_revision,collector_id,collector_version,command_id,key,resource,kind,text_value,integer_value,number_value,unit,transport,quality,observed_at,received_at,ttl_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, r.ID, o.AssetID, o.EndpointID, o.ProfileID, o.ProfileVersion, o.CollectorID, o.CollectorVersion, o.CommandID, o.Key, o.Resource, o.Value.Kind, text, integer, number, o.Unit, o.Transport, o.Quality, o.ObservedAt, o.ReceivedAt, ttl)
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
func (s *Store) CollectionHistory(ctx context.Context, p workspace.Principal, h collection.HistoryScope, before string) ([]collection.Run, error) {
	if e := collectionAccess(p, h); e != nil {
		return nil, e
	}
	if before != "" && !inventory.ValidID(before) {
		return nil, inventory.ErrNotFound
	}
	rows, e := s.pool.Query(ctx, `SELECT `+runColumns+` FROM collection_run WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 AND ($4='' OR (started_at,id)<(SELECT started_at,id FROM collection_run WHERE id=nullif($4,'')::uuid AND customer_id=$1 AND environment_id=$2 AND asset_id=$3)) ORDER BY started_at DESC,id DESC LIMIT 20`, h.CustomerID, h.EnvironmentID, h.AssetID, before)
	if e != nil {
		return nil, ErrUnavailable
	}
	all := []collection.Run{}
	for rows.Next() {
		r, e := scanRun(rows)
		if e != nil {
			rows.Close()
			return nil, ErrUnavailable
		}
		all = append(all, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, ErrUnavailable
	}
	for i := range all {
		r := &all[i]
		rr, e := s.pool.Query(ctx, `SELECT collector_id,version,command_id,outcome,transport_outcome,started_at,ended_at,observation_count,diagnostics FROM collector_result WHERE run_id=$1 ORDER BY collector_id`, r.ID)
		if e != nil {
			return nil, ErrUnavailable
		}
		for rr.Next() {
			var c collection.Result
			var ds []string
			if rr.Scan(&c.CollectorID, &c.Version, &c.CommandID, &c.Outcome, &c.TransportOutcome, &c.StartedAt, &c.EndedAt, &c.ObservationCount, &ds) != nil {
				rr.Close()
				return nil, ErrUnavailable
			}
			for _, d := range ds {
				c.Diagnostics = append(c.Diagnostics, collection.Diagnostic{Code: d})
			}
			r.Results = append(r.Results, c)
		}
		e = rr.Err()
		rr.Close()
		if e != nil {
			return nil, ErrUnavailable
		}
	}
	return all, nil
}
func (s *Store) LatestEvidence(ctx context.Context, p workspace.Principal, h collection.HistoryScope) ([]collection.Evidence, error) {
	if e := collectionAccess(p, h); e != nil {
		return nil, e
	}
	rows, e := s.pool.Query(ctx, `SELECT DISTINCT ON(o.key,o.resource_hash) o.id::text,o.run_id::text,o.asset_id::text,o.endpoint_id::text,o.profile_id::text,o.profile_revision,o.collector_id,o.collector_version,o.command_id,o.key,o.resource,o.kind,coalesce(o.text_value,''),coalesce(o.integer_value::text,''),coalesce(o.number_value,0),o.unit,o.transport,o.quality,o.observed_at,o.received_at,o.ttl_seconds FROM observation o JOIN collection_run r ON r.id=o.run_id WHERE r.customer_id=$1 AND r.environment_id=$2 AND o.asset_id=$3 ORDER BY o.key,o.resource_hash,o.observed_at DESC,o.id DESC LIMIT 2049`, h.CustomerID, h.EnvironmentID, h.AssetID)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	all := []collection.Evidence{}
	for rows.Next() {
		var o collection.Evidence
		var integer string
		o.SubjectType = "asset"
		if rows.Scan(&o.ID, &o.RunID, &o.AssetID, &o.EndpointID, &o.ProfileID, &o.ProfileVersion, &o.CollectorID, &o.CollectorVersion, &o.CommandID, &o.Key, &o.Resource, &o.Value.Kind, &o.Value.Text, &integer, &o.Value.Number, &o.Unit, &o.Transport, &o.Quality, &o.ObservedAt, &o.ReceivedAt, &o.TTLSeconds) != nil {
			return nil, ErrUnavailable
		}
		if integer != "" {
			v, e := strconv.ParseUint(integer, 10, 64)
			if e != nil {
				return nil, ErrUnavailable
			}
			o.Value.Integer = v
		}
		all = append(all, o)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Key != all[j].Key {
			return all[i].Key < all[j].Key
		}
		return all[i].Resource < all[j].Resource
	})
	return all, nil
}

// Called once at single-process startup, never an automatic SSH retry.
func (s *Store) RecoverCollections(ctx context.Context) error {
	_, e := s.pool.Exec(ctx, `UPDATE collection_run SET state='interrupted',category='interrupted',ended_at=greatest(clock_timestamp(),started_at) WHERE state='running'`)
	if e != nil {
		return ErrUnavailable
	}
	return nil
}

// Bounded manual-request maintenance retains latest valid series and their parent
// provenance even beyond detail retention. No independent latest-value store.
func (s *Store) MaintainCollections(ctx context.Context, now time.Time, runDays, sampleDays int) error {
	if runDays < 1 || runDays > 365 || sampleDays < 1 || sampleDays > runDays {
		return collection.ErrPersistence
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	_, e = tx.Exec(ctx, `DELETE FROM observation WHERE id IN(SELECT o.id FROM observation o WHERE observed_at<$1 AND EXISTS(SELECT 1 FROM observation n WHERE ((n.asset_id=o.asset_id AND o.source_id IS NULL) OR (n.source_id=o.source_id AND o.asset_id IS NULL)) AND n.key=o.key AND n.resource_hash=o.resource_hash AND n.resource=o.resource AND (n.observed_at,n.id)>(o.observed_at,o.id)) ORDER BY observed_at LIMIT 2000)`, now.AddDate(0, 0, -sampleDays))
	if e != nil {
		return ErrUnavailable
	}
	_, e = tx.Exec(ctx, `DELETE FROM collection_run WHERE id IN(SELECT r.id FROM collection_run r WHERE r.started_at<$1 AND r.state<>'running' AND NOT EXISTS(SELECT 1 FROM observation o WHERE o.run_id=r.id) ORDER BY r.started_at LIMIT 200)`, now.AddDate(0, 0, -runDays))
	if e != nil || tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
