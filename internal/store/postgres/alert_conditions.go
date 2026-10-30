package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/services"
	"noc-workbench/internal/health"
	"noc-workbench/internal/integrations/mariadb"
)

func operationalConditionsTx(ctx context.Context, tx pgx.Tx, in health.Input) ([]health.Condition, error) {
	// No policies, no additional source reads. All reads share the evaluator's
	// transaction and canonical asset lock; failures abort, never imply recovery.
	needed := map[string]bool{}
	for _, p := range in.Policies {
		if p.Enabled && health.OperationalSelector(p.Selector) {
			needed[p.Selector] = true
		}
	}
	if len(needed) == 0 {
		return nil, nil
	}
	h, at := in.Scope, in.At
	var out []health.Condition
	add := func(key, resource, state, reason string, e collection.Evidence, value *uint64) {
		e.Key = key
		e.Resource = resource
		e.AssetID = h.AssetID
		if value != nil {
			e.Value = collection.Integer(*value)
			e.Unit = "count"
			if key == "database.replication.lag_seconds" {
				e.Unit = "seconds"
			}
		}
		out = append(out, health.Condition{Evidence: e, State: state, Reason: reason, Value: value})
	}
	previousResources := func(key string) ([]string, error) {
		rows, err := tx.Query(ctx, `SELECT DISTINCT a.resource FROM alert_instance a JOIN alert_rule r ON r.id=a.rule_id AND r.revision=a.rule_revision JOIN evaluation_policy p ON p.id=r.policy_id AND p.revision=r.policy_revision WHERE a.asset_id=$1 AND p.selector=$2 AND a.state<>'resolved' ORDER BY a.resource LIMIT 2049`, h.AssetID, key)
		if err != nil {
			return nil, ErrUnavailable
		}
		defer rows.Close()
		var resources []string
		for rows.Next() {
			var v string
			if rows.Scan(&v) != nil {
				return nil, ErrUnavailable
			}
			resources = append(resources, v)
		}
		if rows.Err() != nil || len(resources) > 2048 {
			return nil, ErrUnavailable
		}
		return resources, nil
	}
	var s health.ScheduleProgress
	var profile string
	var revision int64
	var last, complete, due *time.Time
	err := tx.QueryRow(ctx, `SELECT s.monitoring_expected,s.authorized,s.enabled,
 s.paused OR EXISTS(SELECT 1 FROM schedule_pause p WHERE p.customer_id=s.customer_id OR p.asset_id=s.asset_id OR p.cluster_id IN(SELECT cluster_id FROM cluster_membership WHERE asset_id=s.asset_id)) OR c.paused,
 c.stopped,EXISTS(SELECT 1 FROM ssh_execution_guard WHERE profile_id=s.profile_id),s.interval_seconds,s.budget_seconds,s.category,s.last_dispatch,s.completed_at,s.next_due,s.profile_id::text,s.profile_revision
 FROM collection_schedule s CROSS JOIN scheduler_control c WHERE s.asset_id=$1 AND s.customer_id=$2 AND s.environment_id=$3 AND s.source_id IS NULL`, h.AssetID, h.CustomerID, h.EnvironmentID).Scan(&s.Expected, &s.Authorized, &s.Enabled, &s.Paused, &s.Stopped, &s.Guard, &s.Interval, &s.Budget, &s.Category, &last, &complete, &due, &profile, &revision)
	if err != nil && err != pgx.ErrNoRows {
		return nil, ErrUnavailable
	}
	s.Exists = err == nil
	if last != nil {
		s.LastDispatch = *last
	}
	if due != nil {
		s.NextDue = *due
	}
	// Only a durable completed scheduled attempt establishes collector progress.
	// Admission completion timestamps alone cannot hide repeated local failures.
	var durable *time.Time
	if err = tx.QueryRow(ctx, `SELECT max(r.ended_at) FROM collection_run r WHERE r.asset_id=$1 AND r.profile_id=$2::uuid AND r.profile_revision=$3 AND r.request_source='scheduled' AND EXISTS(SELECT 1 FROM collector_result c WHERE c.run_id=r.id AND c.transport_outcome NOT IN ('local_storage_failure','ssh_guard_unavailable','ssh_guard_conflict','ssh_guard_uncertain','cancelled','internal_transport_error')) AND r.ended_at<=$4 AND r.evidence_recorded_at<=$4`, h.AssetID, nullableID(profile), revision, at).Scan(&durable); err != nil {
		return nil, ErrUnavailable
	}
	if durable != nil {
		s.CompletedAt = *durable
	}
	control := collection.Evidence{Observation: collection.Observation{AssetID: h.AssetID, ProfileID: profile, ProfileVersion: revision, CollectorID: "monitoring.controls", CollectorVersion: "1", Transport: "local", Quality: "valid", ObservedAt: at, ReceivedAt: at, Value: collection.Text("Current persisted monitoring controls")}}
	for _, p := range in.Policies {
		if p.Selector == "monitoring.continuity" && p.Enabled {
			state, reason := health.Continuity(s, p, at)
			add(p.Selector, "monitoring", state, reason, control, nil)
		}
	}
	eligible := s.Exists && s.Expected && s.Enabled && s.Authorized && !s.Paused && !s.Stopped && in.Active && in.Trusted && in.Authority[profile] == revision
	if !eligible {
		return out, nil
	} // Missing candidates hold incidents; no fabricated recovery.
	grants := map[string]bool{}
	grantRows, err := tx.Query(ctx, `SELECT integration FROM collection_integration WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND enabled`, h.AssetID, profile, revision)
	if err != nil {
		return nil, ErrUnavailable
	}
	for grantRows.Next() {
		var name string
		if grantRows.Scan(&name) != nil {
			grantRows.Close()
			return nil, ErrUnavailable
		}
		grants[name] = true
	}
	err = grantRows.Err()
	grantRows.Close()
	if err != nil {
		return nil, ErrUnavailable
	}
	// Adjacent terminal attempts use precisely the Dashboard SSH reduction.
	if needed["server.ssh_unreachable"] {
		rows, e := tx.Query(ctx, `SELECT `+runColumns+` FROM collection_run WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND ended_at<=$4 AND evidence_recorded_at<=$4 ORDER BY started_at DESC,id DESC LIMIT 2`, h.AssetID, profile, revision, at)
		if e != nil {
			return nil, ErrUnavailable
		}
		var runs []collection.Run
		for rows.Next() {
			r, e := scanRun(rows)
			if e != nil {
				rows.Close()
				return nil, ErrUnavailable
			}
			runs = append(runs, r)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, ErrUnavailable
		}
		for i := range runs {
			rr, e := tx.Query(ctx, `SELECT transport_outcome FROM collector_result WHERE run_id=$1 ORDER BY collector_id LIMIT 32`, runs[i].ID)
			if e != nil {
				return nil, ErrUnavailable
			}
			for rr.Next() {
				var c collection.Result
				if rr.Scan(&c.TransportOutcome) != nil {
					rr.Close()
					return nil, ErrUnavailable
				}
				runs[i].Results = append(runs[i].Results, c)
			}
			e = rr.Err()
			rr.Close()
			if e != nil {
				return nil, ErrUnavailable
			}
		}
		if len(runs) > 0 {
			r := runs[0]
			e := control
			e.RunID = r.ID
			e.ObservedAt = r.StartedAt
			e.ReceivedAt = r.EndedAt
			state, reason := "unknown", "SSH evidence inconclusive"
			if health.Connectivity(r) == "success" {
				state, reason = "healthy", "Authorized SSH observation succeeded"
			} else if health.NetworkFailure(health.Connectivity(r)) && len(runs) == 2 && health.NetworkFailure(health.Connectivity(runs[1])) && r.StartedAt.After(runs[1].StartedAt) && r.StartedAt.Sub(runs[1].StartedAt) <= time.Duration(3*s.Interval+s.Budget)*time.Second && corroborationFresh(runs[1].StartedAt, in.Policies, at) {
				state, reason = "degraded", "Two consecutive verified SSH network failures"
			}
			add("server.ssh_unreachable", "ssh", state, reason, e, nil)
		}
	}
	// Select latest terminal result, including failures with no observations.
	result := func(id string) (collection.Evidence, string, []string, error) {
		e := control
		var outcome string
		var codes []string
		err := tx.QueryRow(ctx, `SELECT r.id::text,c.started_at,c.ended_at,c.outcome,c.diagnostics,c.transport_outcome FROM collection_run r JOIN collector_result c ON c.run_id=r.id WHERE r.asset_id=$1 AND r.profile_id=$2 AND r.profile_revision=$3 AND c.collector_id=$4 AND r.ended_at<=$5 AND r.evidence_recorded_at<=$5 ORDER BY c.started_at DESC,r.id DESC LIMIT 1`, h.AssetID, profile, revision, id, at).Scan(&e.RunID, &e.ObservedAt, &e.ReceivedAt, &outcome, &codes, &e.Transport)
		e.CollectorID = id
		e.Value = collection.Text("Normalized collector result")
		return e, outcome, codes, err
	}
	if needed["service.runtime.unavailable"] && grants["runtime_services"] && grants["asterisk"] {
		e, outcome, _, err := result("linux.services")
		if err != nil && err != pgx.ErrNoRows {
			return nil, ErrUnavailable
		}
		if err == nil && outcome == "success" {
			for _, o := range in.Evidence {
				if o.Key == services.Key && o.Resource == "asterisk" && o.RunID == e.RunID {
					signal, err := services.Decode(o)
					if err != nil {
						continue
					}
					r := services.Classify(signal)
					state := "unknown"
					if r.Runtime == "Running" {
						state = "healthy"
					}
					if r.Runtime == "Stopped" {
						state = "degraded"
					}
					add("service.runtime.unavailable", "asterisk", state, r.Reason, o, nil)
				}
			}
		}
	}
	if grants["mariadb"] && (needed["database.query.failed"] || needed["database.replication.failed"] || needed["database.replication.lag_seconds"]) {
		e, outcome, codes, err := result("mariadb.health")
		if err != nil && err != pgx.ErrNoRows {
			return nil, ErrUnavailable
		}
		if err == nil {
			state, reason := "unknown", "Database collector unavailable"
			if outcome == "success" || outcome == "partial" {
				state, reason = "healthy", "Authenticated monitoring query succeeded"
			}
			for _, code := range codes {
				if e.Transport != "success" {
					break
				}
				switch code {
				case "connection_unavailable", "authentication_denied", "permission_denied", "query_failure", "timeout":
					state, reason = "degraded", "Database query readiness: "+code
				}
			}
			// Only a normalized readiness diagnostic is a database failure. SSH/local
			// executor errors do not establish a database outcome.
			if state == "healthy" {
				rows, err := tx.Query(ctx, `SELECT resource,text_value FROM observation WHERE run_id=$1 AND collector_id='mariadb.health' AND key='mariadb.snapshot' AND observed_at<=$2 AND received_at<=$2 AND recorded_at<=$2 ORDER BY resource LIMIT 66`, e.RunID, at)
				if err != nil {
					return nil, ErrUnavailable
				}
				var obs []collection.Observation
				for rows.Next() {
					var o collection.Observation
					o.Key = mariadb.Key
					o.Value.Kind = "text"
					if rows.Scan(&o.Resource, &o.Value.Text) != nil {
						rows.Close()
						return nil, ErrUnavailable
					}
					obs = append(obs, o)
				}
				err = rows.Err()
				rows.Close()
				if err != nil {
					return nil, ErrUnavailable
				}
				snap, err := mariadb.Decode(obs)
				if err != nil {
					state, reason = "unknown", "Database readiness snapshot missing or invalid"
				}
				if err == nil && snap.Replication == "ready" {
					seen := map[string]bool{}
					for _, c := range snap.Channels {
						seen[c.Name] = true
						state, reason := replicationCondition(c)
						add("database.replication.failed", c.Name, state, reason, e, nil)
						lagState := "unknown"
						if c.Lag != nil {
							lagState = "healthy"
						}
						add("database.replication.lag_seconds", c.Name, lagState, "Reported replica lag in seconds; NULL remains unavailable", e, c.Lag)
					}
					for _, key := range []string{"database.replication.failed", "database.replication.lag_seconds"} {
						resources, err := previousResources(key)
						if err != nil {
							return nil, err
						}
						for _, name := range resources {
							if !seen[name] {
								add(key, name, "healthy", "Complete replica snapshot: channel no longer configured", e, nil)
							}
						}
					}
				}
			}
			add("database.query.failed", "mariadb", state, reason, e, nil)
		}
	}
	if needed["service.ami.disconnected"] && grants["asterisk"] {
		var granted bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM asterisk_ami_grant WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND enabled)`, h.AssetID, profile, revision).Scan(&granted) != nil {
			return nil, ErrUnavailable
		}
		if granted {
			var state, reason string
			var updated time.Time
			err := tx.QueryRow(ctx, `SELECT state,reason,updated_at FROM asterisk_ami_session WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND credential_digest=(SELECT credential_digest FROM asterisk_ami_grant WHERE asset_id=$1 AND enabled) AND started_at<=$4 ORDER BY started_at DESC,id DESC LIMIT 1`, h.AssetID, profile, revision, at).Scan(&state, &reason, &updated)
			if err != nil && err != pgx.ErrNoRows {
				return nil, ErrUnavailable
			}
			// Connected is current managed-session state, not its last RTCP/event time.
			status := "unknown"
			if err == nil && state == "connected" {
				status = "healthy"
			} else if err == pgx.ErrNoRows || (err == nil && reason != "monitoring_paused" && reason != "authorization_revoked" && reason != "authority_unavailable") {
				status = "degraded"
			}
			e := control
			e.Value = collection.Text(state)
			add("service.ami.disconnected", "ami", status, "AMI "+state+": "+reason, e, nil)
		}
	}
	if needed["service.authentication.repeated"] && grants["asterisk_auth"] && grants["asterisk"] {
		e, outcome, _, err := result("asterisk.auth")
		if err != nil && err != pgx.ErrNoRows {
			return nil, ErrUnavailable
		}
		if err == nil && (outcome == "success" || outcome == "partial") {
			var status string
			var checked time.Time
			err = tx.QueryRow(ctx, `SELECT status,checked_at FROM asterisk_auth_status WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3`, h.AssetID, profile, revision).Scan(&status, &checked)
			if err != nil && err != pgx.ErrNoRows {
				return nil, ErrUnavailable
			}
			if err == nil && (status == "current" || status == "current_with_gap") && !checked.After(at) && at.Sub(checked) < 180*time.Second {
				// Complete retained hour groups allow known incidents to recover after
				// aging out of five minutes. Unknown account/IP rows never form a group.
				e.ObservedAt = checked
				e.ReceivedAt = checked
				seen := map[string]bool{}
				rows, err := tx.Query(ctx, `SELECT account,host(observed_ip),event_type,count(*) FILTER(WHERE event_at>=$4::timestamptz-interval '5 minutes') FROM asterisk_auth_event WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND account<>'' AND observed_ip IS NOT NULL AND event_at>=$4::timestamptz-interval '1 hour' AND event_at<=$4 GROUP BY account,observed_ip,event_type ORDER BY account,observed_ip,event_type LIMIT 2049`, h.AssetID, profile, revision, checked)
				if err != nil {
					return nil, ErrUnavailable
				}
				count := 0
				for rows.Next() {
					var account, ip, kind string
					var n uint64
					if rows.Scan(&account, &ip, &kind, &n) != nil {
						rows.Close()
						return nil, ErrUnavailable
					}
					count++
					if count > 2048 {
						rows.Close()
						return nil, ErrUnavailable
					}
					resource, _ := json.Marshal([]string{account, ip, kind})
					seen[string(resource)] = true
					state := "healthy"
					if n >= 5 {
						state = "degraded"
					}
					add("service.authentication.repeated", string(resource), state, "Supported authentication failures in five-minute window", e, &n)
				}
				err = rows.Err()
				rows.Close()
				if err != nil {
					return nil, ErrUnavailable
				}
				resources, err := previousResources("service.authentication.repeated")
				if err != nil {
					return nil, err
				}
				for _, resource := range resources {
					if !seen[resource] {
						add("service.authentication.repeated", resource, "healthy", "Complete current authentication window: repeated condition absent", e, nil)
					}
				}
			}
		}
	}
	return out, nil
}
func nullableID(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func replicationCondition(c mariadb.Channel) (string, string) {
	if c.IOError != 0 || c.SQLError != 0 || c.IO == "No" || c.IO == "Connecting" || c.SQL == "No" {
		return "degraded", c.Condition()
	}
	if c.IO == "Yes" && c.SQL == "Yes" {
		return "healthy", "Both replica threads operating; lag evaluated separately"
	}
	return "unknown", "Replica thread state unavailable"
}

func corroborationFresh(source time.Time, policies []health.Policy, at time.Time) bool {
	for _, p := range policies {
		if p.Enabled && p.Selector == "server.ssh_unreachable" {
			return !source.After(at) && at.Before(source.Add(time.Duration(p.TTLSeconds)*time.Second))
		}
	}
	return false
}
