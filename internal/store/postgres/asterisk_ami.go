package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	activity "noc-workbench/internal/integrations/asteriskactivity"
	ami "noc-workbench/internal/integrations/asteriskami"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

func (s *Store) SetAMIGrant(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, ref, digest string, enabled bool) error {
	if collectionAccess(p, h) != nil || h.AssetID != t.AssetID {
		return workspace.ErrDenied
	}
	r, e := s.Enrollment(ctx, t.EndpointID, t.ProfileID)
	if e != nil || r.Target() != t || r.CustomerID != h.CustomerID || r.EnvironmentID != h.EnvironmentID {
		return workspace.ErrDenied
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	if !enabled {
		_, e = tx.Exec(ctx, `UPDATE asterisk_ami_grant SET enabled=false,actor=$2,updated_at=clock_timestamp() WHERE profile_id=$1`, t.ProfileID, p.ID)
	} else {
		if r.State != "connection_verified" || integrationAllowed(ctx, tx, p, t, "asterisk") != nil {
			return workspace.ErrDenied
		}
		if e = lockEnrollmentOwners(ctx, tx, r); e != nil {
			return e
		}
		var rev int64
		if tx.QueryRow(ctx, `SELECT revision FROM connection_profile WHERE id=$1 AND state='connection_verified' FOR SHARE`, t.ProfileID).Scan(&rev) != nil || rev != t.ProfileVersion {
			return workspace.ErrDenied
		}
		_, e = tx.Exec(ctx, `INSERT INTO asterisk_ami_grant(profile_id,customer_id,environment_id,asset_id,endpoint_id,profile_revision,credential_ref,credential_digest,enabled,actor) VALUES($1,$2,$3,$4,$5,$6,$7,$8,true,$9) ON CONFLICT(profile_id) DO UPDATE SET profile_revision=excluded.profile_revision,credential_ref=excluded.credential_ref,credential_digest=excluded.credential_digest,enabled=true,actor=excluded.actor,updated_at=clock_timestamp()`, t.ProfileID, h.CustomerID, h.EnvironmentID, t.AssetID, t.EndpointID, t.ProfileVersion, ref, digest, p.ID)
	}
	if e != nil {
		return ErrUnavailable
	}
	return tx.Commit(ctx)
}
func (s *Store) AMIBindings(ctx context.Context, p workspace.Principal) ([]ami.Binding, error) {
	if p.ID != workspace.OperatorID {
		return nil, workspace.ErrDenied
	}
	snapshot, e := s.Schedules(ctx, p)
	if e != nil {
		return nil, e
	}
	rows, e := s.pool.Query(ctx, `SELECT profile_id::text,customer_id::text,environment_id::text,asset_id::text,endpoint_id::text,profile_revision,credential_ref,credential_digest,enabled FROM asterisk_ami_grant ORDER BY asset_id LIMIT 1001`)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var out []ami.Binding
	for rows.Next() {
		var b ami.Binding
		if rows.Scan(&b.Target.ProfileID, &b.Scope.CustomerID, &b.Scope.EnvironmentID, &b.Target.AssetID, &b.Target.EndpointID, &b.Target.ProfileVersion, &b.Ref, &b.Digest, &b.Enabled) != nil {
			return nil, ErrUnavailable
		}
		b.Scope.AssetID = b.Target.AssetID
		for _, p := range snapshot.Profiles {
			if p.CollectionSource.ID == "" && p.Target == b.Target && p.CustomerID == b.Scope.CustomerID && p.EnvironmentID == b.Scope.EnvironmentID {
				b.Eligible = p.EvidenceEligible && p.Enabled && p.Authorized
				b.Paused = snapshot.Paused || snapshot.Stopped || p.Paused
				break
			}
		}
		if s.IntegrationAllowed(ctx, workspace.Principal{ID: workspace.OperatorID}, b.Target, "asterisk") != nil {
			b.Eligible = false
		}
		b.Activity = s.IntegrationAllowed(ctx, workspace.Principal{ID: workspace.OperatorID}, b.Target, "asterisk_activity") == nil
		b.Media = b.Activity && s.IntegrationAllowed(ctx, workspace.Principal{ID: workspace.OperatorID}, b.Target, "asterisk_media") == nil
		out = append(out, b)
	}
	if rows.Err() != nil || len(out) > 1000 {
		return nil, ErrUnavailable
	}
	return out, nil
}

// Transactions hold the grant, enrollment and pause-control rows through event
// persistence. No evidence can commit under a withdrawn grant or old revision.
func amiAllowed(ctx context.Context, tx pgx.Tx, b ami.Binding) error {
	// Serialize before taking the statement snapshot that inspects scoped pauses.
	// Control locks this singleton before changing any global or scoped pause.
	var control bool
	if tx.QueryRow(ctx, `SELECT id FROM scheduler_control WHERE id FOR SHARE`).Scan(&control) != nil {
		return workspace.ErrDenied
	}
	var yes bool
	e := tx.QueryRow(ctx, `SELECT true FROM asterisk_ami_grant g JOIN connection_profile p ON p.id=g.profile_id JOIN asset a ON a.id=g.asset_id JOIN environment e ON e.id=g.environment_id JOIN customer c ON c.id=g.customer_id JOIN asset_endpoint ep ON ep.id=g.endpoint_id JOIN collection_schedule s ON s.profile_id=g.profile_id JOIN scheduler_control control ON control.id WHERE g.profile_id=$1 AND g.customer_id=$2 AND g.environment_id=$3 AND g.asset_id=$4 AND g.endpoint_id=$5 AND g.profile_revision=$6 AND g.credential_digest=$7 AND g.enabled AND p.revision=$6 AND p.state='connection_verified' AND a.lifecycle='active' AND e.status='active' AND c.status='active' AND ep.status='active' AND ep.updated_at=s.endpoint_revision AND s.profile_revision=$6 AND s.enabled AND s.authorized AND NOT s.paused AND NOT control.paused AND NOT control.stopped AND NOT EXISTS(SELECT 1 FROM schedule_pause pause WHERE pause.customer_id=g.customer_id OR pause.asset_id=g.asset_id OR pause.cluster_id IN(SELECT cluster_id FROM cluster_membership WHERE asset_id=g.asset_id)) AND NOT EXISTS(SELECT 1 FROM cluster_membership m JOIN cluster cl ON cl.id=m.cluster_id WHERE m.asset_id=g.asset_id AND cl.lifecycle<>'active') FOR SHARE OF g,p,a,e,c,ep,s,control`, b.Target.ProfileID, b.Scope.CustomerID, b.Scope.EnvironmentID, b.Target.AssetID, b.Target.EndpointID, b.Target.ProfileVersion, b.Digest).Scan(&yes)
	if e != nil || !yes {
		return workspace.ErrDenied
	}
	return integrationAllowed(ctx, tx, workspace.Principal{ID: workspace.OperatorID}, b.Target, "asterisk")
}
func (s *Store) RecoverAMI(ctx context.Context) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	_, e = tx.Exec(ctx, `WITH recovered AS (UPDATE asterisk_ami_session SET state='disconnected',reason='application_restart',coverage_gap=true,ended_at=clock_timestamp(),updated_at=clock_timestamp() WHERE ended_at IS NULL RETURNING id,updated_at,dropped) INSERT INTO asterisk_ami_transition(session_id,state,reason,at,coverage_gap,dropped) SELECT id,'disconnected','application_restart',updated_at,true,dropped FROM recovered`)
	if e != nil {
		return ErrUnavailable
	}
	return tx.Commit(ctx)
}

// Called only after the in-process owner has closed and joined its prior SSH
// stream. Application ownership excludes another process; the profile identity
// matches recovery to that completed owner, without touching finite SSH guards.
func (s *Store) RecoverAMIBinding(ctx context.Context, b ami.Binding) error {
	_, e := s.pool.Exec(ctx, `WITH recovered AS (UPDATE asterisk_ami_session SET state='disconnected',reason='transport_disconnected',coverage_gap=true,ended_at=clock_timestamp(),updated_at=clock_timestamp() WHERE profile_id=$1 AND customer_id=$2 AND environment_id=$3 AND asset_id=$4 AND ended_at IS NULL RETURNING id,updated_at,dropped) INSERT INTO asterisk_ami_transition(session_id,state,reason,at,coverage_gap,dropped) SELECT id,'disconnected','transport_disconnected',updated_at,true,dropped FROM recovered`, b.Target.ProfileID, b.Scope.CustomerID, b.Scope.EnvironmentID, b.Target.AssetID)
	if e != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) BeginAMISession(ctx context.Context, b ami.Binding, at time.Time) (string, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return "", ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	if e = amiAllowed(ctx, tx, b); e != nil {
		return "", e
	}
	var id string
	e = tx.QueryRow(ctx, `INSERT INTO asterisk_ami_session(customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,credential_digest,state,reason,started_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,'connecting','',$8,$8) RETURNING id::text`, b.Scope.CustomerID, b.Scope.EnvironmentID, b.Target.AssetID, b.Target.EndpointID, b.Target.ProfileID, b.Target.ProfileVersion, b.Digest, at).Scan(&id)
	if e != nil {
		return "", ErrUnavailable
	}
	if _, e = tx.Exec(ctx, `INSERT INTO asterisk_ami_transition(session_id,state,reason,at,coverage_gap,dropped) VALUES($1,'connecting','',$2,false,0)`, id, at); e != nil {
		return "", ErrUnavailable
	}
	return id, tx.Commit(ctx)
}
func (s *Store) AMITransition(ctx context.Context, b ami.Binding, id, state, reason string, at time.Time, dropped int64, gap bool) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	terminal := state != "connecting" && state != "authenticating" && state != "connected"
	if !terminal {
		if e = amiAllowed(ctx, tx, b); e != nil {
			return e
		}
	}
	var old string
	var oldGap bool
	var oldDrop int64
	if tx.QueryRow(ctx, `SELECT state,coverage_gap,dropped FROM asterisk_ami_session WHERE id=$1 AND profile_id=$2 AND customer_id=$3 AND environment_id=$4 AND asset_id=$5 AND endpoint_id=$6 AND profile_revision=$7 AND credential_digest=$8 FOR UPDATE`, id, b.Target.ProfileID, b.Scope.CustomerID, b.Scope.EnvironmentID, b.Target.AssetID, b.Target.EndpointID, b.Target.ProfileVersion, b.Digest).Scan(&old, &oldGap, &oldDrop) != nil {
		return workspace.ErrDenied
	}
	if !terminal && old != "connecting" && old != "authenticating" && old != "connected" {
		return workspace.ErrDenied
	}
	_, e = tx.Exec(ctx, `UPDATE asterisk_ami_session SET state=$2,reason=CASE WHEN reason='persistence_failed' AND $3='transport_disconnected' THEN reason ELSE $3 END,updated_at=$4,connected_at=CASE WHEN $2='connected' THEN coalesce(connected_at,$4) ELSE connected_at END,ended_at=CASE WHEN $5 THEN coalesce(ended_at,$4) ELSE NULL END,dropped=greatest(dropped,$6),coverage_gap=coverage_gap OR $7 OR $5 OR $6>0 WHERE id=$1`, id, state, reason, at, terminal, dropped, gap)
	if e != nil {
		return ErrUnavailable
	}
	if old != state || (!oldGap && gap) || dropped > oldDrop {
		_, e = tx.Exec(ctx, `INSERT INTO asterisk_ami_transition(session_id,state,reason,at,coverage_gap,dropped) VALUES($1,$2,$3,$4,$5,$6)`, id, state, reason, at, gap || oldGap || terminal || dropped > 0, max(dropped, oldDrop))
		if e != nil {
			return ErrUnavailable
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) PersistAMIEvent(ctx context.Context, b ami.Binding, id string, event ami.Event, dropped int64) error {
	if !ami.ValidEvent(event) {
		return workspace.ErrDenied
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	if e = amiAllowed(ctx, tx, b); e != nil {
		return e
	}
	if event.Media != nil {
		if !b.Media || !b.Activity || integrationAllowed(ctx, tx, workspace.Principal{ID: workspace.OperatorID}, b.Target, "asterisk_media") != nil || integrationAllowed(ctx, tx, workspace.Principal{ID: workspace.OperatorID}, b.Target, "asterisk_activity") != nil {
			return workspace.ErrDenied
		}
	}
	if activity.IsEvent(event.Name) {
		if !b.Activity || integrationAllowed(ctx, tx, workspace.Principal{ID: workspace.OperatorID}, b.Target, "asterisk_activity") != nil {
			return workspace.ErrDenied
		}
	}
	var gap bool
	if tx.QueryRow(ctx, `SELECT coverage_gap FROM asterisk_ami_session WHERE id=$1 AND profile_id=$2 AND state='connected' AND ended_at IS NULL FOR UPDATE`, id, b.Target.ProfileID).Scan(&gap) != nil {
		return workspace.ErrDenied
	}
	activityJSON, _ := json.Marshal(event.Activity)
	mediaRuntime, mediaChannel := "", ""
	if event.Media != nil {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT state FROM asterisk_activity_state WHERE profile_id=$1 AND profile_revision=$2 AND state->>'session'=$3`, b.Target.ProfileID, b.Target.ProfileVersion, id).Scan(&raw)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return ErrUnavailable
		}
		if err == nil {
			var state activity.State
			if activity.Decode(raw, &state) != nil {
				return ErrUnavailable
			}
			mediaRuntime = state.Runtime
			for _, c := range state.Channels {
				if c.ID == event.Media.Uniqueid {
					mediaChannel = c.Name
					break
				}
			}
		}
	}
	mediaJSON, _ := json.Marshal(event.Media)
	insert, e := tx.Exec(ctx, `INSERT INTO asterisk_ami_event(session_id,customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,sequence,name,technology,endpoint,aor,address,state,rtt_ms,source_at,received_at,parser_version,coverage_gap,activity,media,media_runtime,media_channel) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'1',$18,$19,$20,$21,$22) ON CONFLICT(session_id,sequence) DO NOTHING`, id, b.Scope.CustomerID, b.Scope.EnvironmentID, b.Target.AssetID, b.Target.EndpointID, b.Target.ProfileID, b.Target.ProfileVersion, event.Sequence, event.Name, event.Technology, event.Endpoint, event.AOR, event.Address, event.State, event.RTT, event.SourceAt, event.ReceivedAt, gap || dropped > 0, activityJSON, mediaJSON, mediaRuntime, mediaChannel)
	if e != nil {
		return ErrUnavailable
	}
	if insert.RowsAffected() == 0 {
		return tx.Commit(ctx)
	}
	if err := applyActivityEvent(ctx, tx, b, id, event, dropped); err != nil {
		return err
	}
	_, e = tx.Exec(ctx, `UPDATE asterisk_ami_session SET last_event_at=greatest(last_event_at,$2),updated_at=clock_timestamp(),dropped=greatest(dropped,$3),coverage_gap=coverage_gap OR $3>0 WHERE id=$1`, id, event.ReceivedAt, dropped)
	if e != nil {
		return ErrUnavailable
	}
	// Bounded maintenance, preserving current sessions and their provenance.
	_, e = tx.Exec(ctx, `DELETE FROM asterisk_ami_session WHERE id IN(SELECT id FROM asterisk_ami_session WHERE ended_at<clock_timestamp()-interval '30 days' ORDER BY ended_at LIMIT 10)`)
	if e != nil {
		return ErrUnavailable
	}
	_, e = tx.Exec(ctx, `DELETE FROM asterisk_ami_event WHERE id IN(SELECT id FROM asterisk_ami_event WHERE received_at<clock_timestamp()-interval '7 days' ORDER BY received_at LIMIT 1000)`)
	if e != nil {
		return ErrUnavailable
	}
	return tx.Commit(ctx)
}
func (s *Store) AMIView(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, now time.Time) (ami.View, error) {
	v := ami.View{State: "unauthorized", Reason: "AMI forwarding has not been authorized"}
	if collectionAccess(p, h) != nil || h.AssetID != t.AssetID {
		return v, workspace.ErrDenied
	}
	var exists bool
	if s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM connection_profile WHERE id=$1 AND customer_id=$2 AND environment_id=$3 AND asset_id=$4 AND endpoint_id=$5)`, t.ProfileID, h.CustomerID, h.EnvironmentID, t.AssetID, t.EndpointID).Scan(&exists) != nil || !exists {
		return v, workspace.ErrDenied
	}
	var revision int64
	var grantDigest string
	e := s.pool.QueryRow(ctx, `SELECT enabled,credential_ref,profile_revision,credential_digest FROM asterisk_ami_grant WHERE profile_id=$1`, t.ProfileID).Scan(&v.Authorized, &v.Ref, &revision, &grantDigest)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return v, ErrUnavailable
	}
	v.Authorized = v.Authorized && revision == t.ProfileVersion
	var connected, eventAt *time.Time
	var sessionProfile, sessionDigest string
	var sessionRevision int64
	e = s.pool.QueryRow(ctx, `SELECT id::text,state,reason,started_at,updated_at,connected_at,last_event_at,ended_at,dropped,coverage_gap,profile_id::text,profile_revision,credential_digest FROM asterisk_ami_session WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 ORDER BY started_at DESC,id DESC LIMIT 1`, h.CustomerID, h.EnvironmentID, h.AssetID).Scan(&v.Session.ID, &v.Session.State, &v.Session.Reason, &v.Session.StartedAt, &v.Session.UpdatedAt, &connected, &eventAt, &v.Session.EndedAt, &v.Session.Dropped, &v.Session.Gap, &sessionProfile, &sessionRevision, &sessionDigest)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return v, ErrUnavailable
	}
	if connected != nil {
		v.Session.ConnectedAt = *connected
	}
	if eventAt != nil {
		v.Session.LastEventAt = *eventAt
	}
	if e == nil {
		v.State, v.Reason = v.Session.State, v.Session.Reason
		v.Current = v.Authorized && sessionProfile == t.ProfileID && sessionRevision == t.ProfileVersion && sessionDigest == grantDigest && v.State == "connected" && !now.Before(v.Session.UpdatedAt) && now.Sub(v.Session.UpdatedAt) < 30*time.Second
		if v.State == "connected" && !v.Current {
			v.State = "disconnected"
			v.Reason = "Session evidence is stale or belongs to an earlier authorization"
		}
	}
	if !v.Authorized {
		v.State = "unauthorized"
		v.Current = false
		v.Reason = "AMI forwarding authorization is absent or its enrollment revision changed"
	}
	var lastConnection, lastEvent *time.Time
	if s.pool.QueryRow(ctx, `SELECT max(connected_at),max(last_event_at) FROM asterisk_ami_session WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3`, h.CustomerID, h.EnvironmentID, h.AssetID).Scan(&lastConnection, &lastEvent) != nil {
		return v, ErrUnavailable
	}
	if lastConnection != nil {
		v.LastConnectedAt = *lastConnection
	}
	if lastEvent != nil {
		v.LastEventAt = *lastEvent
	}
	rows, e := s.pool.Query(ctx, `SELECT session_id::text,sequence,name,technology,endpoint,aor,address,state,rtt_ms,source_at,received_at,parser_version,coverage_gap,activity FROM asterisk_ami_event WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 ORDER BY received_at DESC,id DESC LIMIT 30`, h.CustomerID, h.EnvironmentID, h.AssetID)
	if e != nil {
		return v, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var r ami.Record
		var activityJSON []byte
		if rows.Scan(&r.SessionID, &r.Sequence, &r.Name, &r.Technology, &r.Endpoint, &r.AOR, &r.Address, &r.State, &r.RTT, &r.SourceAt, &r.ReceivedAt, &r.ParserVersion, &r.Gap, &activityJSON) != nil {
			return v, ErrUnavailable
		}
		if json.Unmarshal(activityJSON, &r.Activity) != nil {
			return v, ErrUnavailable
		}
		v.Events = append(v.Events, r)
	}
	if rows.Err() != nil {
		return v, ErrUnavailable
	}
	rows.Close()
	transitions, e := s.pool.Query(ctx, `SELECT t.state,t.reason,t.at,t.coverage_gap,t.dropped FROM asterisk_ami_transition t JOIN asterisk_ami_session s ON s.id=t.session_id WHERE s.customer_id=$1 AND s.environment_id=$2 AND s.asset_id=$3 ORDER BY t.id DESC LIMIT 20`, h.CustomerID, h.EnvironmentID, h.AssetID)
	if e != nil {
		return v, ErrUnavailable
	}
	defer transitions.Close()
	for transitions.Next() {
		var tr ami.Transition
		if transitions.Scan(&tr.State, &tr.Reason, &tr.At, &tr.Gap, &tr.Dropped) != nil {
			return v, ErrUnavailable
		}
		v.Transitions = append(v.Transitions, tr)
	}
	return v, transitions.Err()
}

var _ ami.Repository = (*Store)(nil)
