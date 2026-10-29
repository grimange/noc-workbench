package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	ast "noc-workbench/internal/integrations/asterisk"
	activity "noc-workbench/internal/integrations/asteriskactivity"
	ami "noc-workbench/internal/integrations/asteriskami"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

// The same per-profile transaction lock serializes snapshots and event updates.
// Journal replay closes the interval between remote read and durable commit.
func loadActivity(ctx context.Context, tx pgx.Tx, profile string) (activity.State, error) {
	var s activity.State
	if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,37004))`, profile); e != nil {
		return s, e
	}
	var b []byte
	e := tx.QueryRow(ctx, `SELECT state FROM asterisk_activity_state WHERE profile_id=$1 FOR UPDATE`, profile).Scan(&b)
	if errors.Is(e, pgx.ErrNoRows) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	return s, activity.Decode(b, &s)
}
func saveActivity(ctx context.Context, tx pgx.Tx, h collection.HistoryScope, t sshcli.Target, s activity.State) error {
	s.Sort()
	b, e := json.Marshal(s)
	if e != nil || len(b) > 1024*1024 {
		return collection.ErrPersistence
	}
	_, e = tx.Exec(ctx, `INSERT INTO asterisk_activity_state(customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,state) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(profile_id) DO UPDATE SET profile_revision=excluded.profile_revision,state=excluded.state,updated_at=clock_timestamp()`, h.CustomerID, h.EnvironmentID, h.AssetID, t.EndpointID, t.ProfileID, t.ProfileVersion, b)
	return e
}
func persistActivity(ctx context.Context, tx pgx.Tx, p workspace.Principal, r collection.Run, c collection.Result) error {
	var h collection.HistoryScope
	if tx.QueryRow(ctx, `SELECT customer_id::text,environment_id::text,asset_id::text FROM connection_profile WHERE id=$1 AND revision=$2`, r.Target.ProfileID, r.Target.ProfileVersion).Scan(&h.CustomerID, &h.EnvironmentID, &h.AssetID) != nil {
		return workspace.ErrDenied
	}
	if e := integrationAllowed(ctx, tx, p, r.Target, "asterisk_activity"); e != nil {
		return e
	}
	state, e := loadActivity(ctx, tx, r.Target.ProfileID)
	if e != nil {
		return e
	}
	if c.Outcome != "success" {
		state.Invalidate("CLI snapshot failed or incomplete; previous activity retained")
		return saveActivity(ctx, tx, h, r.Target, state)
	}
	snapshot, e := ast.DecodeActivity(c.Observations)
	if e != nil {
		return collection.ErrPersistence
	}
	var session string
	var dropped int64
	e = tx.QueryRow(ctx, `SELECT s.id::text,s.dropped FROM asterisk_ami_session s JOIN asterisk_ami_grant g ON g.profile_id=s.profile_id AND g.enabled AND g.profile_revision=s.profile_revision AND g.credential_digest=s.credential_digest WHERE s.profile_id=$1 AND s.profile_revision=$2 AND s.state='connected' AND s.ended_at IS NULL AND s.connected_at<=$3 AND s.updated_at>=clock_timestamp()-interval '30 seconds'`, r.Target.ProfileID, r.Target.ProfileVersion, c.StartedAt).Scan(&session, &dropped)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	state.Reconcile(snapshot, session, c.StartedAt, c.EndedAt)
	if session == "" {
		state.Invalidate("Snapshot observed; connected event baseline not established")
	}
	if dropped > 0 {
		state.Invalidate("AMI queue overflow in this session; event coverage incomplete")
	}
	if session != "" {
		rows, e := tx.Query(ctx, `SELECT name,activity,source_at,received_at FROM asterisk_ami_event WHERE session_id=$1 AND received_at>=$2 AND name IN ('Newchannel','Newstate','Hangup','BridgeCreate','BridgeDestroy','BridgeEnter','BridgeLeave','MeetmeJoin','MeetmeLeave','ConfbridgeStart','ConfbridgeEnd','ConfbridgeJoin','ConfbridgeLeave') ORDER BY sequence LIMIT 2049`, session, c.StartedAt)
		if e != nil {
			return e
		}
		count := 0
		for rows.Next() {
			var name string
			var b []byte
			var at *time.Time
			var received time.Time
			if rows.Scan(&name, &b, &at, &received) != nil {
				rows.Close()
				return ErrUnavailable
			}
			if !activity.IsEvent(name) {
				continue
			}
			count++
			if count > 2048 {
				state.Invalidate("Event replay limit; new baseline required")
				break
			}
			var event activity.Event
			if activity.Decode(b, &event) != nil {
				rows.Close()
				return ErrUnavailable
			}
			source := time.Time{}
			if at != nil {
				source = *at
			}
			state.Apply(name, event, source, received)
			if !received.After(c.EndedAt) {
				state.Invalidate("Activity changed during snapshot; awaiting a stable reconciliation")
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	return saveActivity(ctx, tx, h, r.Target, state)
}
func applyActivityEvent(ctx context.Context, tx pgx.Tx, b ami.Binding, session string, e ami.Event, dropped int64) error {
	if !activity.IsEvent(e.Name) {
		return nil
	}
	if integrationAllowed(ctx, tx, workspace.Principal{ID: workspace.OperatorID}, b.Target, "asterisk_activity") != nil {
		return nil
	}
	state, err := loadActivity(ctx, tx, b.Target.ProfileID)
	if err != nil {
		return err
	}
	if state.Session != session {
		state.Invalidate("AMI session changed; current-state reconciliation required")
	}
	if dropped > 0 {
		state.Invalidate("AMI queue overflow; event coverage incomplete")
	}
	source := time.Time{}
	if e.SourceAt != nil {
		source = *e.SourceAt
	}
	state.Apply(e.Name, e.Activity, source, e.ReceivedAt)
	// An event can have waited in the bounded queue while a snapshot committed.
	if !state.Started.IsZero() && !e.ReceivedAt.Before(state.Started) && !e.ReceivedAt.After(state.Baseline) {
		state.Invalidate("Activity changed during snapshot; awaiting a stable reconciliation")
	}
	return saveActivity(ctx, tx, b.Scope, b.Target, state)
}
func (s *Store) ActivityView(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, now time.Time) (activity.View, error) {
	v := activity.View{}
	v.Reason = "Channel/conference monitoring not authorized or not observed"
	if collectionAccess(p, h) != nil || h.AssetID != t.AssetID {
		return v, workspace.ErrDenied
	}
	var exists bool
	if s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM connection_profile WHERE id=$1 AND customer_id=$2 AND environment_id=$3 AND asset_id=$4 AND endpoint_id=$5)`, t.ProfileID, h.CustomerID, h.EnvironmentID, t.AssetID, t.EndpointID).Scan(&exists) != nil || !exists {
		return v, workspace.ErrDenied
	}
	var data []byte
	e := s.pool.QueryRow(ctx, `SELECT a.state FROM asterisk_activity_state a JOIN connection_profile p ON p.id=a.profile_id AND p.customer_id=a.customer_id AND p.environment_id=a.environment_id AND p.asset_id=a.asset_id AND p.endpoint_id=a.endpoint_id WHERE a.customer_id=$1 AND a.environment_id=$2 AND a.asset_id=$3 AND a.profile_id=$4 AND a.endpoint_id=$5 AND a.profile_revision=$6`, h.CustomerID, h.EnvironmentID, h.AssetID, t.ProfileID, t.EndpointID, t.ProfileVersion).Scan(&data)
	if errors.Is(e, pgx.ErrNoRows) {
		return v, nil
	}
	if e != nil || activity.Decode(data, &v.State) != nil {
		return v, ErrUnavailable
	}
	v.Current = v.Complete && !v.Baseline.IsZero() && !now.Before(v.Baseline) && now.Sub(v.Baseline) < 180*time.Second && s.IntegrationAllowed(ctx, p, t, "asterisk_activity") == nil
	if !v.Current && v.Complete {
		v.Reason = "Snapshot evidence is stale or authorization is unavailable"
	}
	live, e := s.AMIView(ctx, p, h, t, now)
	if e != nil {
		return v, e
	}
	if !live.Current || live.Session.ID != v.Session || live.Session.Dropped > 0 {
		v.Current = false
		v.Reason = "AMI connection changed or interrupted; fresh reconciliation required"
	}
	for _, r := range live.Events {
		if activity.IsEvent(r.Name) {
			v.Recent = append(v.Recent, activity.History{Name: r.Name, Event: r.Activity, At: r.ReceivedAt, SourceAt: r.SourceAt, Session: r.SessionID})
		}
	}
	// A failed recent collection must not keep an older active count current.
	var failed bool
	e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collector_result c JOIN collection_run r ON r.id=c.run_id WHERE r.profile_id=$1 AND r.profile_revision=$2 AND c.collector_id='asterisk.activity' AND c.started_at>$3 AND c.outcome<>'success')`, t.ProfileID, t.ProfileVersion, v.Started).Scan(&failed)
	if e != nil {
		return v, ErrUnavailable
	}
	if failed {
		v.Current = false
		v.Reason = "Latest channel/conference snapshot failed"
	}
	return v, nil
}
