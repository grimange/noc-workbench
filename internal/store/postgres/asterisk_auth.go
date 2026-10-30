package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	auth "noc-workbench/internal/integrations/asteriskauth"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

func (s *Store) AuthCursors(ctx context.Context, p workspace.Principal, t sshcli.Target) (map[string]auth.Cursor, error) {
	if err := s.IntegrationAllowed(ctx, p, t, "asterisk_auth"); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT source,identity,byte_offset,generation,anchor,coverage_gap,discard_line FROM asterisk_auth_cursor WHERE profile_id=$1 AND asset_id=$2 AND endpoint_id=$3`, t.ProfileID, t.AssetID, t.EndpointID)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	out := map[string]auth.Cursor{}
	for rows.Next() {
		var source string
		var c auth.Cursor
		if rows.Scan(&source, &c.Identity, &c.Offset, &c.Generation, &c.Anchor, &c.Gap, &c.Discard) != nil {
			return nil, ErrUnavailable
		}
		out[source] = c
	}
	return out, rows.Err()
}
func persistAuth(ctx context.Context, tx pgx.Tx, p workspace.Principal, r collection.Run, c collection.Result) error {
	if err := integrationAllowed(ctx, tx, p, r.Target, "asterisk"); err != nil {
		return err
	}
	if err := integrationAllowed(ctx, tx, p, r.Target, "asterisk_auth"); err != nil {
		return err
	}
	if c.CommandID == "asterisk.auth.helper.v1" {
		if err := integrationAllowed(ctx, tx, p, r.Target, "asterisk_auth_helper"); err != nil {
			return err
		}
	}
	if len(c.Observations) == 0 {
		return nil
	} // Transport errors remain in canonical attempts.
	first := c.Observations[0]
	if first.Key != auth.Key || first.Value.Kind != "text" {
		return collection.ErrPersistence
	}
	b, err := auth.Decode([]byte(first.Value.Text))
	if err != nil || len(b.Events) != 0 {
		return collection.ErrPersistence
	}
	for i, o := range c.Observations[1:] {
		var event auth.Event
		if o.Key != "asterisk.auth.event" || o.Resource != fmt.Sprintf("%s/%03d", b.Source, i) || o.Value.Kind != "text" || strictAuthEvent([]byte(o.Value.Text), &event) != nil {
			return collection.ErrPersistence
		}
		b.Events = append(b.Events, event)
	}
	if first.Resource != b.Source || !auth.ValidBatch(b) {
		return collection.ErrPersistence
	}
	var customer, environment string
	if err = tx.QueryRow(ctx, `SELECT customer_id::text,environment_id::text FROM collection_run WHERE id=$1`, r.ID).Scan(&customer, &environment); err != nil {
		return persistenceError("authentication", err)
	}
	if b.Source != "" {
		var old auth.Cursor
		err = tx.QueryRow(ctx, `SELECT identity,byte_offset,generation,anchor,coverage_gap,discard_line FROM asterisk_auth_cursor WHERE profile_id=$1 AND source=$2 FOR UPDATE`, r.Target.ProfileID, b.Source).Scan(&old.Identity, &old.Offset, &old.Generation, &old.Anchor, &old.Gap, &old.Discard)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return persistenceError("authentication", err)
		}
		if old != b.Before {
			return collection.ErrPersistence
		}
		// Replays after commit with a stale cursor roll back; unique event identities
		// are a second barrier. Interrupted pre-commit batches can be retried intact.
		for _, v := range b.Events {
			if _, err = tx.Exec(ctx, `INSERT INTO asterisk_auth_event(customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,source,identity,generation,byte_position,event_at,event_type,account,observed_ip,observed_port,technology,severity,reason,parser_version,run_id,coverage_gap) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,nullif($14,'')::inet,nullif($15,0),$16,$17,$18,'1',$19,$20) ON CONFLICT(asset_id,endpoint_id,source,identity,generation,byte_position,event_at) DO NOTHING`, customer, environment, r.Target.AssetID, r.Target.EndpointID, r.Target.ProfileID, r.Target.ProfileVersion, b.Source, b.After.Identity, b.After.Generation, v.Position, v.At, v.Type, v.Account, v.IP, v.Port, v.Technology, v.Severity, v.Reason, r.ID, b.After.Gap); err != nil {
				return persistenceError("authentication", err)
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO asterisk_auth_cursor(customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,source,identity,generation,byte_offset,anchor,coverage_gap,discard_line) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(profile_id,source) DO UPDATE SET profile_revision=excluded.profile_revision,identity=excluded.identity,generation=excluded.generation,byte_offset=excluded.byte_offset,anchor=excluded.anchor,coverage_gap=excluded.coverage_gap,discard_line=excluded.discard_line,updated_at=clock_timestamp()`, customer, environment, r.Target.AssetID, r.Target.EndpointID, r.Target.ProfileID, r.Target.ProfileVersion, b.Source, b.After.Identity, b.After.Generation, b.After.Offset, b.After.Anchor, b.After.Gap, b.After.Discard)
		if err != nil {
			return persistenceError("authentication", err)
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO asterisk_auth_status(customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,source,status,checked_at,security_category,rejected_lines) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(profile_id,profile_revision) DO UPDATE SET source=excluded.source,status=excluded.status,checked_at=excluded.checked_at,security_category=excluded.security_category,rejected_lines=excluded.rejected_lines`, customer, environment, r.Target.AssetID, r.Target.EndpointID, r.Target.ProfileID, r.Target.ProfileVersion, b.Source, b.Status, b.InspectedAt, b.Security, b.Rejected)
	if err != nil {
		return persistenceError("authentication_status", err)
	}
	return nil
}

func (s *Store) AuthEvents(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, f auth.Filter, now time.Time) (auth.View, error) {
	v := auth.View{Status: "not_authorized", Filter: f}
	if collectionAccess(p, h) != nil || h.AssetID != t.AssetID {
		return v, workspace.ErrDenied
	}
	var exists bool
	if s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM connection_profile WHERE id=$1 AND customer_id=$2 AND environment_id=$3 AND asset_id=$4 AND endpoint_id=$5)`, t.ProfileID, h.CustomerID, h.EnvironmentID, h.AssetID, t.EndpointID).Scan(&exists) != nil || !exists {
		return v, workspace.ErrDenied
	}
	if f.Minutes != 5 && f.Minutes != 15 && f.Minutes != 60 {
		f.Minutes = 15
		v.Filter = f
	}
	err := s.pool.QueryRow(ctx, `SELECT status,source,checked_at,security_category,rejected_lines FROM asterisk_auth_status WHERE profile_id=$1 AND profile_revision=$2 AND customer_id=$3 AND environment_id=$4 AND asset_id=$5`, t.ProfileID, t.ProfileVersion, h.CustomerID, h.EnvironmentID, h.AssetID).Scan(&v.Status, &v.Source, &v.CheckedAt, &v.Security, &v.Rejected)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return v, ErrUnavailable
	}
	allowed := s.IntegrationAllowed(ctx, p, t, "asterisk_auth") == nil && s.IntegrationAllowed(ctx, p, t, "asterisk") == nil
	v.Current = allowed && (v.Status == "current" || v.Status == "current_with_gap") && !now.Before(v.CheckedAt) && now.Sub(v.CheckedAt) < 180*time.Second
	v.Gap = strings.HasSuffix(v.Status, "_with_gap")
	if attempt, err := s.LatestCollectorAttempt(ctx, p, h, auth.Collector); err != nil {
		return v, err
	} else if attempt != nil && attempt.StartedAt.After(v.CheckedAt) {
		for _, result := range attempt.Results {
			if result.CollectorID == auth.Collector && result.Outcome == "failed" {
				v.Current = false
				v.Status = "transport_unavailable"
			}
		}
	}
	if !allowed {
		v.Status = "not_authorized"
	} else if !v.CheckedAt.IsZero() && now.Sub(v.CheckedAt) >= 180*time.Second {
		v.Status = "stale"
	}
	// Never derive totals from a bounded event list. Indexed SQL computes exact
	// retained-window totals, including separate 5/15/60 minute counts.
	var latest *time.Time
	err = s.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE event_at >= $4::timestamptz-interval '5 minutes'),count(*) FILTER(WHERE event_at >= $4::timestamptz-interval '15 minutes'),count(*),count(DISTINCT observed_ip),max(event_at) FROM asterisk_auth_event WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 AND event_at >= $4::timestamptz-interval '1 hour' AND event_at <= $4`, h.CustomerID, h.EnvironmentID, h.AssetID, now).Scan(&v.Failures5, &v.Failures15, &v.FailuresHour, &v.Sources, &latest)
	if err != nil {
		return v, ErrUnavailable
	}
	if err = s.pool.QueryRow(ctx, `SELECT max(event_at) FROM asterisk_auth_event WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 AND event_at<=$4`, h.CustomerID, h.EnvironmentID, h.AssetID, now).Scan(&latest); err != nil {
		return v, ErrUnavailable
	}
	if latest != nil {
		v.Latest = *latest
	}
	rows, err := s.pool.Query(ctx, `SELECT account,coalesce(host(observed_ip),''),event_type,count(*),min(event_at),max(event_at),count(*) FILTER(WHERE event_at >= $4::timestamptz-interval '5 minutes'),count(*) FILTER(WHERE event_at >= $4::timestamptz-interval '15 minutes') FROM asterisk_auth_event WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 AND event_at >= $4::timestamptz-make_interval(mins=>$5) AND event_at <= $4 AND ($6='' OR event_type=$6) AND ($7='' OR account=$7) AND ($8='' OR host(observed_ip)=$8) GROUP BY account,observed_ip,event_type,CASE WHEN account='' OR observed_ip IS NULL THEN id ELSE 0 END ORDER BY max(event_at) DESC LIMIT 101`, h.CustomerID, h.EnvironmentID, h.AssetID, now, f.Minutes, f.Type, f.Account, f.IP)
	if err != nil {
		return v, ErrUnavailable
	}
	for rows.Next() {
		var g auth.Group
		if rows.Scan(&g.Account, &g.IP, &g.Type, &g.Count, &g.First, &g.Last, &g.Count5, &g.Count15) != nil {
			rows.Close()
			return v, ErrUnavailable
		}
		g.Repeated = g.Count5 >= 5
		v.Groups = append(v.Groups, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, ErrUnavailable
	}
	if len(v.Groups) > 100 {
		v.Groups = v.Groups[:100]
		v.Limited = true
	}
	rows, err = s.pool.Query(ctx, `SELECT byte_position,event_at,event_type,account,coalesce(host(observed_ip),''),coalesce(observed_port,0),technology,severity,reason,source,identity,generation,parser_version,ingested_at FROM asterisk_auth_event WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 AND event_at >= $4::timestamptz-make_interval(mins=>$5) AND event_at <= $4 AND ($6='' OR event_type=$6) AND ($7='' OR account=$7) AND ($8='' OR host(observed_ip)=$8) ORDER BY event_at DESC,id DESC LIMIT 50`, h.CustomerID, h.EnvironmentID, h.AssetID, now, f.Minutes, f.Type, f.Account, f.IP)
	if err != nil {
		return v, ErrUnavailable
	}
	for rows.Next() {
		var e auth.EventRecord
		if rows.Scan(&e.Position, &e.At, &e.Type, &e.Account, &e.IP, &e.Port, &e.Technology, &e.Severity, &e.Reason, &e.Source, &e.Identity, &e.Generation, &e.ParserVersion, &e.IngestedAt) != nil {
			rows.Close()
			return v, ErrUnavailable
		}
		v.Events = append(v.Events, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, ErrUnavailable
	}
	if allowed {
		v.Cursors, err = s.AuthCursors(ctx, p, t)
		if err != nil {
			return v, err
		}
	}
	return v, nil
}

func strictAuthEvent(raw []byte, event *auth.Event) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(event); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return collection.ErrPersistence
	}
	return nil
}
