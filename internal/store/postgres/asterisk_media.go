package postgres

import (
	"context"
	"encoding/json"
	"noc-workbench/internal/collection"
	ast "noc-workbench/internal/integrations/asterisk"
	ami "noc-workbench/internal/integrations/asteriskami"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
	"time"
)

// MediaHistory returns a bounded scoped journal. Freshness and channel joins
// are evaluated independently using the current reconciled activity view.
func (s *Store) MediaHistory(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target) ([]ami.MediaRecord, bool, error) {
	if collectionAccess(p, h) != nil || h.AssetID != t.AssetID {
		return nil, false, workspace.ErrDenied
	}
	var exists bool
	if s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM connection_profile WHERE id=$1 AND customer_id=$2 AND environment_id=$3 AND asset_id=$4 AND endpoint_id=$5)`, t.ProfileID, h.CustomerID, h.EnvironmentID, h.AssetID, t.EndpointID).Scan(&exists) != nil || !exists {
		return nil, false, workspace.ErrDenied
	}
	allowed := s.IntegrationAllowed(ctx, p, t, "asterisk_media") == nil && s.IntegrationAllowed(ctx, p, t, "asterisk_activity") == nil
	rows, e := s.pool.Query(ctx, `SELECT profile_revision,session_id::text,sequence,received_at,source_at,coverage_gap,media_runtime,media_channel,media FROM asterisk_ami_event WHERE customer_id=$1 AND environment_id=$2 AND asset_id=$3 AND profile_id=$4 AND name IN ('RTCPReceived','RTCPSent') ORDER BY received_at DESC,id DESC LIMIT 100`, h.CustomerID, h.EnvironmentID, h.AssetID, t.ProfileID)
	if e != nil {
		return nil, allowed, ErrUnavailable
	}
	defer rows.Close()
	var out []ami.MediaRecord
	for rows.Next() {
		var r ami.MediaRecord
		var b []byte
		if rows.Scan(&r.ProfileRevision, &r.Session, &r.Sequence, &r.At, &r.SourceAt, &r.Gap, &r.Runtime, &r.Channel, &b) != nil || json.Unmarshal(b, &r.Report) != nil || !r.Report.Valid() {
			return nil, allowed, ErrUnavailable
		}
		out = append(out, r)
	}
	return out, allowed, rows.Err()
}

// MediaCLIView returns only the most recent attempt. A failed attempt never
// borrows an older successful row set and labels it current.
func (s *Store) MediaCLIView(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, now time.Time) (ast.CLIStatsView, error) {
	var v ast.CLIStatsView
	if collectionAccess(p, h) != nil || h.AssetID != t.AssetID {
		return v, workspace.ErrDenied
	}
	run, e := s.LatestCollectorAttempt(ctx, p, h, "asterisk.media")
	if e != nil || run == nil {
		return v, e
	}
	if run.Target != t {
		return v, nil
	}
	c := run.Results[0]
	v.At = c.EndedAt
	v.Outcome = c.Outcome
	if c.Outcome != "success" {
		return v, nil
	}
	rows, e := s.pool.Query(ctx, `SELECT resource,text_value FROM observation WHERE run_id=$1 AND collector_id='asterisk.media' AND key='asterisk.media.cli' ORDER BY resource LIMIT 259`, run.ID)
	if e != nil {
		return v, ErrUnavailable
	}
	defer rows.Close()
	sources := map[string]int{}
	for rows.Next() {
		var resource, text string
		if rows.Scan(&resource, &text) != nil {
			return v, ErrUnavailable
		}
		parts := strings.Split(resource, "/")
		if len(parts) == 1 {
			var source ast.CLIStats
			if json.Unmarshal([]byte(text), &source) != nil || (source.Source != "sip" && source.Source != "pjsip") || source.Source != resource {
				return v, ErrUnavailable
			}
			sources[resource] = len(v.Sources)
			v.Sources = append(v.Sources, source)
		} else if len(parts) == 2 {
			idx, ok := sources[parts[0]]
			if !ok {
				return v, ErrUnavailable
			}
			var row ast.CLIStatsRow
			if json.Unmarshal([]byte(text), &row) != nil {
				return v, ErrUnavailable
			}
			v.Sources[idx].Rows = append(v.Sources[idx].Rows, row)
		} else {
			return v, ErrUnavailable
		}
	}
	if rows.Err() != nil {
		return v, ErrUnavailable
	}
	age := now.Sub(v.At)
	v.Current = age >= 0 && age < 180*time.Second && s.IntegrationAllowed(ctx, p, t, "asterisk_media") == nil && s.IntegrationAllowed(ctx, p, t, "asterisk_activity") == nil
	return v, nil
}
