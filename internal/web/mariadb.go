package web

import (
	"context"
	"net/http"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"noc-workbench/internal/integrations/mariadb"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"slices"
	"strings"
	"time"
)

type mariaDBData struct {
	Authorized, Current                          bool
	State, Readiness, Replication, Role, Process string
	History                                      mariadb.History
	Sample                                       *mariadb.Sample
	Metrics                                      []mariadb.Metric
}

func mariaDBView(h mariadb.History, in health.Input, rt runtimeData, allowed bool) mariaDBData {
	d := mariaDBData{History: h, Authorized: allowed, State: "Unavailable", Readiness: "Unknown", Replication: "Unknown", Role: "Unknown", Process: "Unknown"}
	for _, r := range rt.Rows {
		if r.Reading.ID == "database" {
			d.Process = r.State
		}
	}
	if len(h.Attempt.Codes) > 0 {
		d.Readiness = strings.Join(h.Attempt.Codes, ", ")
	}
	if len(h.Samples) == 0 {
		return d
	}
	v := h.Samples[0]
	d.Sample = &v
	d.Metrics = v.Snapshot.Activity()
	d.Current = allowed && rt.Enabled && !rt.Paused && slices.Contains(rt.Profile.Collectors, mariadb.Collector) && in.Active && in.Trusted && in.Authority[v.ProfileID] == v.ProfileVersion && rt.Profile.Target.ProfileID == v.ProfileID && rt.Profile.Target.ProfileVersion == v.ProfileVersion && rt.Profile.Target.EndpointID == v.EndpointID && !in.At.Before(v.At) && !v.Received.After(in.At) && in.At.Before(v.At.Add(time.Duration(v.TTL)*time.Second)) && (!h.Attempt.At.After(v.At) || h.Attempt.Outcome == "partial") && h.Attempt.Outcome != "failed"
	if d.Current {
		d.State = "Current"
		d.Readiness = "Ready — authenticated connection and SELECT 1 succeeded"
		d.Role = v.Snapshot.Role()
		d.Replication = v.Snapshot.Replication
		if v.Snapshot.Replication == "ready" {
			d.Replication = "No local replica channels configured"
			if len(v.Snapshot.Channels) > 0 {
				d.Replication = "Configured replica channels — inspect each channel below"
			}
		}
	} else {
		d.State = "Historical / stale or monitoring unavailable"
		if d.Readiness == "Unknown" {
			d.Readiness = "Stale / unavailable"
		}
	}
	return d
}
func (s *Server) serverMariaDB(r *http.Request, in health.Input, rt runtimeData) (mariaDBData, error) {
	repo, ok := s.store.(interface {
		MariaDBHistory(context.Context, workspace.Principal, collection.HistoryScope) (mariadb.History, error)
	})
	if !ok {
		return mariaDBData{State: "Unavailable", Readiness: "Unknown", Replication: "Unknown", Role: "Unknown", Process: "Unknown"}, nil
	}
	h, e := repo.MariaDBHistory(r.Context(), operatorPrincipal(), in.Scope)
	if e != nil {
		return mariaDBData{}, e
	}
	allowed := false
	if a, ok := s.store.(interface {
		IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error
	}); ok {
		allowed = a.IntegrationAllowed(r.Context(), operatorPrincipal(), rt.Profile.Target, "mariadb") == nil
	}
	return mariaDBView(h, in, rt, allowed), nil
}
