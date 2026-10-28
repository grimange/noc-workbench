package web

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"time"

	"noc-workbench/internal/connections"
	"noc-workbench/internal/health"
	"noc-workbench/internal/integrations/vicidialdiscovery"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/workspace"
)

type consoleServer struct {
	workspace.Server
	Runtime   runtimeData
	Discovery vicidialdiscovery.Result
}
type consoleRepository interface {
	ServerEvidence(context.Context, workspace.Scope, []string, time.Time) ([]health.Input, []connections.Record, error)
}

func (s *Server) consoleServers(r *http.Request, scope workspace.Scope, servers []workspace.Server) ([]consoleServer, error) {
	out := make([]consoleServer, len(servers))
	for i, v := range servers {
		out[i] = consoleServer{Server: v, Runtime: runtimeData{Status: "Monitoring disabled", Summary: "Unknown — no runtime evidence", Freshness: "Unknown", Outcome: "Not attempted"}, Discovery: vicidialdiscovery.Unknown()}
	}
	repo, ok := s.store.(consoleRepository)
	if !ok || len(servers) == 0 {
		return out, nil
	}
	ids := []string{}
	for _, v := range servers {
		ids = append(ids, v.ID)
	}
	inputs, records, e := repo.ServerEvidence(r.Context(), scope, ids, s.now().UTC())
	if e != nil {
		return nil, e
	}
	live := map[string]bool{}
	if s.options.Enrollment != nil {
		live = s.options.Enrollment.CurrentCredentials(operatorPrincipal(), records, s.now().UTC())
	}
	snap := scheduler.Status{}
	if s.options.Scheduler != nil {
		snap, e = s.options.Scheduler.Status(r.Context(), operatorPrincipal())
		if e != nil {
			return nil, e
		}
	}
	byID := map[string]health.Input{}
	for _, in := range inputs {
		byID[in.Scope.AssetID] = in
	}
	for i, v := range out {
		in, ok := byID[v.ID]
		if !ok {
			continue
		}
		d := v.Runtime
		d.Available = s.options.Scheduler != nil && s.options.Enrollment != nil
		d.Attempt = in.LatestAttempt
		for _, p := range snap.Profiles {
			if p.AssetID == v.ID && p.CustomerID == v.CustomerID && p.EnvironmentID == v.EnvironmentID && p.CollectionSource.ID == "" {
				d.Profile = p
				break
			}
		}
		p := d.Profile
		in.IntervalSeconds = p.Interval
		for _, rec := range records {
			if rec.AssetID == v.ID && rec.Target() == p.Target && live[rec.ID] && p.Enabled && p.Authorized && p.Eligible && !p.Paused && !snap.Paused && !snap.Stopped {
				for _, c := range p.Collectors {
					if c == "linux.services" {
						d.Enabled = true
					}
				}
			}
		}
		if d.Enabled {
			d.Status = "Monitoring enabled"
		} else if p.Enabled {
			d.Status = "Monitoring paused or blocked"
		}
		evaluated, e := health.Evaluate(in)
		if e != nil {
			return nil, e
		}
		out[i].Runtime = runtimeReadings(d, in, evaluated)
		for _, reading := range evaluated.Readings {
			if reading.Evidence.Key == vicidialdiscovery.Key {
				ev := reading.Evidence
				out[i].Discovery = vicidialdiscovery.Evaluate(ev, in.At, reading.Freshness, in.Active && in.Trusted && in.Authority[ev.ProfileID] == ev.ProfileVersion)
			}
		}
	}
	return out, nil
}

// Notifications share the accepted bounded, session-revalidated SSE delivery.
// Fingerprints contain rendered state, never advancing evaluation timestamps.
func (s *Server) consoleEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(w, r); !ok {
		return
	}
	scope, e := (workspace.LocalOperatorPolicy{}).Scope(operatorPrincipal(), workspace.Search)
	if e != nil {
		http.Error(w, "Forbidden", 403)
		return
	}
	repo, ok := s.store.(workspace.ServerRepository)
	if !ok {
		http.Error(w, "Unavailable", 503)
		return
	}
	q, e := workspace.Query(r.URL.Query().Get("q"))
	if e != nil {
		http.Error(w, "Invalid search", 400)
		return
	}
	offset, e := consoleOffset(r)
	if e != nil {
		http.Error(w, "Invalid page", 400)
		return
	}
	id := r.PathValue("asset")
	if id != "" {
		if _, err := repo.ServerDetails(r.Context(), scope, id); err != nil {
			http.Error(w, "Server unavailable", 404)
			return
		}
	}
	s.reconcileEvents(w, r, func() ([32]byte, error) {
		var servers []workspace.Server
		if id != "" {
			v, e := repo.ServerDetails(r.Context(), scope, id)
			if e != nil {
				return [32]byte{}, e
			}
			servers = []workspace.Server{v.Server}
		} else {
			var e error
			servers, _, e = repo.Servers(r.Context(), scope, q, offset)
			if e != nil {
				return [32]byte{}, e
			}
		}
		rows, e := s.consoleServers(r, scope, servers)
		if e != nil {
			return [32]byte{}, e
		}
		// Drop continuously advancing counters; persisted IDs/outcomes, eligibility
		// and evaluated freshness still trigger reconciliation at state boundaries.
		for i := range rows {
			rows[i].Runtime.Profile.LagSeconds = 0
			for j := range rows[i].Runtime.Rows {
				rows[i].Runtime.Rows[j].AgeSeconds = 0
			}
		}
		b, e := json.Marshal(rows)
		return sha256.Sum256(b), e
	})
}
