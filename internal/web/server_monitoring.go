package web

import (
	"context"
	"net/http"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/services"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/health"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"slices"
	"strconv"
)

type runtimeRow struct {
	Reading            services.Reading
	Evidence           collection.Evidence
	Freshness, Quality string
}
type runtimeData struct {
	Available, Enabled bool
	Status             string
	Profile            scheduler.Profile
	Rows               []runtimeRow
	Attempt            *collection.Run
}

func (s *Server) serverRuntime(r *http.Request, v workspace.ServerDetail, in health.Input, out health.Evaluation, records []connections.Record) (runtimeData, error) {
	d := runtimeData{Available: s.options.Scheduler != nil && s.options.Enrollment != nil, Status: "Monitoring disabled"}
	if s.options.Scheduler != nil {
		snap, e := s.options.Scheduler.Status(r.Context(), operatorPrincipal())
		if e != nil {
			return d, e
		}
		for _, p := range snap.Profiles {
			if p.AssetID == v.ID && p.CustomerID == v.CustomerID && p.EnvironmentID == v.EnvironmentID && p.CollectionSource.ID == "" {
				d.Profile = p
				break
			}
		}
		p := d.Profile
		live := false
		for _, rec := range records {
			if rec.CustomerID == v.CustomerID && rec.EnvironmentID == v.EnvironmentID && rec.AssetID == v.ID && rec.State == "connection_verified" && rec.Target() == p.Target {
				live = true
			}
		}
		d.Enabled = live && p.Enabled && p.Authorized && p.Eligible && !p.Paused && !snap.Paused && !snap.Stopped && slices.Contains(p.Collectors, services.Collector)
		if d.Enabled {
			d.Status = "Monitoring enabled"
		} else if p.Enabled {
			d.Status = "Monitoring paused, blocked or runtime profile not enabled"
		}
	}
	if repo, ok := s.store.(interface {
		RuntimeAttempt(context.Context, workspace.Principal, collection.HistoryScope) (*collection.Run, error)
	}); ok {
		var e error
		d.Attempt, e = repo.RuntimeAttempt(r.Context(), operatorPrincipal(), in.Scope)
		if e != nil {
			return d, e
		}
	}
	for _, reading := range out.Readings {
		if reading.Evidence.Key != services.Key {
			continue
		}
		ev := reading.Evidence
		sig, e := services.Decode(ev)
		if e != nil {
			continue
		}
		classified := services.Classify(sig)
		classified.Current = "Unknown"
		authorized := in.Active && in.Trusted && in.Authority[ev.ProfileID] == ev.ProfileVersion && d.Profile.Target.ProfileID == ev.ProfileID && d.Profile.Target.ProfileVersion == ev.ProfileVersion
		if d.Enabled && authorized && reading.Freshness == "fresh" && reading.Quality == "valid" {
			classified.Current = classified.Runtime
		}
		d.Rows = append(d.Rows, runtimeRow{classified, ev, reading.Freshness, reading.Quality})
	}
	return d, nil
}

// Explicit opt-in configures the existing one-per-server profile. It preserves
// existing collector choices, uses the existing admission gate and never runs SSH.
func (s *Server) serverMonitoring(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(workspace.ServerRepository)
	authority, has := s.store.(interface {
		SetIntegration(context.Context, workspace.Principal, collection.HistoryScope, sshcli.Target, string, bool) error
	})
	if !ok || !has || s.options.Enrollment == nil || s.options.Scheduler == nil {
		http.Error(w, "Monitoring unavailable", 503)
		return
	}
	scope, e := (workspace.LocalOperatorPolicy{}).Scope(operatorPrincipal(), workspace.Search)
	if e != nil {
		http.Error(w, "Forbidden", 403)
		return
	}
	v, e := repo.ServerDetails(r.Context(), scope, r.PathValue("asset"))
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	snap, e := s.options.Scheduler.Status(r.Context(), operatorPrincipal())
	if e != nil {
		http.Error(w, "Scheduler unavailable", 503)
		return
	}
	p := scheduler.Profile{CustomerID: v.CustomerID, EnvironmentID: v.EnvironmentID, AssetID: v.ID}
	for _, x := range snap.Profiles {
		if x.AssetID == v.ID && x.CustomerID == v.CustomerID && x.EnvironmentID == v.EnvironmentID && x.CollectionSource.ID == "" {
			p = x
			break
		}
	}
	rev, e := strconv.ParseInt(r.PostForm.Get("schedule_revision"), 10, 64)
	if e != nil || rev != p.Revision {
		http.Error(w, "Schedule changed; reload before editing", 409)
		return
	}
	switch r.PostForm.Get("action") {
	case "disable":
		if p.ID == "" {
			http.Error(w, "No monitoring schedule", 409)
			return
		}
		p.Enabled = false
		p.Authorized = false
	case "enable":
		paused := p.Paused || snap.Paused || snap.Stopped
		for _, control := range snap.Controls {
			if !control.Paused {
				continue
			}
			if (control.Kind == "customer" && control.ID == v.CustomerID) || (control.Kind == "asset" && control.ID == v.ID) {
				paused = true
			}
			for _, cluster := range v.Clusters {
				if control.Kind == "cluster" && control.ID == cluster.ID {
					paused = true
				}
			}
		}
		if paused {
			http.Error(w, "Resume monitoring using the existing scheduler controls before enabling runtime collection", 409)
			return
		}
		if r.PostForm.Get("authorize") != "yes" {
			http.Error(w, "Explicit monitoring authorization required", 400)
			return
		}
		records, e := s.options.Enrollment.List(r.Context(), operatorPrincipal(), v.CustomerID, v.EnvironmentID, v.ID)
		if e != nil {
			s.inventoryFailure(w, d, e)
			return
		}
		found := false
		for _, rec := range records {
			if rec.ID == r.PostForm.Get("profile") && rec.EndpointID == r.PostForm.Get("endpoint") && strconv.FormatInt(rec.Revision, 10) == r.PostForm.Get("revision") && rec.State == "connection_verified" {
				p.Target = rec.Target()
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "Verified SSH enrollment changed or is unavailable", 409)
			return
		}
		if !slices.Contains(p.Collectors, services.Collector) {
			p.Collectors = append(p.Collectors, services.Collector)
		}
		p.Interval = 60
		p.Budget = 20
		p.Enabled = true
		p.Authorized = true
		if scheduler.Validate(p) != nil {
			http.Error(w, "Existing profile cannot include runtime collection", 409)
			return
		}
		h := collection.HistoryScope{CustomerID: v.CustomerID, EnvironmentID: v.EnvironmentID, AssetID: v.ID}
		if e = authority.SetIntegration(r.Context(), operatorPrincipal(), h, p.Target, "runtime_services", true); e != nil {
			s.inventoryFailure(w, d, e)
			return
		}
	default:
		http.Error(w, "Invalid monitoring action", 400)
		return
	}
	if _, e = s.options.Scheduler.Save(r.Context(), operatorPrincipal(), p); e != nil {
		http.Error(w, "Monitoring schedule was not saved; review current authorization and schedule", 409)
		return
	}
	http.Redirect(w, r, "/servers/"+v.ID, 303)
}
