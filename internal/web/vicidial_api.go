package web

import (
	"context"
	"errors"
	"net/http"
	"noc-workbench/internal/alerts"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"noc-workbench/internal/integrations/vicidialapi"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/workspace"
	"strconv"
	"time"
)

type apiConfigurationRepository interface {
	SourceConfiguration(context.Context, workspace.Principal, collection.Source) (collection.Source, error)
	SaveSourceConfiguration(context.Context, workspace.Principal, collection.Source) (collection.Source, error)
	SourceHistory(context.Context, workspace.Principal, collection.Source, time.Time) (collection.History, error)
	SourceEvaluation(context.Context, workspace.Principal, collection.Source, time.Time) (health.Input, error)
	SourceSeries(context.Context, workspace.Principal, collection.Source, string, time.Time, time.Time) (alerts.Series, error)
}
type apiData struct {
	Source     collection.Source
	History    collection.History
	Schedule   scheduler.Profile
	Cluster    inventory.Cluster
	Back       string
	Evaluation health.Evaluation
	Series     alerts.Series
	Hours, Key string
}

func (s *Server) vicidialAPI(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(apiConfigurationRepository)
	if !ok || s.options.VICIdialAPI == nil || s.options.Scheduler == nil {
		http.Error(w, "API integration unavailable", 503)
		return
	}
	topo, ok := s.store.(inventory.TopologyRepository)
	if !ok {
		http.Error(w, "Inventory unavailable", 503)
		return
	}
	var e error
	d.Customer, e = s.inventory.Customer(r.Context(), r.PathValue("customer"))
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	d.Environment, e = s.inventory.Environment(r.Context(), d.Customer.ID, r.PathValue("environment"))
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	d.API.Cluster, e = topo.GetCluster(r.Context(), d.Environment.ID, r.PathValue("cluster"))
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	v := collection.Source{CustomerID: d.Customer.ID, EnvironmentID: d.Environment.ID, ClusterID: d.API.Cluster.ID}
	current, e := repo.SourceConfiguration(r.Context(), operatorPrincipal(), v)
	if e != nil && !errors.Is(e, inventory.ErrNotFound) {
		s.inventoryFailure(w, d, e)
		return
	}
	if e == nil {
		v = current
	}
	d.Action = "/customers/" + d.Customer.ID + "/environments/" + d.Environment.ID + "/clusters/" + d.API.Cluster.ID + "/vicidial/api"
	d.API.Back = d.Action[:len(d.Action)-4]
	snap, e := s.options.Scheduler.Status(r.Context(), operatorPrincipal())
	if e != nil {
		http.Error(w, "Scheduling storage unavailable", 503)
		return
	}
	var profile scheduler.Profile
	for _, p := range snap.Profiles {
		if v.ID != "" && p.CollectionSource.ID == v.ID {
			profile = p
			break
		}
	}
	if r.Method == http.MethodPost {
		rev, err := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
		if err != nil || rev != v.Revision {
			http.Error(w, "Configuration changed; reload", 409)
			return
		}
		switch r.PostForm.Get("action") {
		case "configure":
			v.CredentialReference = r.PostForm.Get("credential_reference")
			v.Enabled = r.PostForm.Get("enabled") == "yes"
			_, e = repo.SaveSourceConfiguration(r.Context(), operatorPrincipal(), v)
		case "collect":
			if v.ID == "" {
				e = workspace.ErrDenied
			} else {
				_, e = s.options.VICIdialAPI.Collect(r.Context(), operatorPrincipal(), v.ID, v.Revision)
			}
		case "schedule", "pause", "resume", "disable":
			schedRev, err := strconv.ParseInt(r.PostForm.Get("schedule_revision"), 10, 64)
			if err != nil || schedRev != profile.Revision {
				http.Error(w, "Schedule changed; reload", 409)
				return
			}
			action := r.PostForm.Get("action")
			if action == "schedule" {
				profile.CustomerID = v.CustomerID
				profile.EnvironmentID = v.EnvironmentID
				profile.ClusterID = v.ClusterID
				profile.CollectionSource = v
				profile.Collectors = vicidialapi.CollectorIDs()
				profile.Budget = 20
				profile.Interval, _ = strconv.Atoi(r.PostForm.Get("interval"))
				profile.Authorized = r.PostForm.Get("authorize") == "yes"
				profile.Enabled = profile.Authorized
				profile.Paused = false
			} else if profile.ID == "" {
				e = scheduler.ErrInvalid
			} else {
				profile.Paused = action == "pause"
				if action == "disable" {
					profile.Enabled = false
					profile.Authorized = false
				}
			}
			if e == nil {
				_, e = s.options.Scheduler.Save(r.Context(), operatorPrincipal(), profile)
			}
		default:
			e = workspace.ErrDenied
		}
		if e != nil {
			http.Error(w, "API operation rejected or storage unavailable. Review current authorization, credential catalog and configuration revision.", 409)
			return
		}
		http.Redirect(w, r, d.Action, 303)
		return
	}
	d.API.Source = v
	d.API.Schedule = profile
	if v.ID != "" {
		d.API.History, e = repo.SourceHistory(r.Context(), operatorPrincipal(), v, time.Now().UTC())
		if e != nil {
			http.Error(w, "Evidence unavailable", 503)
			return
		}
	}
	if v.ID != "" {
		in, err := repo.SourceEvaluation(r.Context(), operatorPrincipal(), v, s.now().UTC())
		if err != nil {
			http.Error(w, "Evidence unavailable", 503)
			return
		}
		d.API.Evaluation, e = health.Evaluate(in)
		if e != nil {
			http.Error(w, "Evaluation unavailable", 503)
			return
		}
		hours := 24
		key := r.URL.Query().Get("key")
		if key == "" {
			key = "vicidial.agents.visible_logged_in_count"
		}
		if raw := r.URL.Query().Get("hours"); raw != "" {
			hours, _ = strconv.Atoi(raw)
		}
		if hours != 1 && hours != 6 && hours != 24 && hours != 168 {
			http.Error(w, "Select 1, 6, 24 or 168 hours", 400)
			return
		}
		at := s.now().UTC()
		d.API.Series, e = repo.SourceSeries(r.Context(), operatorPrincipal(), v, key, at.Add(-time.Duration(hours)*time.Hour), at)
		if e != nil {
			http.Error(w, "Unsupported metric or unavailable history", 400)
			return
		}
		d.API.Hours = strconv.Itoa(hours)
		d.API.Key = key
	}
	s.render(w, "vicidial_api.html", d)
}

// API events carry no credentials, agent rows or endpoint metadata. Reconnection
// always reconciles the current authorized PostgreSQL view, without API traffic.
func (s *Server) vicidialAPIEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(w, r); !ok {
		return
	}
	repo, ok := s.store.(apiConfigurationRepository)
	if !ok {
		http.Error(w, "Unavailable", 503)
		return
	}
	scope := collection.Source{CustomerID: r.PathValue("customer"), EnvironmentID: r.PathValue("environment"), ClusterID: r.PathValue("cluster")}
	v, e := repo.SourceConfiguration(r.Context(), operatorPrincipal(), scope)
	if e != nil {
		http.Error(w, "Scope unavailable", 403)
		return
	}
	s.reconcileEvents(w, r, func() ([32]byte, error) {
		current, e := repo.SourceConfiguration(r.Context(), operatorPrincipal(), scope)
		if e != nil {
			return [32]byte{}, e
		}
		if current.ID != v.ID {
			return [32]byte{}, workspace.ErrDenied
		}
		in, e := repo.SourceEvaluation(r.Context(), operatorPrincipal(), current, s.now().UTC())
		if e != nil {
			return [32]byte{}, e
		}
		return monitoringFingerprint(alerts.View{}, in)
	})
}
