package web

import (
	"net/http"
	"strconv"

	"noc-workbench/internal/inventory"
	"noc-workbench/internal/scheduler"
)

type schedulingData struct {
	Available  bool
	Status     scheduler.Status
	Profile    scheduler.Profile
	Exists     bool
	Collectors []string
}

func (s *Server) schedulerPage(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	d.Active = "scheduler"
	if s.options.Scheduler == nil {
		http.Error(w, "Scheduling unavailable", 503)
		return
	}
	if r.Method == http.MethodPost {
		c := scheduler.Control{Action: r.PostForm.Get("action"), Kind: r.PostForm.Get("scope"), ID: r.PostForm.Get("scope_id")}
		switch r.PostForm.Get("action") {
		case "pause":
			c.Paused = true
		case "resume":
		case "stop":
			if c.Kind != "global" {
				http.Error(w, "invalid scope", 400)
				return
			}
			c.Stopped = true
		case "release":
			if c.Kind != "global" {
				http.Error(w, "invalid scope", 400)
				return
			}
		default:
			http.Error(w, "invalid action", 400)
			return
		}
		if e := s.options.Scheduler.Control(r.Context(), operatorPrincipal(), c); e != nil {
			http.Error(w, "Scheduling control rejected or storage unavailable", 409)
			return
		}
		http.Redirect(w, r, "/scheduler", 303)
		return
	}
	status, e := s.options.Scheduler.Status(r.Context(), operatorPrincipal())
	if e != nil {
		http.Error(w, "Scheduling storage unavailable", 503)
		return
	}
	d.Scheduling = schedulingData{Available: true, Status: status}
	s.render(w, "scheduler.html", d)
}
func (s *Server) assetSchedule(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	if s.options.Scheduler == nil || s.options.Enrollment == nil {
		http.Error(w, "Scheduling unavailable", 503)
		return
	}
	customer, environment, asset := r.PathValue("customer"), r.PathValue("environment"), r.PathValue("asset")
	if _, e := s.inventory.Environment(r.Context(), customer, environment); e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	repo, ok := s.store.(inventory.TopologyRepository)
	if !ok {
		http.Error(w, "Scheduling unavailable", 503)
		return
	}
	if _, e := repo.GetAsset(r.Context(), environment, asset); e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	snap, e := s.options.Scheduler.Status(r.Context(), operatorPrincipal())
	if e != nil {
		http.Error(w, "Scheduling storage unavailable", 503)
		return
	}
	var p scheduler.Profile
	for _, x := range snap.Profiles {
		if x.AssetID == asset && x.EnvironmentID == environment && x.CustomerID == customer {
			p = x
			break
		}
	}
	action := r.PostForm.Get("action")
	if action == "save" {
		rev, err := strconv.ParseInt(r.PostForm.Get("schedule_revision"), 10, 64)
		if err != nil {
			http.Error(w, "invalid revision", 400)
			return
		}
		if p.Revision != rev {
			http.Error(w, "Schedule changed; reload before editing", 409)
			return
		}
		records, err := s.options.Enrollment.List(r.Context(), operatorPrincipal(), customer, environment, asset)
		if err != nil {
			http.Error(w, "Enrollment unavailable", 409)
			return
		}
		found := false
		for _, rec := range records {
			if rec.ID == r.PostForm.Get("profile") && strconv.FormatInt(rec.Revision, 10) == r.PostForm.Get("revision") && rec.State == "connection_verified" {
				p.Target = rec.Target()
				found = true
			}
		}
		if !found {
			http.Error(w, "Review verified SSH enrollment before enabling scheduling", 409)
			return
		}
		p.CustomerID = customer
		p.EnvironmentID = environment
		p.AssetID = asset
		p.Collectors = r.PostForm["collectors"]
		p.Interval, _ = strconv.Atoi(r.PostForm.Get("interval"))
		p.Budget = 20
		p.Authorized = r.PostForm.Get("authorize") == "yes"
		p.Enabled = p.Authorized
		p.Paused = false
	} else {
		if p.ID == "" {
			http.Error(w, "Schedule not found", 404)
			return
		}
		rev, _ := strconv.ParseInt(r.PostForm.Get("schedule_revision"), 10, 64)
		if rev != p.Revision {
			http.Error(w, "Schedule changed; reload", 409)
			return
		}
		switch action {
		case "pause":
			p.Paused = true
		case "resume":
			p.Paused = false
		case "disable":
			p.Enabled = false
			p.Authorized = false
		default:
			http.Error(w, "invalid action", 400)
			return
		}
	}
	if _, e = s.options.Scheduler.Save(r.Context(), operatorPrincipal(), p); e != nil {
		http.Error(w, "Schedule rejected: verify interval, collector selection, current enrollment and authorization", 409)
		return
	}
	http.Redirect(w, r, "/customers/"+customer+"/environments/"+environment+"/assets/"+asset+"/linux", 303)
}
