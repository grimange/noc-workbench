package web

import (
	"net/http"
	"strconv"

	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/workspace"
)

type maintenanceData struct {
	Blockers                                        []string
	AssetPaused, ProfilePaused, CanPause, CanResume bool
	Revision                                        int64
}

func maintenance(v workspace.Server, p scheduler.Profile, snap scheduler.Status) maintenanceData {
	d := maintenanceData{Revision: p.Revision, ProfilePaused: p.OwnPaused}
	if snap.Paused {
		d.Blockers = append(d.Blockers, "Global scheduler pause")
	}
	if snap.Stopped {
		d.Blockers = append(d.Blockers, "Global emergency stop")
	}
	if p.OwnPaused {
		d.Blockers = append(d.Blockers, "Server profile pause")
	}
	for _, c := range snap.Controls {
		if !c.Paused {
			continue
		}
		switch c.Kind {
		case "asset":
			if c.ID == v.ID {
				d.AssetPaused = true
				d.Blockers = append(d.Blockers, "Server maintenance pause")
			}
		case "customer":
			if c.ID == v.CustomerID {
				d.Blockers = append(d.Blockers, "Customer-wide pause: "+v.Customer)
			}
		case "cluster":
			for _, cluster := range v.Clusters {
				if c.ID == cluster.ID {
					d.Blockers = append(d.Blockers, "Cluster-wide pause: "+cluster.Name)
				}
			}
		}
	}
	d.CanPause = p.ID != "" && !d.AssetPaused
	d.CanResume = d.AssetPaused || (p.ID != "" && p.OwnPaused && p.Enabled && p.Authorized)
	return d
}

// The contextual action cannot select another asset or any inherited scope. It
// never enables a profile, changes collectors, or grants enrollment authority.
func (s *Server) serverMaintenance(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	if s.options.Scheduler == nil {
		http.Error(w, "Scheduler unavailable", 503)
		return
	}
	repo, ok := s.store.(workspace.ServerRepository)
	if !ok {
		http.Error(w, "Server storage unavailable", 503)
		return
	}
	scope, e := (workspace.LocalOperatorPolicy{}).Scope(operatorPrincipal(), workspace.ScheduleManage)
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
	var p scheduler.Profile
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
	m := maintenance(v.Server, p, snap)
	switch r.PostForm.Get("action") {
	case "pause":
		if !m.CanPause {
			http.Error(w, "Server pause is unavailable or already applied", 409)
			return
		}
		e = s.options.Scheduler.Control(r.Context(), operatorPrincipal(), scheduler.Control{Action: "pause", Kind: "asset", ID: v.ID, Paused: true})
	case "resume":
		if !m.CanResume {
			http.Error(w, "No server-owned pause can be resumed here. Review the displayed blockers.", 409)
			return
		}
		// Resolve profile authority first. If rejected, leave the scoped pause in
		// place. A subsequent GET always reports remaining inherited blockers.
		if p.OwnPaused {
			if !p.Enabled || !p.Authorized {
				http.Error(w, "Monitoring authorization is required in connection settings", 409)
				return
			}
			p.Paused = false
			_, e = s.options.Scheduler.Save(r.Context(), operatorPrincipal(), p)
		}
		if e == nil && m.AssetPaused {
			e = s.options.Scheduler.Control(r.Context(), operatorPrincipal(), scheduler.Control{Action: "resume", Kind: "asset", ID: v.ID})
		}
	default:
		http.Error(w, "Invalid maintenance action", 400)
		return
	}
	if e != nil {
		http.Error(w, "Maintenance action was not completed. Reload to inspect remaining blockers and current authorization.", 409)
		return
	}
	http.Redirect(w, r, "/servers/"+v.ID+"?maintenance=saved", http.StatusSeeOther)
}
