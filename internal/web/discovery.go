package web

import (
	"net/http"
	"strconv"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/inventory"
)

type discoverySnapshot struct {
	Profile   string
	Run       collection.Run
	Suspended bool
}
type discoveryData struct {
	Snapshots []discoverySnapshot
	Durable   bool
	History   collection.History
	Withheld  bool
	Older     bool
}

func (s *Server) linuxDiscovery(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(inventory.TopologyRepository)
	svc := s.options.Enrollment
	if !ok || svc == nil || s.options.Discovery == nil {
		d.Error = "Linux discovery is unavailable on this installation."
		s.renderStatus(w, 503, "inventory-error.html", d)
		return
	}
	var err error
	d.Customer, err = s.inventory.Customer(r.Context(), r.PathValue("customer"))
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	d.Environment, err = s.inventory.Environment(r.Context(), d.Customer.ID, r.PathValue("environment"))
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	d.Enrollment.Asset, err = repo.GetAsset(r.Context(), d.Environment.ID, r.PathValue("asset"))
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	d.Action = "/customers/" + d.Customer.ID + "/environments/" + d.Environment.ID + "/assets/" + d.Enrollment.Asset.ID + "/linux"
	d.Enrollment.Records, err = svc.List(r.Context(), operatorPrincipal(), d.Customer.ID, d.Environment.ID, d.Enrollment.Asset.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	if r.Method == http.MethodPost {
		rev, e := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
		if e != nil {
			http.Error(w, "invalid revision", 400)
			return
		}
		found := false
		for _, rec := range d.Enrollment.Records {
			if rec.ID != r.PostForm.Get("profile") || rec.EndpointID != r.PostForm.Get("endpoint") {
				continue
			}
			found = true
			if rec.State != "connection_verified" || rec.Revision != rev {
				http.Error(w, "Verified enrollment changed or is unavailable. Review SSH enrollment.", 409)
				return
			}
			_, err = s.options.Discovery.Collect(r.Context(), operatorPrincipal(), rec.Target())
		}
		if !found {
			http.Error(w, "invalid enrollment scope", 404)
			return
		}
		if err != nil {
			d.Error = "Linux collection is busy or its evidence could not be committed. Review history after database recovery; retry only with an explicit new request."
			s.renderStatus(w, 409, "discovery.html", d)
			return
		}
		http.Redirect(w, r, d.Action, http.StatusSeeOther)
		return
	}
	history, durable, historyErr := s.options.Discovery.History(r.Context(), operatorPrincipal(), collection.HistoryScope{CustomerID: d.Customer.ID, EnvironmentID: d.Environment.ID, AssetID: d.Enrollment.Asset.ID}, r.URL.Query().Get("before"))
	if historyErr != nil {
		s.inventoryFailure(w, d, historyErr)
		return
	}
	d.Discovery.Older = r.URL.Query().Get("before") != ""
	d.Discovery.Durable = durable
	d.Discovery.History = history
	if durable {
		for _, rec := range d.Enrollment.Records {
			if rec.State == "identity_changed" {
				d.Discovery.Withheld = true
				d.Discovery.History.Latest = nil
			}
		}
		s.render(w, "discovery.html", d)
		return
	}
	for _, rec := range d.Enrollment.Records {
		if rec.State == "identity_changed" {
			if run, ok := s.options.Discovery.SuspendedDiagnostics(operatorPrincipal(), rec.Target()); ok {
				d.Discovery.Snapshots = append(d.Discovery.Snapshots, discoverySnapshot{Profile: rec.ID, Run: run, Suspended: true})
			}
		} else if run, ok := s.options.Discovery.Latest(operatorPrincipal(), rec.Target()); ok {
			d.Discovery.Snapshots = append(d.Discovery.Snapshots, discoverySnapshot{Profile: rec.ID, Run: run})
		}
	}
	s.render(w, "discovery.html", d)
}
