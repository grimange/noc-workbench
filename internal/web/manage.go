package web

import (
	"net/http"
	"noc-workbench/internal/inventory"
)

// Advanced records preserve the existing ownership and integration model without
// making those records prerequisites in the monitoring navigation.
func (s *Server) manageRecords(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	d.Active = "records"
	var err error
	d.Customers, err = s.inventory.ListCustomers(r.Context())
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	if id := r.URL.Query().Get("customer"); id != "" {
		d.Customer, err = s.inventory.Customer(r.Context(), id)
		if err != nil {
			s.inventoryFailure(w, d, err)
			return
		}
		d.Environments, err = s.inventory.ListEnvironments(r.Context(), id)
		if err != nil {
			s.inventoryFailure(w, d, err)
			return
		}
		if env := r.URL.Query().Get("environment"); env != "" {
			d.Environment, err = s.inventory.Environment(r.Context(), id, env)
			if err != nil {
				s.inventoryFailure(w, d, err)
				return
			}
			d.Topology.Base = "/customers/" + id + "/environments/" + env + "/topology"
			for _, kind := range []string{"assets", "endpoints", "clusters", "memberships", "services", "instances", "bindings"} {
				d.Topology.Sections = append(d.Topology.Sections, topologySection{Kind: kind, Label: topologyLabel(kind)})
			}
		}
	} else if r.URL.Query().Get("environment") != "" {
		s.inventoryFailure(w, d, inventory.ErrNotFound)
		return
	}
	s.render(w, "manage.html", d)
}
