package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"noc-workbench/internal/workspace"
)

type registrationData struct {
	Input      workspace.Registration
	Placements []topologyOption
}

func (s *Server) registerServer(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	d.Active = "servers"
	d.Registration.Input = workspace.Registration{CustomerID: r.URL.Query().Get("customer"), Port: 22}
	var err error
	d.Customers, err = s.inventory.ListCustomers(r.Context())
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	if r.Method == http.MethodPost {
		port, _ := strconv.Atoi(r.PostForm.Get("port"))
		d.Registration.Input = workspace.Registration{CustomerID: r.PostForm.Get("customer"), EnvironmentID: r.PostForm.Get("placement"), Name: r.PostForm.Get("name"), Host: r.PostForm.Get("host"), Port: port}
		repo, yes := s.store.(workspace.RegistrationRepository)
		if !yes {
			http.Error(w, "Registration unavailable", 503)
			return
		}
		v, e := repo.RegisterServer(r.Context(), operatorPrincipal(), d.Registration.Input)
		if e == nil {
			http.Redirect(w, r, "/servers/"+v.Asset.ID+"/connection", http.StatusSeeOther)
			return
		}
		if !errors.As(e, &d.Fields) {
			s.inventoryFailure(w, d, e)
			return
		}
		d.Error = "Server was not registered. Review the highlighted fields."
	}
	// Only ambiguous existing placement requires an operator choice. Registration
	// never silently selects an environment from another customer.
	for _, c := range d.Customers {
		if c.Status != "active" {
			continue
		}
		envs, e := s.inventory.ListEnvironments(r.Context(), c.ID)
		if e != nil {
			s.inventoryFailure(w, d, e)
			return
		}
		for _, env := range envs {
			if env.Status == "active" {
				d.Registration.Placements = append(d.Registration.Placements, topologyOption{Value: env.ID, Label: c.DisplayName + " / " + env.Name})
			}
		}
	}
	if d.Error != "" {
		s.renderStatus(w, 422, "registration.html", d)
	} else {
		s.render(w, "registration.html", d)
	}
}

// Direct operational URLs resolve through the same scoped server read model as
// Server Details before reusing the accepted connection/history handlers.
func (s *Server) serverContext(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, ok := s.inventoryPage(w, r)
		if !ok {
			return
		}
		repo, ok := s.store.(workspace.ServerRepository)
		if !ok {
			http.Error(w, "Server storage unavailable", 503)
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
		r.SetPathValue("customer", v.CustomerID)
		r.SetPathValue("environment", v.EnvironmentID)
		next(w, r)
	}
}

func (s *Server) compatibility(destination string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if _, ok := s.session(w, r); !ok {
				return
			}
		} else if _, ok := s.mutation(w, r); !ok {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "This operation has been retired", http.StatusGone)
			return
		}
		u := destination
		if destination == "/servers" && r.URL.Query().Get("q") != "" {
			u += "?q=" + url.QueryEscape(r.URL.Query().Get("q"))
		}
		http.Redirect(w, r, u, http.StatusSeeOther)
	}
}
