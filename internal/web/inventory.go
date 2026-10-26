package web

import (
	"errors"
	"net/http"

	"noc-workbench/internal/inventory"
	"noc-workbench/internal/store/postgres"
)

func (s *Server) inventoryPage(w http.ResponseWriter, r *http.Request) (pageData, bool) {
	var session postgres.Session
	var ok bool
	if r.Method == http.MethodPost {
		session, ok = s.mutation(w, r)
	} else {
		session, ok = s.session(w, r)
	}
	if !ok {
		return pageData{}, false
	}
	d := pageData{CSRF: session.CSRFToken, Active: "customers"}
	if s.inventory == nil {
		s.inventoryFailure(w, d, inventory.ErrUnavailable)
		return d, false
	}
	return d, true
}
func (s *Server) inventoryFailure(w http.ResponseWriter, d pageData, err error) {
	status := http.StatusServiceUnavailable
	d.Error = "Inventory storage is unavailable. Please try again shortly."
	if errors.Is(err, inventory.ErrNotFound) {
		status = http.StatusNotFound
		d.Error = "This inventory record was not found under the selected customer."
	}
	if errors.Is(err, inventory.ErrArchived) {
		status = http.StatusConflict
		d.Error = "This customer is archived. Restore it before changing environments."
	}
	s.renderStatus(w, status, "inventory-error.html", d)
}
func (s *Server) customers(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	var err error
	d.Customers, err = s.inventory.ListCustomers(r.Context())
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	s.render(w, "customers.html", d)
}
func (s *Server) customerDetail(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	var err error
	d.Customer, err = s.inventory.Customer(r.Context(), r.PathValue("customer"))
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	d.Environments, err = s.inventory.ListEnvironments(r.Context(), d.Customer.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	if r.URL.Query().Get("saved") == "1" {
		d.Notice = "Customer saved."
	}
	s.render(w, "customer-detail.html", d)
}
func (s *Server) customerForm(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	id := r.PathValue("customer")
	d.Heading = "Create customer"
	d.Action = "/customers"
	d.Customer.Status = "active"
	if id != "" {
		var err error
		d.Customer, err = s.inventory.Customer(r.Context(), id)
		if err != nil {
			s.inventoryFailure(w, d, err)
			return
		}
		d.Heading = "Edit customer"
		d.Action = "/customers/" + id + "/edit"
	}
	if r.Method == http.MethodPost {
		c := inventory.Customer{ID: id, DisplayName: r.PostForm.Get("display_name"), ShortCode: r.PostForm.Get("short_code"), Notes: r.PostForm.Get("notes"), Status: r.PostForm.Get("status")}
		var err error
		c, err = inventory.ValidateCustomer(c)
		d.Customer = c
		if err == nil {
			if id == "" {
				c, err = s.inventory.CreateCustomer(r.Context(), c)
			} else {
				c, err = s.inventory.UpdateCustomer(r.Context(), c)
			}
		}
		if err == nil {
			http.Redirect(w, r, "/customers/"+c.ID+"?saved=1", http.StatusSeeOther)
			return
		}
		if !errors.As(err, &d.Fields) {
			s.inventoryFailure(w, d, err)
			return
		}
		s.renderStatus(w, http.StatusUnprocessableEntity, "customer-form.html", d)
		return
	}
	s.render(w, "customer-form.html", d)
}
func (s *Server) environmentDetail(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
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
	if r.URL.Query().Get("saved") == "1" {
		d.Notice = "Environment saved."
	}
	s.render(w, "environment-detail.html", d)
}
func (s *Server) environmentForm(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	var err error
	d.Customer, err = s.inventory.Customer(r.Context(), r.PathValue("customer"))
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	id := r.PathValue("environment")
	d.Heading = "Create environment"
	d.Action = "/customers/" + d.Customer.ID + "/environments"
	d.Environment = inventory.Environment{CustomerID: d.Customer.ID, Kind: "lab", Status: "active"}
	if id != "" {
		d.Environment, err = s.inventory.Environment(r.Context(), d.Customer.ID, id)
		if err != nil {
			s.inventoryFailure(w, d, err)
			return
		}
		d.Heading = "Edit environment"
		d.Action += "/" + id + "/edit"
	}
	if d.Customer.Status == "archived" {
		s.inventoryFailure(w, d, inventory.ErrArchived)
		return
	}
	if r.Method == http.MethodPost {
		if owner := r.PostForm.Get("customer_id"); owner != "" && owner != d.Customer.ID {
			http.Error(w, "invalid environment owner", http.StatusForbidden)
			return
		}
		e := inventory.Environment{ID: id, CustomerID: d.Customer.ID, Name: r.PostForm.Get("name"), Kind: r.PostForm.Get("kind"), Status: r.PostForm.Get("status")}
		e, err = inventory.ValidateEnvironment(e)
		d.Environment = e
		if err == nil {
			if id == "" {
				e, err = s.inventory.CreateEnvironment(r.Context(), e)
			} else {
				e, err = s.inventory.UpdateEnvironment(r.Context(), e)
			}
		}
		if err == nil {
			http.Redirect(w, r, "/customers/"+e.CustomerID+"/environments/"+e.ID+"?saved=1", http.StatusSeeOther)
			return
		}
		if !errors.As(err, &d.Fields) {
			s.inventoryFailure(w, d, err)
			return
		}
		s.renderStatus(w, http.StatusUnprocessableEntity, "environment-form.html", d)
		return
	}
	s.render(w, "environment-form.html", d)
}
