package web

import (
	"errors"
	"net/http"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strconv"
)

type enrollmentData struct {
	Asset      inventory.Asset
	Endpoints  []inventory.Endpoint
	Records    []connections.Record
	References []string
}

func (s *Server) sshEnrollment(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(inventory.TopologyRepository)
	svc := s.options.Enrollment
	if !ok || svc == nil {
		d.Error = "SSH enrollment is unavailable on this installation."
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
	d.Action = "/customers/" + d.Customer.ID + "/environments/" + d.Environment.ID + "/assets/" + d.Enrollment.Asset.ID + "/ssh"
	if d.Enrollment.Asset.Kind == "server" {
		d.Action = "/servers/" + d.Enrollment.Asset.ID + "/connection"
	}
	status := 200
	if r.Method == http.MethodPost {
		action := r.PostForm.Get("action")
		if action == "create" {
			_, err = svc.Create(r.Context(), operatorPrincipal(), d.Customer.ID, d.Environment.ID, d.Enrollment.Asset.ID, r.PostForm.Get("endpoint"), r.PostForm.Get("address"), r.PostForm.Get("credential"))
		} else {
			// Do not allow an enrollment belonging to another URL's asset/scope.
			existing, e := svc.Repository.Enrollment(r.Context(), r.PostForm.Get("endpoint"), r.PostForm.Get("profile"))
			if e != nil || existing.CustomerID != d.Customer.ID || existing.EnvironmentID != d.Environment.ID || existing.AssetID != d.Enrollment.Asset.ID {
				http.Error(w, "invalid enrollment scope", 404)
				return
			}
			revision, e := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
			if e != nil {
				http.Error(w, "invalid revision", 400)
				return
			}
			_, err = svc.Act(r.Context(), operatorPrincipal(), existing.EndpointID, existing.ID, revision, action, r.PostForm.Get("fingerprint"), r.PostForm.Get("evidence"))
		}
		if err == nil {
			http.Redirect(w, r, d.Action+"?saved=1", http.StatusSeeOther)
			return
		}
		status = 409
		d.Error = "Enrollment could not be saved. Reload and review the current record."
		var failure *sshcli.Failure
		switch {
		case errors.Is(err, workspace.ErrDenied):
			status = 403
			d.Error = "Connection permission denied."
		case errors.Is(err, connections.ErrCredential), errors.Is(err, connections.ErrInput), errors.Is(err, connections.ErrState), errors.Is(err, connections.ErrConflict), errors.Is(err, workspace.ErrLimit):
			d.Error = err.Error()
		case errors.As(err, &failure):
			d.Error = "SSH transport: " + string(failure.Category) + ". Connection outcome is not service health."
		}
	}
	endpoints, err := repo.ListEndpoints(r.Context(), d.Environment.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	for _, ep := range endpoints {
		if ep.AssetID == d.Enrollment.Asset.ID && ep.Protocol == "ssh" && ep.Status == "active" {
			d.Enrollment.Endpoints = append(d.Enrollment.Endpoints, ep)
		}
	}
	d.Enrollment.References = svc.CredentialReferences()
	d.Enrollment.Records, err = svc.List(r.Context(), operatorPrincipal(), d.Customer.ID, d.Environment.ID, d.Enrollment.Asset.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	if r.URL.Query().Get("saved") == "1" {
		d.Notice = "Enrollment action recorded."
	}
	s.renderStatus(w, status, "enrollment.html", d)
}
