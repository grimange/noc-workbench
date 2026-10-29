package web

import (
	"context"
	"errors"
	"net/http"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strconv"
)

type enrollmentData struct {
	Asset                      inventory.Asset
	Endpoints                  []inventory.Endpoint
	Records                    []connections.Record
	References                 []string
	Standard                   map[string]bool
	Helper                     map[string]bool
	Auth, AuthHelper, Activity map[string]bool
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
			if action == "standard" {
				grant, yes := s.store.(interface {
					SetStandardMonitoring(context.Context, workspace.Principal, collection.HistoryScope, sshcli.Target, bool) error
				})
				if !yes || revision != existing.Revision || r.PostForm.Get("evidence") != "standard" {
					err = connections.ErrInput
				} else {
					if expanded, ok := s.store.(interface {
						SetStandardMonitoringWithAuth(context.Context, workspace.Principal, collection.HistoryScope, sshcli.Target, bool, bool, bool) error
					}); ok {
						if expandedActivity, ok := s.store.(interface {
							SetStandardMonitoringWithActivity(context.Context, workspace.Principal, collection.HistoryScope, sshcli.Target, bool, bool, bool, bool) error
						}); ok {
							err = expandedActivity.SetStandardMonitoringWithActivity(r.Context(), operatorPrincipal(), collection.HistoryScope{CustomerID: existing.CustomerID, EnvironmentID: existing.EnvironmentID, AssetID: existing.AssetID}, existing.Target(), r.PostForm.Get("helper") == "yes", r.PostForm.Get("auth_logs") == "yes", r.PostForm.Get("auth_helper") == "yes", r.PostForm.Get("activity") == "yes")
						} else {
							err = expanded.SetStandardMonitoringWithAuth(r.Context(), operatorPrincipal(), collection.HistoryScope{CustomerID: existing.CustomerID, EnvironmentID: existing.EnvironmentID, AssetID: existing.AssetID}, existing.Target(), r.PostForm.Get("helper") == "yes", r.PostForm.Get("auth_logs") == "yes", r.PostForm.Get("auth_helper") == "yes")
						}
					} else {
						err = grant.SetStandardMonitoring(r.Context(), operatorPrincipal(), collection.HistoryScope{CustomerID: existing.CustomerID, EnvironmentID: existing.EnvironmentID, AssetID: existing.AssetID}, existing.Target(), r.PostForm.Get("helper") == "yes")
					}
				}
			} else {
				_, err = svc.Act(r.Context(), operatorPrincipal(), existing.EndpointID, existing.ID, revision, action, r.PostForm.Get("fingerprint"), r.PostForm.Get("evidence"))
			}
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
	d.Enrollment.Standard = map[string]bool{}
	d.Enrollment.Helper = map[string]bool{}
	d.Enrollment.Auth = map[string]bool{}
	d.Enrollment.AuthHelper = map[string]bool{}
	d.Enrollment.Activity = map[string]bool{}
	if grant, yes := s.store.(interface {
		StandardMonitoringAllowed(context.Context, workspace.Principal, sshcli.Target) error
		IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error
	}); yes {
		for _, rec := range d.Enrollment.Records {
			d.Enrollment.Standard[rec.ID] = grant.StandardMonitoringAllowed(r.Context(), operatorPrincipal(), rec.Target()) == nil
			d.Enrollment.Helper[rec.ID] = grant.IntegrationAllowed(r.Context(), operatorPrincipal(), rec.Target(), "asterisk_helper") == nil
			d.Enrollment.Auth[rec.ID] = grant.IntegrationAllowed(r.Context(), operatorPrincipal(), rec.Target(), "asterisk_auth") == nil
			d.Enrollment.AuthHelper[rec.ID] = grant.IntegrationAllowed(r.Context(), operatorPrincipal(), rec.Target(), "asterisk_auth_helper") == nil
			d.Enrollment.Activity[rec.ID] = grant.IntegrationAllowed(r.Context(), operatorPrincipal(), rec.Target(), "asterisk_activity") == nil
		}
	}
	if r.URL.Query().Get("saved") == "1" {
		d.Notice = "Enrollment action recorded."
	}
	s.renderStatus(w, status, "enrollment.html", d)
}
