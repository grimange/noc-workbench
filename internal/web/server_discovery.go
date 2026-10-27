package web

import (
	"context"
	"net/http"
	"strconv"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/integrations/vicidialdiscovery"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

// Refresh is an explicit authenticated and CSRF-protected opt-in for this exact
// enrollment revision. GET details uses only saved evidence.
func (s *Server) serverDiscovery(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(workspace.ServerRepository)
	authority, has := s.store.(interface {
		SetIntegration(context.Context, workspace.Principal, collection.HistoryScope, sshcli.Target, string, bool) error
	})
	if !ok || !has || s.options.Enrollment == nil || s.options.Discovery == nil {
		http.Error(w, "Discovery unavailable", 503)
		return
	}
	scope, err := (workspace.LocalOperatorPolicy{}).Scope(operatorPrincipal(), workspace.Search)
	if err != nil {
		http.Error(w, "Forbidden", 403)
		return
	}
	v, err := repo.ServerDetails(r.Context(), scope, r.PathValue("asset"))
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	records, err := s.options.Enrollment.List(r.Context(), operatorPrincipal(), v.CustomerID, v.EnvironmentID, v.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	revision, err := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid revision", 400)
		return
	}
	for _, rec := range records {
		if rec.ID != r.PostForm.Get("profile") || rec.EndpointID != r.PostForm.Get("endpoint") {
			continue
		}
		if rec.State != "connection_verified" || rec.Revision != revision {
			http.Error(w, "Verified SSH enrollment changed or is unavailable", 409)
			return
		}
		h := collection.HistoryScope{CustomerID: v.CustomerID, EnvironmentID: v.EnvironmentID, AssetID: v.ID}
		if err = authority.SetIntegration(r.Context(), operatorPrincipal(), h, rec.Target(), "vicidial_discovery", true); err != nil {
			s.inventoryFailure(w, d, err)
			return
		}
		_, err = s.options.Discovery.Collect(collection.WithRequest(r.Context(), collection.Request{Source: "operator", Collectors: []string{vicidialdiscovery.Collector}}), operatorPrincipal(), rec.Target())
		if err != nil {
			http.Error(w, "Discovery could not complete; retained evidence is unchanged. Review collection history.", 409)
			return
		}
		http.Redirect(w, r, "/servers/"+v.ID, http.StatusSeeOther)
		return
	}
	http.Error(w, "Enrollment does not belong to this server", 404)
}
