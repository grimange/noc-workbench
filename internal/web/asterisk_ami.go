package web

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"noc-workbench/internal/collection"
	ami "noc-workbench/internal/integrations/asteriskami"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type amiReader interface {
	AMIView(context.Context, workspace.Principal, collection.HistoryScope, sshcli.Target, time.Time) (ami.View, error)
}

func (s *Server) serverAMI(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(workspace.ServerRepository)
	if !ok || s.options.AMI == nil || s.options.Enrollment == nil {
		http.Error(w, "AMI integration unavailable", 503)
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
	records, e := s.options.Enrollment.List(r.Context(), operatorPrincipal(), v.CustomerID, v.EnvironmentID, v.ID)
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	revision, e := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
	if e != nil {
		http.Error(w, "Invalid revision", 400)
		return
	}
	enabled := r.PostForm.Get("authorize") == "yes"
	if !enabled && r.PostForm.Get("authorize") != "no" {
		http.Error(w, "Explicit AMI authorization required", 400)
		return
	}
	for _, rec := range records {
		if rec.ID != r.PostForm.Get("profile") || rec.EndpointID != r.PostForm.Get("endpoint") {
			continue
		}
		if rec.Revision != revision || enabled && rec.State != "connection_verified" {
			http.Error(w, "Connection changed; reload", 409)
			return
		}
		if e = s.options.AMI.Authorize(r.Context(), operatorPrincipal(), collection.HistoryScope{CustomerID: v.CustomerID, EnvironmentID: v.EnvironmentID, AssetID: v.ID}, rec.Target(), r.PostForm.Get("credential_ref"), enabled); e != nil {
			http.Error(w, "AMI capability is unavailable or authorization changed", 409)
			return
		}
		http.Redirect(w, r, "/servers/"+v.ID+"#ami-monitoring", 303)
		return
	}
	http.Error(w, "Connection unavailable", 404)
}
