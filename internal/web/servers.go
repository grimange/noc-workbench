package web

import (
	"fmt"
	"net/http"
	"net/url"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/services"
	"noc-workbench/internal/health"
	"noc-workbench/internal/integrations/vicidialdiscovery"
	"noc-workbench/internal/workspace"
	"strconv"
)

type dashboardData struct {
	Servers               []consoleServer
	Query, Next, Previous string
}
type serverData struct {
	Detail            workspace.ServerDetail
	Base, Inventory   string
	EvidenceAvailable bool
	Result            health.Evaluation
	Discovery         vicidialdiscovery.Result
	CanDiscover       bool
	Runtime           runtimeData
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, d pageData) {
	d.Active = ""
	raw := r.URL.Query().Get("q")
	q, err := workspace.Query(raw)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	offset, err := consoleOffset(r)
	if err != nil {
		http.Error(w, "Invalid page", 400)
		return
	}
	scope, err := (workspace.LocalOperatorPolicy{}).Scope(operatorPrincipal(), workspace.Search)
	if err != nil {
		http.Error(w, "Forbidden", 403)
		return
	}
	d.Dashboard.Query = raw
	if repo, ok := s.store.(workspace.ServerRepository); ok {
		var more bool
		var servers []workspace.Server
		servers, more, err = repo.Servers(r.Context(), scope, q, offset)
		if err == nil {
			d.Dashboard.Servers, err = s.consoleServers(r, scope, servers)
		}
		if err != nil {
			s.inventoryFailure(w, d, err)
			return
		}
		if more {
			d.Dashboard.Next = "/?q=" + url.QueryEscape(raw) + "&offset=" + strconv.Itoa(offset+25)
		}
	}
	if offset > 0 {
		d.Dashboard.Previous = "/?q=" + url.QueryEscape(raw) + "&offset=" + strconv.Itoa(offset-25)
	}
	s.render(w, "home.html", d)
}
func (s *Server) serverDetails(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	d.Active = ""
	scope, err := (workspace.LocalOperatorPolicy{}).Scope(operatorPrincipal(), workspace.Search)
	if err != nil {
		http.Error(w, "Forbidden", 403)
		return
	}
	repo, ok := s.store.(workspace.ServerRepository)
	if !ok {
		http.Error(w, "Server inventory unavailable", 503)
		return
	}
	v, err := repo.ServerDetails(r.Context(), scope, r.PathValue("asset"))
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	base := "/customers/" + v.CustomerID + "/environments/" + v.EnvironmentID
	d.Server = serverData{Discovery: vicidialdiscovery.Unknown(), CanDiscover: s.options.Discovery != nil, Detail: v, Base: base + "/assets/" + v.ID, Inventory: base + "/topology/assets/" + v.ID}
	if s.options.Enrollment != nil {
		d.Enrollment.Records, err = s.options.Enrollment.List(r.Context(), operatorPrincipal(), v.CustomerID, v.EnvironmentID, v.ID)
		if err != nil {
			s.inventoryFailure(w, d, err)
			return
		}
	}
	if hr, ok := s.store.(health.Repository); ok {
		in, e := hr.EvaluationEvidence(r.Context(), operatorPrincipal(), collection.HistoryScope{CustomerID: v.CustomerID, EnvironmentID: v.EnvironmentID, AssetID: v.ID}, s.now().UTC())
		if e != nil {
			s.inventoryFailure(w, d, e)
			return
		}
		d.Server.Result, e = health.Evaluate(in)
		if e != nil {
			http.Error(w, "Stored evidence could not be evaluated", 503)
			return
		}
		for _, reading := range d.Server.Result.Readings {
			if reading.Evidence.Key == vicidialdiscovery.Key {
				ev := reading.Evidence
				authorized := in.Active && in.Trusted && in.Authority[ev.ProfileID] == ev.ProfileVersion
				d.Server.Discovery = vicidialdiscovery.Evaluate(ev, in.At, reading.Freshness, authorized)
			}
		}
		d.Server.Runtime, e = s.serverRuntime(r, v, in, d.Server.Result, d.Enrollment.Records)
		if e != nil {
			s.inventoryFailure(w, d, e)
			return
		}
		filtered := d.Server.Result.Readings[:0]
		for _, reading := range d.Server.Result.Readings {
			if reading.Evidence.Key != vicidialdiscovery.Key && reading.Evidence.Key != services.Key {
				filtered = append(filtered, reading)
			}
		}
		d.Server.Result.Readings = filtered
		d.Server.EvidenceAvailable = true
	}
	s.render(w, "server.html", d)
}
func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	session, ok := s.session(w, r)
	if !ok {
		return
	}
	label, err := s.store.GetNote(r.Context())
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	s.render(w, "settings.html", pageData{CSRF: session.CSRFToken, Label: label, Active: "settings"})
}

func consoleOffset(r *http.Request) (int, error) {
	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		var e error
		offset, e = strconv.Atoi(v)
		if e != nil || offset < 0 || offset > 1000000 || offset%25 != 0 {
			return 0, fmt.Errorf("invalid page")
		}
	}
	return offset, nil
}
