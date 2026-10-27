package web

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"noc-workbench/internal/alerts"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"noc-workbench/internal/inventory"
	"strconv"
	"time"
)

type monitoringItem struct {
	Scope collection.HistoryScope
	Name  string
	View  alerts.View
}
type monitoringData struct {
	View                       alerts.View
	Series                     alerts.Series
	Evaluation                 health.Evaluation
	Items                      []monitoringItem
	Base, Hours, Key, Resource string
}

func requestScope(r *http.Request) collection.HistoryScope {
	return collection.HistoryScope{CustomerID: r.PathValue("customer"), EnvironmentID: r.PathValue("environment"), AssetID: r.PathValue("asset")}
}
func scopeBase(h collection.HistoryScope) string {
	return "/customers/" + h.CustomerID + "/environments/" + h.EnvironmentID + "/assets/" + h.AssetID
}
func (s *Server) monitoringOverview(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(alerts.Repository)
	if !ok {
		http.Error(w, "Monitoring unavailable", 503)
		return
	}
	scopes, e := repo.MonitoringAssets(r.Context(), operatorPrincipal())
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	topology, ok := s.store.(inventory.TopologyRepository)
	if !ok {
		http.Error(w, "Inventory unavailable", 503)
		return
	}
	for _, h := range scopes {
		v, e := repo.AlertView(r.Context(), operatorPrincipal(), h)
		if e != nil {
			s.inventoryFailure(w, d, e)
			return
		}
		a, e := topology.GetAsset(r.Context(), h.EnvironmentID, h.AssetID)
		if e != nil {
			s.inventoryFailure(w, d, e)
			return
		}
		d.Monitoring.Items = append(d.Monitoring.Items, monitoringItem{Scope: h, Name: a.Name, View: v})
	}
	d.Active = "monitoring"
	s.render(w, "monitoring-overview.html", d)
}
func (s *Server) assetMonitoring(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(alerts.Repository)
	if !ok {
		http.Error(w, "Monitoring unavailable", 503)
		return
	}
	h := requestScope(r)
	base := scopeBase(h)
	d.Action = base + "/monitoring"
	// Prove resource ownership before reads and mutations, including acknowledgment.
	v, e := repo.AlertView(r.Context(), operatorPrincipal(), h)
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	if r.Method == "POST" {
		if r.PostForm.Get("action") == "acknowledge" {
			e = repo.AcknowledgeAlert(r.Context(), operatorPrincipal(), h, r.PostForm.Get("alert"))
		} else {
			rev, e1 := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
			deb, e2 := strconv.Atoi(r.PostForm.Get("debounce"))
			if e1 != nil || e2 != nil {
				http.Error(w, "Invalid rule numbers", 400)
				return
			}
			_, e = repo.SaveAlertRule(r.Context(), operatorPrincipal(), h, alerts.Rule{PolicyID: r.PostForm.Get("policy"), Revision: rev, Severity: r.PostForm.Get("severity"), DebounceSeconds: deb, Enabled: r.PostForm.Get("enabled") == "yes"})
		}
		if e != nil {
			http.Error(w, "Alert change rejected or storage unavailable", 409)
			return
		}
		http.Redirect(w, r, d.Action, 303)
		return
	}
	hours := 24
	if raw := r.URL.Query().Get("hours"); raw != "" {
		hours, e = strconv.Atoi(raw)
		if e != nil || (hours != 1 && hours != 6 && hours != 24 && hours != 168) {
			http.Error(w, "Select 1, 6, 24 or 168 hours", 400)
			return
		}
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		key = "linux.load.1m"
	}
	resource := r.URL.Query().Get("resource")
	now := s.now().UTC()
	series, e := repo.ObservationSeries(r.Context(), operatorPrincipal(), h, key, resource, now.Add(-time.Duration(hours)*time.Hour), now)
	if e != nil {
		http.Error(w, "History unavailable or exceeds 1000 samples; select a narrower range", 422)
		return
	}
	er, ok := s.store.(health.Repository)
	if !ok {
		http.Error(w, "Evaluation unavailable", 503)
		return
	}
	in, e := er.EvaluationEvidence(r.Context(), operatorPrincipal(), h, now)
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	evaluation, e := health.Evaluate(in)
	if e != nil {
		http.Error(w, "Evaluation unavailable", 503)
		return
	}
	d.Monitoring = monitoringData{View: v, Series: series, Evaluation: evaluation, Base: base, Key: key, Resource: resource, Hours: strconv.Itoa(hours)}
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d.Monitoring)
		return
	}
	d.Customer, e = s.inventory.Customer(r.Context(), h.CustomerID)
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	d.Environment, e = s.inventory.Environment(r.Context(), h.CustomerID, h.EnvironmentID)
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	topology := s.store.(inventory.TopologyRepository)
	d.Enrollment.Asset, e = topology.GetAsset(r.Context(), h.EnvironmentID, h.AssetID)
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	d.Active = "monitoring"
	s.render(w, "monitoring.html", d)
}

// Each stream has no producer queue: bounded clients independently reconcile a
// bounded PostgreSQL snapshot. Slow writes have a deadline. Notifications carry
// no inventory or evidence payload and promise no durable replay. Reconnect
// always begins with reconciliation. Session revocation is checked each tick.
func (s *Server) monitoringEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(w, r); !ok {
		return
	}
	repo, ok := s.store.(alerts.Repository)
	if !ok {
		http.Error(w, "Monitoring unavailable", 503)
		return
	}
	h := requestScope(r)
	if _, e := repo.AlertView(r.Context(), operatorPrincipal(), h); e != nil {
		http.Error(w, "Monitoring scope unavailable", 403)
		return
	}
	select {
	case s.streams <- struct{}{}:
		defer func() { <-s.streams }()
	default:
		http.Error(w, "Live connection limit reached", 429)
		return
	}
	controller := http.NewResponseController(w)
	// Refresh the bounded deadline for net/http to flush the final chunk after
	// an idle heartbeat interval, including session revocation and cancellation.
	defer func() { _ = controller.SetWriteDeadline(time.Now().Add(3 * time.Second)) }()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	var previous [32]byte
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		// Re-check the original session against PostgreSQL without exposing errors
		// in an already-started stream.
		cookie, e := r.Cookie("nw_session")
		if e != nil {
			return
		}
		session, e := s.store.Session(r.Context(), s.sessionKey(cookie.Value))
		if e != nil || !s.now().Before(session.ExpiresAt) {
			return
		}
		v, e := repo.AlertView(r.Context(), operatorPrincipal(), h)
		if e != nil {
			return
		}
		er, ok := s.store.(health.Repository)
		if !ok {
			return
		}
		in, e := er.EvaluationEvidence(r.Context(), operatorPrincipal(), h, s.now().UTC())
		if e != nil {
			return
		}
		current, err := monitoringFingerprint(v, in)
		if err != nil {
			return
		}
		if e = controller.SetWriteDeadline(time.Now().Add(3 * time.Second)); e != nil {
			return
		}
		if current != previous {
			_, e = fmt.Fprint(w, "event: reconcile\ndata: {}\n\n")
			previous = current
		} else {
			_, e = fmt.Fprint(w, ": heartbeat\n\n")
		}
		if e != nil || controller.Flush() != nil {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
	}
}

// Fingerprint excludes advancing age/evaluation time but includes exact freshness
// boundaries and current trust context, even when no alert rule is configured.
func monitoringFingerprint(v alerts.View, in health.Input) ([32]byte, error) {
	evaluated, e := health.Evaluate(in)
	if e != nil {
		return [32]byte{}, e
	}
	for i := range evaluated.Readings {
		evaluated.Readings[i].AgeSeconds = 0
	}
	evaluated.EvaluatedAt = time.Time{}
	payload, e := json.Marshal(struct {
		View            alerts.View
		Evaluation      health.Evaluation
		Policies        []health.Policy
		Active, Trusted bool
		Authority       map[string]int64
	}{v, evaluated, in.Policies, in.Active, in.Trusted, in.Authority})
	return sha256.Sum256(payload), e
}
