package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"noc-workbench/internal/inventory"
)

type evaluationData struct {
	Available   bool
	Result      health.Evaluation
	Policies    []health.Policy
	Selectors   []string
	At          string
	LinuxAction string
}

func (s *Server) assetEvaluation(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(health.Repository)
	if !ok {
		http.Error(w, "Evaluation unavailable", 503)
		return
	}
	h := collection.HistoryScope{CustomerID: r.PathValue("customer"), EnvironmentID: r.PathValue("environment"), AssetID: r.PathValue("asset")}
	at := s.now().UTC()
	if raw := r.URL.Query().Get("at"); raw != "" {
		var e error
		at, e = time.Parse(time.RFC3339Nano, raw)
		if e != nil {
			http.Error(w, "Invalid evaluation timestamp; use RFC3339 UTC", 400)
			return
		}
	}
	in, e := repo.EvaluationEvidence(r.Context(), operatorPrincipal(), h, at)
	if e != nil {
		s.inventoryFailure(w, d, e)
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
	topology, ok := s.store.(inventory.TopologyRepository)
	if !ok {
		http.Error(w, "Inventory context unavailable", 503)
		return
	}
	d.Enrollment.Asset, e = topology.GetAsset(r.Context(), h.EnvironmentID, h.AssetID)
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	base := "/customers/" + h.CustomerID + "/environments/" + h.EnvironmentID + "/assets/" + h.AssetID
	if r.Method == http.MethodPost {
		ttl, err := strconv.Atoi(r.PostForm.Get("ttl"))
		rev, err2 := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
		threshold, err3 := strconv.ParseFloat(r.PostForm.Get("threshold"), 64)
		if err != nil || err2 != nil || err3 != nil {
			http.Error(w, "Invalid policy numbers", 400)
			return
		}
		v := health.Policy{Selector: r.PostForm.Get("selector"), Revision: rev, TTLSeconds: ttl, Rule: r.PostForm.Get("rule"), Threshold: threshold, Enabled: r.PostForm.Get("enabled") == "yes"}
		if _, e = repo.SaveEvaluationPolicy(r.Context(), operatorPrincipal(), h, v); e != nil {
			http.Error(w, "Policy rejected, revision changed or storage unavailable", 409)
			return
		}
		http.Redirect(w, r, base+"/evaluation", 303)
		return
	}
	result, e := health.Evaluate(in)
	if e != nil {
		http.Error(w, "Evaluation evidence or policy unavailable within supported bounds", 503)
		return
	}
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}
	d.Action = base + "/evaluation"
	d.Evaluation = evaluationData{Available: true, Result: result, Policies: in.Policies, At: at.UTC().Format(time.RFC3339Nano), LinuxAction: base + "/linux", Selectors: []string{"monitoring.continuity", "server.ssh_unreachable", "service.runtime.unavailable", "service.ami.disconnected", "service.authentication.repeated", "database.query.failed", "database.replication.failed", "database.replication.lag_seconds", "asterisk.identity", "asterisk.channels", "asterisk.modules", "asterisk.pjsip", "linux.identity", "linux.uptime", "linux.load", "linux.memory", "linux.filesystems", "linux.mem.available_bytes", "linux.filesystem.utilization_percent"}}
	s.render(w, "evaluation.html", d)
}
