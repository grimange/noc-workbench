package web

import (
	"context"
	"net/http"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strconv"
	"strings"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"noc-workbench/internal/inventory"
)

type discoverySnapshot struct {
	Profile   string
	Run       collection.Run
	Suspended bool
}
type discoveryData struct {
	IntegrationAvailable bool
	IntegrationEnabled   bool
	LinuxEvidence        []collection.Evidence
	AsteriskEvidence     []collection.Evidence
	Snapshots            []discoverySnapshot
	Durable              bool
	History              collection.History
	Withheld             bool
	Older                bool
}

func (s *Server) linuxDiscovery(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(inventory.TopologyRepository)
	svc := s.options.Enrollment
	if !ok || svc == nil || s.options.Discovery == nil {
		d.Error = "Linux discovery is unavailable on this installation."
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
	d.Action = "/customers/" + d.Customer.ID + "/environments/" + d.Environment.ID + "/assets/" + d.Enrollment.Asset.ID + "/linux"
	d.Enrollment.Records, err = svc.List(r.Context(), operatorPrincipal(), d.Customer.ID, d.Environment.ID, d.Enrollment.Asset.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	integration, hasIntegration := s.store.(interface {
		IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error
		SetIntegration(context.Context, workspace.Principal, collection.HistoryScope, sshcli.Target, string, bool) error
	})
	d.Discovery.IntegrationAvailable = hasIntegration
	if hasIntegration {
		for _, rec := range d.Enrollment.Records {
			if integration.IntegrationAllowed(r.Context(), operatorPrincipal(), rec.Target(), "asterisk") == nil {
				d.Discovery.IntegrationEnabled = true
			}
		}
	}
	if s.options.Scheduler != nil {
		status, e := s.options.Scheduler.Status(r.Context(), operatorPrincipal())
		if e != nil {
			s.inventoryFailure(w, d, e)
			return
		}
		d.Scheduling.Available = true
		d.Scheduling.Status = status
		d.Scheduling.Collectors = []string{"linux.identity", "linux.uptime", "linux.load", "linux.memory", "linux.filesystems"}
		if d.Discovery.IntegrationEnabled {
			d.Scheduling.Collectors = append(d.Scheduling.Collectors, "asterisk.identity", "asterisk.channels", "asterisk.modules", "asterisk.pjsip")
		}
		for _, p := range status.Profiles {
			if p.AssetID == d.Enrollment.Asset.ID && p.CustomerID == d.Customer.ID && p.EnvironmentID == d.Environment.ID {
				d.Scheduling.Profile = p
				d.Scheduling.Exists = true
			}
		}
	}
	if r.Method == http.MethodPost {
		rev, e := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
		if e != nil {
			http.Error(w, "invalid revision", 400)
			return
		}
		found := false
		for _, rec := range d.Enrollment.Records {
			if rec.ID != r.PostForm.Get("profile") || rec.EndpointID != r.PostForm.Get("endpoint") {
				continue
			}
			found = true
			if (rec.State != "connection_verified" && r.PostForm.Get("integration_action") != "disable") || rec.Revision != rev {
				http.Error(w, "Verified enrollment changed or is unavailable. Review SSH enrollment.", 409)
				return
			}
			action := r.PostForm.Get("integration_action")
			if action == "enable" || action == "disable" {
				if !hasIntegration {
					http.Error(w, "Integration unavailable", 503)
					return
				}
				err = integration.SetIntegration(r.Context(), operatorPrincipal(), collection.HistoryScope{CustomerID: d.Customer.ID, EnvironmentID: d.Environment.ID, AssetID: d.Enrollment.Asset.ID}, rec.Target(), "asterisk", action == "enable")
			} else if action == "collect" {
				if !hasIntegration || integration.IntegrationAllowed(r.Context(), operatorPrincipal(), rec.Target(), "asterisk") != nil {
					http.Error(w, "Explicit Asterisk opt-in required for this enrollment revision", 409)
					return
				}
				ids := []string{"asterisk.identity", "asterisk.channels", "asterisk.modules", "asterisk.pjsip"}
				_, err = s.options.Discovery.Collect(collection.WithRequest(r.Context(), collection.Request{Source: "operator", Collectors: ids}), operatorPrincipal(), rec.Target())
			} else if action == "" {
				_, err = s.options.Discovery.Collect(r.Context(), operatorPrincipal(), rec.Target())
			} else {
				http.Error(w, "Invalid integration action", 400)
				return
			}
		}
		if !found {
			http.Error(w, "invalid enrollment scope", 404)
			return
		}
		if err != nil {
			d.Error = "Linux collection is busy or its evidence could not be committed. Review history after database recovery; retry only with an explicit new request."
			s.renderStatus(w, 409, "discovery.html", d)
			return
		}
		http.Redirect(w, r, d.Action, http.StatusSeeOther)
		return
	}
	history, durable, historyErr := s.options.Discovery.History(r.Context(), operatorPrincipal(), collection.HistoryScope{CustomerID: d.Customer.ID, EnvironmentID: d.Environment.ID, AssetID: d.Enrollment.Asset.ID}, r.URL.Query().Get("before"))
	if historyErr != nil {
		s.inventoryFailure(w, d, historyErr)
		return
	}
	// Freshness comes from versioned policies; the stored NW-010 envelope remains immutable.
	if evaluationRepo, ok := s.store.(health.Repository); ok && durable {
		input, e := evaluationRepo.EvaluationEvidence(r.Context(), operatorPrincipal(), collection.HistoryScope{CustomerID: d.Customer.ID, EnvironmentID: d.Environment.ID, AssetID: d.Enrollment.Asset.ID}, s.now().UTC())
		if e != nil {
			s.inventoryFailure(w, d, e)
			return
		}
		result, e := health.Evaluate(input)
		if e != nil {
			http.Error(w, "Evaluation unavailable", 503)
			return
		}
		d.Evaluation = evaluationData{Available: true, Result: result}
		readings := map[string]health.Reading{}
		for _, v := range result.Readings {
			readings[v.Evidence.ID] = v
		}
		for i := range history.Latest {
			v, ok := readings[history.Latest[i].ID]
			if ok {
				history.Latest[i].Freshness = v.Freshness
				history.Latest[i].TTLSeconds = v.TTLSeconds
				history.Latest[i].AgeSeconds = v.AgeSeconds
			} else {
				history.Latest[i].Freshness = "unknown"
			}
		}
	}
	d.Discovery.Older = r.URL.Query().Get("before") != ""
	d.Discovery.Durable = durable
	d.Discovery.History = history
	if durable {
		for _, rec := range d.Enrollment.Records {
			if rec.State == "identity_changed" {
				d.Discovery.Withheld = true
				d.Discovery.History.Latest = nil
			}
		}
		for _, fact := range d.Discovery.History.Latest {
			if strings.HasPrefix(fact.CollectorID, "asterisk.") {
				d.Discovery.AsteriskEvidence = append(d.Discovery.AsteriskEvidence, fact)
			} else if strings.HasPrefix(fact.CollectorID, "linux.") {
				d.Discovery.LinuxEvidence = append(d.Discovery.LinuxEvidence, fact)
			}
		}
		s.render(w, "discovery.html", d)
		return
	}
	for _, rec := range d.Enrollment.Records {
		if rec.State == "identity_changed" {
			if run, ok := s.options.Discovery.SuspendedDiagnostics(operatorPrincipal(), rec.Target()); ok {
				d.Discovery.Snapshots = append(d.Discovery.Snapshots, discoverySnapshot{Profile: rec.ID, Run: run, Suspended: true})
			}
		} else if run, ok := s.options.Discovery.Latest(operatorPrincipal(), rec.Target()); ok {
			d.Discovery.Snapshots = append(d.Discovery.Snapshots, discoverySnapshot{Profile: rec.ID, Run: run})
		}
	}
	s.render(w, "discovery.html", d)
}
