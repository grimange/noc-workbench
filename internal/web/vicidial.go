package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"noc-workbench/internal/alerts"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"noc-workbench/internal/integrations/vicidial"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type vicidialNode struct {
	Asset                      inventory.Asset
	Role, MembershipURL, Base  string
	Services                   []topologyOption
	Result                     health.Evaluation
	Linux, Asterisk            []health.Reading
	AsteriskEnabled, Truncated bool
	Alerts                     []alerts.Instance
}
type vicidialData struct {
	Integration                 vicidial.Integration
	Cluster                     inventory.Cluster
	Registered, Truncated       bool
	Base, QuickAccess, Topology string
	Nodes                       []vicidialNode
	Links                       []workspace.Link
}

// vicidialContext projects canonical inventory and retained evidence. It never
// grants execution authority or invokes a collector, scheduler, or alert writer.
func (s *Server) vicidialContext(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(vicidial.Repository)
	if !ok {
		s.inventoryFailure(w, d, inventory.ErrUnavailable)
		return
	}
	topo, ok := s.store.(inventory.TopologyRepository)
	if !ok {
		s.inventoryFailure(w, d, inventory.ErrUnavailable)
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
	d.VICIdial.Cluster, err = topo.GetCluster(r.Context(), d.Environment.ID, r.PathValue("cluster"))
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	scope := vicidial.Scope{CustomerID: d.Customer.ID, EnvironmentID: d.Environment.ID, ClusterID: d.VICIdial.Cluster.ID}
	permission, err := (workspace.LocalOperatorPolicy{}).Scope(operatorPrincipal(), workspace.Organize)
	if err != nil || !permission.Allows(d.Customer.ID, d.Environment.ID) {
		http.Error(w, "Not authorized", http.StatusForbidden)
		return
	}
	v, err := repo.VICIdialIntegration(r.Context(), operatorPrincipal(), scope)
	if err != nil && !errors.Is(err, inventory.ErrNotFound) {
		s.inventoryFailure(w, d, err)
		return
	}
	d.VICIdial.Registered = err == nil
	base := "/customers/" + d.Customer.ID + "/environments/" + d.Environment.ID
	d.Action = base + "/clusters/" + d.VICIdial.Cluster.ID + "/vicidial"
	d.VICIdial.Base = base
	d.VICIdial.Topology = base + "/topology"
	d.VICIdial.QuickAccess = "/workspace/clusters/" + d.VICIdial.Cluster.ID
	status := http.StatusOK
	if r.Method == http.MethodPost {
		revision, e := strconv.ParseInt(r.FormValue("revision"), 10, 64)
		v = vicidial.Integration{Name: r.FormValue("name"), Version: r.FormValue("version"), RevisionSource: r.FormValue("source"), Notes: r.FormValue("notes"), Enabled: r.FormValue("enabled") == "yes", Revision: revision}
		if raw := r.FormValue("verified_at"); raw != "" {
			at, e2 := time.Parse(time.RFC3339, raw)
			if e2 != nil {
				e = e2
			} else {
				v.VerifiedAt = &at
			}
		}
		if e != nil || revision < 0 {
			d.Error = "Enter a valid revision and UTC verification timestamp."
			status = http.StatusUnprocessableEntity
		} else {
			_, err = repo.SaveVICIdialIntegration(r.Context(), operatorPrincipal(), scope, v)
			if err == nil {
				http.Redirect(w, r, d.Action, http.StatusSeeOther)
				return
			}
			var fields inventory.FieldErrors
			if errors.As(err, &fields) {
				d.Fields = fields
				d.Error = "The integration could not be saved. Review the fields and reload after a concurrent change."
				status = http.StatusUnprocessableEntity
			} else {
				s.inventoryFailure(w, d, err)
				return
			}
		}
	}
	d.VICIdial.Integration = v
	if status == http.StatusOK && v.Enabled && d.VICIdial.Registered {
		if err = s.vicidialEvidence(r, &d, topo); err != nil {
			s.inventoryFailure(w, d, err)
			return
		}
	}
	w.WriteHeader(status)
	s.render(w, "vicidial.html", d)
}

func (s *Server) vicidialEvidence(r *http.Request, d *pageData, topo inventory.TopologyRepository) error {
	memberships, err := topo.ListMemberships(r.Context(), d.Environment.ID)
	if err != nil {
		return err
	}
	assets, err := topo.ListAssets(r.Context(), d.Environment.ID)
	if err != nil {
		return err
	}
	services, err := topo.ListServices(r.Context(), d.Environment.ID)
	if err != nil {
		return err
	}
	instances, err := topo.ListInstances(r.Context(), d.Environment.ID)
	if err != nil {
		return err
	}
	bindings, err := topo.ListBindings(r.Context(), d.Environment.ID)
	if err != nil {
		return err
	}
	assetMap := map[string]inventory.Asset{}
	for _, a := range assets {
		assetMap[a.ID] = a
	}
	serviceMap := map[string]inventory.Service{}
	for _, v := range services {
		if v.ClusterID == d.VICIdial.Cluster.ID {
			serviceMap[v.ID] = v
		}
	}
	instanceMap := map[string]inventory.Instance{}
	for _, v := range instances {
		if _, ok := serviceMap[v.ServiceID]; ok {
			instanceMap[v.ID] = v
		}
	}
	ws, ok := s.workspaceService()
	if !ok {
		return inventory.ErrUnavailable
	}
	target, err := ws.Target(r.Context(), operatorPrincipal(), "clusters", d.VICIdial.Cluster.ID)
	if err != nil {
		return err
	}
	links, err := ws.Links(r.Context(), operatorPrincipal(), target)
	if err != nil {
		return err
	}
	for _, link := range links {
		if link.Enabled {
			d.VICIdial.Links = append(d.VICIdial.Links, link)
		}
	}
	evidenceRepo, hasEvidence := s.store.(health.Repository)
	alertRepo, hasAlerts := s.store.(alerts.Repository)
	at := s.now().UTC()
	for _, m := range memberships {
		if m.ClusterID != d.VICIdial.Cluster.ID {
			continue
		}
		if len(d.VICIdial.Nodes) >= 20 {
			d.VICIdial.Truncated = true
			continue
		}
		n := vicidialNode{Asset: assetMap[m.AssetID], Role: m.Role, MembershipURL: d.VICIdial.Topology + "/memberships/" + m.ID + "/edit", Base: d.VICIdial.Base + "/assets/" + m.AssetID}
		seen := map[string]bool{}
		for _, b := range bindings {
			if b.AssetID != m.AssetID {
				continue
			}
			if i, ok := instanceMap[b.InstanceID]; ok && !seen[i.ID] {
				seen[i.ID] = true
				n.Services = append(n.Services, topologyOption{Label: serviceMap[i.ServiceID].Name + " · " + i.Name + " · " + b.BindingRole, Value: d.VICIdial.Topology + "/instances/" + i.ID})
			}
		}
		scope := collection.HistoryScope{CustomerID: d.Customer.ID, EnvironmentID: d.Environment.ID, AssetID: m.AssetID}
		if hasEvidence {
			in, e := evidenceRepo.EvaluationEvidence(r.Context(), operatorPrincipal(), scope, at)
			if e != nil {
				return e
			}
			n.Result, e = health.Evaluate(in)
			if e != nil {
				return e
			}
			if integration, ok := s.store.(interface {
				IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error
			}); ok && s.options.Enrollment != nil {
				records, e := s.options.Enrollment.List(r.Context(), operatorPrincipal(), d.Customer.ID, d.Environment.ID, m.AssetID)
				if e != nil {
					return e
				}
				for _, rec := range records {
					if integration.IntegrationAllowed(r.Context(), operatorPrincipal(), rec.Target(), "asterisk") == nil {
						n.AsteriskEnabled = true
						break
					}
				}
			}
			for _, reading := range n.Result.Readings {
				if len(n.Linux)+len(n.Asterisk) >= 40 {
					n.Truncated = true
					break
				}
				if strings.HasPrefix(reading.Evidence.Key, "linux.") {
					n.Linux = append(n.Linux, reading)
				} else if n.AsteriskEnabled && strings.HasPrefix(reading.Evidence.Key, "asterisk.") {
					n.Asterisk = append(n.Asterisk, reading)
				}
			}
		} else {
			n.Result.Collection = "unknown"
			n.Result.Health = "unknown"
		}
		if hasAlerts {
			view, e := alertRepo.AlertView(r.Context(), operatorPrincipal(), scope)
			if e != nil {
				return e
			}
			for _, a := range view.Alerts {
				if a.State != "resolved" {
					n.Alerts = append(n.Alerts, a)
				}
			}
		}
		d.VICIdial.Nodes = append(d.VICIdial.Nodes, n)
	}
	return nil
}
