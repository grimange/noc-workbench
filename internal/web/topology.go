package web

import (
	"errors"
	"net/http"
	"noc-workbench/internal/inventory"
	"strconv"
)

type topologyOption struct{ Value, Label string }
type topologyField struct {
	Name, Label, Value                 string
	Options                            []topologyOption
	Check, Checked, Required, ReadOnly bool
	Max                                int
}
type topologyRow struct {
	ID, Label, Lifecycle, Summary, URL string
	References                         []topologyOption
}
type topologySection struct {
	Kind, Label string
	Rows        []topologyRow
}
type topologyData struct {
	Base, Kind, Label, Back string
	Sections                []topologySection
	Row                     topologyRow
	Inputs                  []topologyField
	Removing                bool
}

func topologyLabel(kind string) string {
	switch kind {
	case "clusters":
		return "Clusters"
	case "assets":
		return "Assets"
	case "endpoints":
		return "Endpoints"
	case "memberships":
		return "Cluster memberships"
	case "services":
		return "Services"
	case "instances":
		return "Service instances"
	case "bindings":
		return "Instance host bindings"
	}
	return ""
}
func (s *Server) topology(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(inventory.TopologyRepository)
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
	base := "/customers/" + d.Customer.ID + "/environments/" + d.Environment.ID + "/topology"
	kind := r.PathValue("kind")
	id := r.PathValue("record")
	edit := r.PathValue("operation") == "edit"
	remove := r.PathValue("operation") == "remove"
	isNew := id == "new"
	if isNew {
		id = ""
		edit = true
	}
	label := topologyLabel(kind)
	if kind != "" && label == "" {
		s.inventoryFailure(w, d, inventory.ErrNotFound)
		return
	}
	if r.PathValue("operation") != "" && !edit && !remove {
		s.inventoryFailure(w, d, inventory.ErrNotFound)
		return
	}
	d.Topology = topologyData{Base: base, Kind: kind, Label: label, Back: base}
	if kind != "" {
		d.Topology.Back = base + "/" + kind
	}
	options := map[string][]topologyOption{}
	labels := map[string]topologyOption{}
	itemsCluster, err := repo.ListClusters(r.Context(), d.Environment.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	for _, v := range itemsCluster {
		o := topologyOption{Value: v.ID, Label: v.Name + " (" + v.Lifecycle + ")"}
		options["clusters"] = append(options["clusters"], o)
		labels[v.ID] = topologyOption{Value: base + "/clusters/" + v.ID, Label: v.Name}
	}
	itemsAsset, err := repo.ListAssets(r.Context(), d.Environment.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	for _, v := range itemsAsset {
		o := topologyOption{Value: v.ID, Label: v.Name + " (" + v.Lifecycle + ")"}
		options["assets"] = append(options["assets"], o)
		labels[v.ID] = topologyOption{Value: base + "/assets/" + v.ID, Label: v.Name}
	}
	itemsEndpoint, err := repo.ListEndpoints(r.Context(), d.Environment.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	itemsMembership, err := repo.ListMemberships(r.Context(), d.Environment.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	itemsService, err := repo.ListServices(r.Context(), d.Environment.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	for _, v := range itemsService {
		o := topologyOption{Value: v.ID, Label: v.Name + " (" + v.Lifecycle + ")"}
		options["services"] = append(options["services"], o)
		labels[v.ID] = topologyOption{Value: base + "/services/" + v.ID, Label: v.Name}
	}
	itemsInstance, err := repo.ListInstances(r.Context(), d.Environment.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	for _, v := range itemsInstance {
		o := topologyOption{Value: v.ID, Label: v.Name + " (" + v.Lifecycle + ")"}
		options["instances"] = append(options["instances"], o)
		labels[v.ID] = topologyOption{Value: base + "/instances/" + v.ID, Label: v.Name}
	}
	itemsBinding, err := repo.ListBindings(r.Context(), d.Environment.ID)
	if err != nil {
		s.inventoryFailure(w, d, err)
		return
	}
	ref := func(id string) topologyOption {
		if o, ok := labels[id]; ok {
			return o
		}
		return topologyOption{Label: "None"}
	}
	sectionCluster := topologySection{Kind: "clusters", Label: topologyLabel("clusters")}
	for _, v := range itemsCluster {
		row := topologyRow{ID: v.ID, Label: v.Name, Lifecycle: v.Lifecycle, Summary: v.Type, URL: base + "/clusters/" + v.ID}
		sectionCluster.Rows = append(sectionCluster.Rows, row)
		if kind == "clusters" && id == v.ID {
			d.Topology.Row = row
		}
	}
	d.Topology.Sections = append(d.Topology.Sections, sectionCluster)
	sectionAsset := topologySection{Kind: "assets", Label: topologyLabel("assets")}
	for _, v := range itemsAsset {
		row := topologyRow{ID: v.ID, Label: v.Name, Lifecycle: v.Lifecycle, Summary: v.Kind, URL: base + "/assets/" + v.ID}
		sectionAsset.Rows = append(sectionAsset.Rows, row)
		if kind == "assets" && id == v.ID {
			d.Topology.Row = row
		}
	}
	d.Topology.Sections = append(d.Topology.Sections, sectionAsset)
	sectionEndpoint := topologySection{Kind: "endpoints", Label: topologyLabel("endpoints")}
	for _, v := range itemsEndpoint {
		row := topologyRow{ID: v.ID, Label: v.Protocol + "://" + v.Host + ":" + strconv.Itoa(v.Port), Lifecycle: v.Status, Summary: "Inventory endpoint; connection trust not established", URL: base + "/endpoints/" + v.ID}
		if v.AssetID != "" {
			row.References = append(row.References, ref(v.AssetID))
		}
		sectionEndpoint.Rows = append(sectionEndpoint.Rows, row)
		if kind == "endpoints" && id == v.ID {
			d.Topology.Row = row
		}
	}
	d.Topology.Sections = append(d.Topology.Sections, sectionEndpoint)
	sectionMembership := topologySection{Kind: "memberships", Label: topologyLabel("memberships")}
	for _, v := range itemsMembership {
		row := topologyRow{ID: v.ID, Label: ref(v.ClusterID).Label + " → " + ref(v.AssetID).Label, Lifecycle: "recorded", Summary: v.Role + " · manually entered; not verified", URL: base + "/memberships/" + v.ID}
		if v.ClusterID != "" {
			row.References = append(row.References, ref(v.ClusterID))
		}
		if v.AssetID != "" {
			row.References = append(row.References, ref(v.AssetID))
		}
		sectionMembership.Rows = append(sectionMembership.Rows, row)
		if kind == "memberships" && id == v.ID {
			d.Topology.Row = row
		}
	}
	d.Topology.Sections = append(d.Topology.Sections, sectionMembership)
	sectionService := topologySection{Kind: "services", Label: topologyLabel("services")}
	for _, v := range itemsService {
		row := topologyRow{ID: v.ID, Label: v.Name, Lifecycle: v.Lifecycle, Summary: v.ServiceType, URL: base + "/services/" + v.ID}
		if v.ClusterID != "" {
			row.References = append(row.References, ref(v.ClusterID))
		}
		sectionService.Rows = append(sectionService.Rows, row)
		if kind == "services" && id == v.ID {
			d.Topology.Row = row
		}
	}
	d.Topology.Sections = append(d.Topology.Sections, sectionService)
	sectionInstance := topologySection{Kind: "instances", Label: topologyLabel("instances")}
	for _, v := range itemsInstance {
		row := topologyRow{ID: v.ID, Label: v.Name, Lifecycle: v.Lifecycle, Summary: v.Role + " · " + v.InstanceKey, URL: base + "/instances/" + v.ID}
		if v.ServiceID != "" {
			row.References = append(row.References, ref(v.ServiceID))
		}
		sectionInstance.Rows = append(sectionInstance.Rows, row)
		if kind == "instances" && id == v.ID {
			d.Topology.Row = row
		}
	}
	d.Topology.Sections = append(d.Topology.Sections, sectionInstance)
	sectionBinding := topologySection{Kind: "bindings", Label: topologyLabel("bindings")}
	for _, v := range itemsBinding {
		row := topologyRow{ID: v.ID, Label: ref(v.InstanceID).Label + " → " + ref(v.AssetID).Label, Lifecycle: "recorded", Summary: v.BindingRole + " · manually entered; not verified", URL: base + "/bindings/" + v.ID}
		if v.InstanceID != "" {
			row.References = append(row.References, ref(v.InstanceID))
		}
		if v.AssetID != "" {
			row.References = append(row.References, ref(v.AssetID))
		}
		sectionBinding.Rows = append(sectionBinding.Rows, row)
		if kind == "bindings" && id == v.ID {
			d.Topology.Row = row
		}
	}
	d.Topology.Sections = append(d.Topology.Sections, sectionBinding)
	if id != "" && d.Topology.Row.ID == "" {
		s.inventoryFailure(w, d, inventory.ErrNotFound)
		return
	}
	if remove {
		if kind != "memberships" && kind != "bindings" {
			s.inventoryFailure(w, d, inventory.ErrNotFound)
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		if kind == "memberships" {
			err = repo.RemoveMembership(r.Context(), d.Environment.ID, id)
		} else {
			err = repo.RemoveBinding(r.Context(), d.Environment.ID, id)
		}
		if err != nil {
			s.topologyFailure(w, d, err)
			return
		}
		http.Redirect(w, r, base+"/"+kind+"?saved=1", 303)
		return
	}
	if r.Method == "POST" && !edit {
		http.Error(w, "method not allowed", 405)
		return
	}
	if edit {
		if kind == "" {
			s.inventoryFailure(w, d, inventory.ErrNotFound)
			return
		}
		d.Heading = "Create " + label
		if id != "" {
			d.Heading = "Edit " + label
		}
		d.Action = base + "/" + kind + "/new"
		if id != "" {
			d.Action = base + "/" + kind + "/" + id + "/edit"
			d.Topology.Back = base + "/" + kind + "/" + id
		}
		switch kind {
		case "clusters":
			v := inventory.Cluster{EnvironmentID: d.Environment.ID}
			v.Lifecycle = "active"
			if id != "" {
				v, err = repo.GetCluster(r.Context(), d.Environment.ID, id)
				if err != nil {
					s.inventoryFailure(w, d, err)
					return
				}
			}
			if r.Method == "POST" {
				v.Name = r.PostForm.Get("name")
				v.Type = r.PostForm.Get("type")
				v.Tags = r.PostForm.Get("tags")
				v.Lifecycle = r.PostForm.Get("lifecycle")
				v, err = repo.SaveCluster(r.Context(), v)
				if err == nil {
					http.Redirect(w, r, base+"/clusters/"+v.ID+"?saved=1", 303)
					return
				}
			}
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "name", Label: "Name", Value: v.Name, Required: true, Max: 120})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "type", Label: "Type", Value: v.Type, Required: false, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "tags", Label: "Tags", Value: v.Tags, Required: false, Max: 512})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "lifecycle", Label: "Lifecycle", Value: v.Lifecycle, Options: []topologyOption{{Value: "active", Label: "active"}, {Value: "archived", Label: "archived"}}, Required: true, Max: 80})
		case "assets":
			v := inventory.Asset{EnvironmentID: d.Environment.ID}
			v.Kind = "server"
			v.Lifecycle = "active"
			if id != "" {
				v, err = repo.GetAsset(r.Context(), d.Environment.ID, id)
				if err != nil {
					s.inventoryFailure(w, d, err)
					return
				}
			}
			if r.Method == "POST" {
				v.Name = r.PostForm.Get("name")
				v.Kind = r.PostForm.Get("kind")
				v.Tags = r.PostForm.Get("tags")
				v.Lifecycle = r.PostForm.Get("lifecycle")
				v, err = repo.SaveAsset(r.Context(), v)
				if err == nil {
					http.Redirect(w, r, base+"/assets/"+v.ID+"?saved=1", 303)
					return
				}
			}
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "name", Label: "Name", Value: v.Name, Required: true, Max: 120})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "kind", Label: "Kind", Value: v.Kind, Options: []topologyOption{{Value: "server", Label: "server"}, {Value: "network", Label: "network"}, {Value: "appliance", Label: "appliance"}}, Required: true, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "tags", Label: "Tags", Value: v.Tags, Required: false, Max: 512})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "lifecycle", Label: "Lifecycle", Value: v.Lifecycle, Options: []topologyOption{{Value: "active", Label: "active"}, {Value: "archived", Label: "archived"}}, Required: true, Max: 80})
		case "endpoints":
			v := inventory.Endpoint{EnvironmentID: d.Environment.ID}
			v.Protocol = "ssh"
			v.Status = "active"
			v.Port = 22
			if id != "" {
				v, err = repo.GetEndpoint(r.Context(), d.Environment.ID, id)
				if err != nil {
					s.inventoryFailure(w, d, err)
					return
				}
			}
			if r.Method == "POST" {
				v.AssetID = r.PostForm.Get("asset_id")
				v.Protocol = r.PostForm.Get("protocol")
				v.Host = r.PostForm.Get("host")
				v.Port, _ = strconv.Atoi(r.PostForm.Get("port"))
				v.Preferred = r.PostForm.Get("preferred") == "true"
				v.Status = r.PostForm.Get("status")
				v, err = repo.SaveEndpoint(r.Context(), v)
				if err == nil {
					http.Redirect(w, r, base+"/endpoints/"+v.ID+"?saved=1", 303)
					return
				}
			}
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "asset_id", Label: "Asset", Value: v.AssetID, Options: append([]topologyOption{{Value: "", Label: "Choose…"}}, options["assets"]...), ReadOnly: id != "" && true, Required: true, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "protocol", Label: "Protocol", Value: v.Protocol, Options: []topologyOption{{Value: "ssh", Label: "ssh"}, {Value: "http", Label: "http"}, {Value: "https", Label: "https"}, {Value: "tcp", Label: "tcp"}, {Value: "udp", Label: "udp"}}, Required: true, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "host", Label: "Host", Value: v.Host, Required: true, Max: 253})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "port", Label: "Port", Value: strconv.Itoa(v.Port), Required: true, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "preferred", Label: "Preferred", Check: true, Checked: v.Preferred})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "status", Label: "Status", Value: v.Status, Options: []topologyOption{{Value: "active", Label: "active"}, {Value: "archived", Label: "archived"}}, Required: true, Max: 80})
		case "memberships":
			v := inventory.Membership{EnvironmentID: d.Environment.ID}
			if id != "" {
				v, err = repo.GetMembership(r.Context(), d.Environment.ID, id)
				if err != nil {
					s.inventoryFailure(w, d, err)
					return
				}
			}
			if r.Method == "POST" {
				v.ClusterID = r.PostForm.Get("cluster_id")
				v.AssetID = r.PostForm.Get("asset_id")
				v.Role = r.PostForm.Get("role")
				v, err = repo.SaveMembership(r.Context(), v)
				if err == nil {
					http.Redirect(w, r, base+"/memberships/"+v.ID+"?saved=1", 303)
					return
				}
			}
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "cluster_id", Label: "Cluster", Value: v.ClusterID, Options: append([]topologyOption{{Value: "", Label: "Choose…"}}, options["clusters"]...), ReadOnly: id != "" && true, Required: true, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "asset_id", Label: "Asset", Value: v.AssetID, Options: append([]topologyOption{{Value: "", Label: "Choose…"}}, options["assets"]...), ReadOnly: id != "" && true, Required: true, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "role", Label: "Role", Value: v.Role, Required: false, Max: 80})
		case "services":
			v := inventory.Service{EnvironmentID: d.Environment.ID}
			v.Lifecycle = "active"
			if id != "" {
				v, err = repo.GetService(r.Context(), d.Environment.ID, id)
				if err != nil {
					s.inventoryFailure(w, d, err)
					return
				}
			}
			if r.Method == "POST" {
				v.ClusterID = r.PostForm.Get("cluster_id")
				v.Name = r.PostForm.Get("name")
				v.ServiceType = r.PostForm.Get("service_type")
				v.Lifecycle = r.PostForm.Get("lifecycle")
				v, err = repo.SaveService(r.Context(), v)
				if err == nil {
					http.Redirect(w, r, base+"/services/"+v.ID+"?saved=1", 303)
					return
				}
			}
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "cluster_id", Label: "Cluster (optional)", Value: v.ClusterID, Options: append([]topologyOption{{Value: "", Label: "Choose…"}}, options["clusters"]...), ReadOnly: id != "" && false, Required: false, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "name", Label: "Name", Value: v.Name, Required: true, Max: 120})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "service_type", Label: "Service type", Value: v.ServiceType, Required: true, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "lifecycle", Label: "Lifecycle", Value: v.Lifecycle, Options: []topologyOption{{Value: "active", Label: "active"}, {Value: "archived", Label: "archived"}}, Required: true, Max: 80})
		case "instances":
			v := inventory.Instance{EnvironmentID: d.Environment.ID}
			v.Lifecycle = "active"
			if id != "" {
				v, err = repo.GetInstance(r.Context(), d.Environment.ID, id)
				if err != nil {
					s.inventoryFailure(w, d, err)
					return
				}
			}
			if r.Method == "POST" {
				v.ServiceID = r.PostForm.Get("service_id")
				v.Name = r.PostForm.Get("name")
				v.Role = r.PostForm.Get("role")
				v.InstanceKey = r.PostForm.Get("instance_key")
				v.Lifecycle = r.PostForm.Get("lifecycle")
				v, err = repo.SaveInstance(r.Context(), v)
				if err == nil {
					http.Redirect(w, r, base+"/instances/"+v.ID+"?saved=1", 303)
					return
				}
			}
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "service_id", Label: "Service", Value: v.ServiceID, Options: append([]topologyOption{{Value: "", Label: "Choose…"}}, options["services"]...), ReadOnly: id != "" && true, Required: true, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "name", Label: "Name", Value: v.Name, Required: true, Max: 120})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "role", Label: "Role", Value: v.Role, Required: false, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "instance_key", Label: "Instance key", Value: v.InstanceKey, Required: false, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "lifecycle", Label: "Lifecycle", Value: v.Lifecycle, Options: []topologyOption{{Value: "active", Label: "active"}, {Value: "archived", Label: "archived"}}, Required: true, Max: 80})
		case "bindings":
			v := inventory.Binding{EnvironmentID: d.Environment.ID}
			if id != "" {
				v, err = repo.GetBinding(r.Context(), d.Environment.ID, id)
				if err != nil {
					s.inventoryFailure(w, d, err)
					return
				}
			}
			if r.Method == "POST" {
				v.InstanceID = r.PostForm.Get("service_instance_id")
				v.AssetID = r.PostForm.Get("asset_id")
				v.BindingRole = r.PostForm.Get("binding_role")
				v, err = repo.SaveBinding(r.Context(), v)
				if err == nil {
					http.Redirect(w, r, base+"/bindings/"+v.ID+"?saved=1", 303)
					return
				}
			}
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "service_instance_id", Label: "Service instance", Value: v.InstanceID, Options: append([]topologyOption{{Value: "", Label: "Choose…"}}, options["instances"]...), ReadOnly: id != "" && true, Required: true, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "asset_id", Label: "Asset", Value: v.AssetID, Options: append([]topologyOption{{Value: "", Label: "Choose…"}}, options["assets"]...), ReadOnly: id != "" && true, Required: true, Max: 80})
			d.Topology.Inputs = append(d.Topology.Inputs, topologyField{Name: "binding_role", Label: "Binding role", Value: v.BindingRole, Required: false, Max: 80})
		}
		if err != nil {
			if errors.As(err, &d.Fields) {
				s.renderStatus(w, 422, "topology-form.html", d)
			} else {
				s.topologyFailure(w, d, err)
			}
			return
		}
		s.render(w, "topology-form.html", d)
		return
	}
	if r.URL.Query().Get("saved") == "1" {
		d.Notice = "Topology saved."
	}
	if id != "" {
		d.Topology.Removing = kind == "memberships" || kind == "bindings"
		s.workspaceVisit(r, kind, id)
		s.render(w, "topology-detail.html", d)
		return
	}
	s.render(w, "topology-list.html", d)
}
func (s *Server) topologyFailure(w http.ResponseWriter, d pageData, err error) {
	if errors.Is(err, inventory.ErrInactive) {
		d.Error = err.Error()
		s.renderStatus(w, 409, "inventory-error.html", d)
		return
	}
	s.inventoryFailure(w, d, err)
}
