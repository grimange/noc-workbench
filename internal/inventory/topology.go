package inventory

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"
)

var ErrInactive = &TopologyConflict{}

type TopologyConflict struct{}

func (*TopologyConflict) Error() string {
	return "Restore owning records before assigning active topology."
}

type Cluster struct {
	ID, EnvironmentID    string
	Name                 string
	Type                 string
	Tags                 string
	Lifecycle            string
	CreatedAt, UpdatedAt time.Time
}
type Asset struct {
	ID, EnvironmentID    string
	Name                 string
	Kind                 string
	Tags                 string
	Lifecycle            string
	CreatedAt, UpdatedAt time.Time
}
type Endpoint struct {
	ID, EnvironmentID    string
	AssetID              string
	Protocol             string
	Host                 string
	Port                 int
	Preferred            bool
	Status               string
	CreatedAt, UpdatedAt time.Time
}
type Membership struct {
	ID, EnvironmentID    string
	ClusterID            string
	AssetID              string
	Role                 string
	CreatedAt, UpdatedAt time.Time
}
type Service struct {
	ID, EnvironmentID    string
	ClusterID            string
	Name                 string
	ServiceType          string
	Lifecycle            string
	CreatedAt, UpdatedAt time.Time
}
type Instance struct {
	ID, EnvironmentID    string
	ServiceID            string
	Name                 string
	Role                 string
	InstanceKey          string
	Lifecycle            string
	CreatedAt, UpdatedAt time.Time
}
type Binding struct {
	ID, EnvironmentID    string
	InstanceID           string
	AssetID              string
	BindingRole          string
	CreatedAt, UpdatedAt time.Time
}
type TopologyRepository interface {
	ListClusters(context.Context, string) ([]Cluster, error)
	GetCluster(context.Context, string, string) (Cluster, error)
	SaveCluster(context.Context, Cluster) (Cluster, error)
	ListAssets(context.Context, string) ([]Asset, error)
	GetAsset(context.Context, string, string) (Asset, error)
	SaveAsset(context.Context, Asset) (Asset, error)
	ListEndpoints(context.Context, string) ([]Endpoint, error)
	GetEndpoint(context.Context, string, string) (Endpoint, error)
	SaveEndpoint(context.Context, Endpoint) (Endpoint, error)
	ListMemberships(context.Context, string) ([]Membership, error)
	GetMembership(context.Context, string, string) (Membership, error)
	SaveMembership(context.Context, Membership) (Membership, error)
	RemoveMembership(context.Context, string, string) error
	ListServices(context.Context, string) ([]Service, error)
	GetService(context.Context, string, string) (Service, error)
	SaveService(context.Context, Service) (Service, error)
	ListInstances(context.Context, string) ([]Instance, error)
	GetInstance(context.Context, string, string) (Instance, error)
	SaveInstance(context.Context, Instance) (Instance, error)
	ListBindings(context.Context, string) ([]Binding, error)
	GetBinding(context.Context, string, string) (Binding, error)
	SaveBinding(context.Context, Binding) (Binding, error)
	RemoveBinding(context.Context, string, string) error
}

var hostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func ValidEndpointHost(h string) bool {
	if h == "" || len(h) > 253 || strings.TrimSpace(h) != h {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	if strings.Trim(h, "0123456789.") == "" {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if !hostnamePattern.MatchString(label) {
			return false
		}
	}
	return true
}
func topologyText(f FieldErrors, key, value string, max int, optional bool) {
	if value == "" && optional {
		return
	}
	if !validName(value, max) {
		f[key] = "Enter valid plain text within the field length limit."
	}
}
func ValidateCluster(v Cluster) (Cluster, error) {
	f := FieldErrors{}
	if !ValidID(v.EnvironmentID) {
		f["environment_id"] = "Choose an existing environment."
	}
	if v.ID != "" && !ValidID(v.ID) {
		f["id"] = "Invalid identity."
	}
	v.Name = strings.TrimSpace(v.Name)
	topologyText(f, "name", v.Name, 120, false)
	v.Type = strings.TrimSpace(v.Type)
	topologyText(f, "type", v.Type, 80, true)
	v.Tags = strings.TrimSpace(v.Tags)
	topologyText(f, "tags", v.Tags, 512, true)
	v.Lifecycle = strings.TrimSpace(v.Lifecycle)
	if !lifecycle(v.Lifecycle) {
		f["lifecycle"] = "Choose active or archived."
	}
	if len(f) > 0 {
		return v, f
	}
	return v, nil
}
func ValidateAsset(v Asset) (Asset, error) {
	f := FieldErrors{}
	if !ValidID(v.EnvironmentID) {
		f["environment_id"] = "Choose an existing environment."
	}
	if v.ID != "" && !ValidID(v.ID) {
		f["id"] = "Invalid identity."
	}
	v.Name = strings.TrimSpace(v.Name)
	topologyText(f, "name", v.Name, 120, false)
	v.Kind = strings.TrimSpace(v.Kind)
	if v.Kind != "server" && v.Kind != "network" && v.Kind != "appliance" {
		f["kind"] = "Choose server, network or appliance."
	}
	v.Tags = strings.TrimSpace(v.Tags)
	topologyText(f, "tags", v.Tags, 512, true)
	v.Lifecycle = strings.TrimSpace(v.Lifecycle)
	if !lifecycle(v.Lifecycle) {
		f["lifecycle"] = "Choose active or archived."
	}
	if len(f) > 0 {
		return v, f
	}
	return v, nil
}
func ValidateEndpoint(v Endpoint) (Endpoint, error) {
	f := FieldErrors{}
	if !ValidID(v.EnvironmentID) {
		f["environment_id"] = "Choose an existing environment."
	}
	if v.ID != "" && !ValidID(v.ID) {
		f["id"] = "Invalid identity."
	}
	v.AssetID = strings.TrimSpace(v.AssetID)
	if !ValidID(v.AssetID) {
		f["asset_id"] = "Choose an existing record in this environment."
	}
	v.Protocol = strings.TrimSpace(v.Protocol)
	if v.Protocol != "ssh" && v.Protocol != "http" && v.Protocol != "https" && v.Protocol != "tcp" && v.Protocol != "udp" {
		f["protocol"] = "Choose ssh, http, https, tcp or udp."
	}
	v.Host = strings.TrimSpace(v.Host)
	v.Host = strings.ToLower(v.Host)
	if !ValidEndpointHost(v.Host) {
		f["host"] = "Enter an IPv4, IPv6 or DNS hostname without a scheme or path."
	}
	if v.Port < 1 || v.Port > 65535 {
		f["port"] = "Use a port from 1 to 65535."
	}
	v.Status = strings.TrimSpace(v.Status)
	if !lifecycle(v.Status) {
		f["status"] = "Choose active or archived."
	}
	if len(f) > 0 {
		return v, f
	}
	return v, nil
}
func ValidateMembership(v Membership) (Membership, error) {
	f := FieldErrors{}
	if !ValidID(v.EnvironmentID) {
		f["environment_id"] = "Choose an existing environment."
	}
	if v.ID != "" && !ValidID(v.ID) {
		f["id"] = "Invalid identity."
	}
	v.ClusterID = strings.TrimSpace(v.ClusterID)
	if !ValidID(v.ClusterID) {
		f["cluster_id"] = "Choose an existing record in this environment."
	}
	v.AssetID = strings.TrimSpace(v.AssetID)
	if !ValidID(v.AssetID) {
		f["asset_id"] = "Choose an existing record in this environment."
	}
	v.Role = strings.TrimSpace(v.Role)
	topologyText(f, "role", v.Role, 80, true)
	if len(f) > 0 {
		return v, f
	}
	return v, nil
}
func ValidateService(v Service) (Service, error) {
	f := FieldErrors{}
	if !ValidID(v.EnvironmentID) {
		f["environment_id"] = "Choose an existing environment."
	}
	if v.ID != "" && !ValidID(v.ID) {
		f["id"] = "Invalid identity."
	}
	v.ClusterID = strings.TrimSpace(v.ClusterID)
	if v.ClusterID != "" && !ValidID(v.ClusterID) {
		f["cluster_id"] = "Choose an existing record in this environment."
	}
	v.Name = strings.TrimSpace(v.Name)
	topologyText(f, "name", v.Name, 120, false)
	v.ServiceType = strings.TrimSpace(v.ServiceType)
	topologyText(f, "service_type", v.ServiceType, 80, false)
	v.Lifecycle = strings.TrimSpace(v.Lifecycle)
	if !lifecycle(v.Lifecycle) {
		f["lifecycle"] = "Choose active or archived."
	}
	if len(f) > 0 {
		return v, f
	}
	return v, nil
}
func ValidateInstance(v Instance) (Instance, error) {
	f := FieldErrors{}
	if !ValidID(v.EnvironmentID) {
		f["environment_id"] = "Choose an existing environment."
	}
	if v.ID != "" && !ValidID(v.ID) {
		f["id"] = "Invalid identity."
	}
	v.ServiceID = strings.TrimSpace(v.ServiceID)
	if !ValidID(v.ServiceID) {
		f["service_id"] = "Choose an existing record in this environment."
	}
	v.Name = strings.TrimSpace(v.Name)
	topologyText(f, "name", v.Name, 120, false)
	v.Role = strings.TrimSpace(v.Role)
	topologyText(f, "role", v.Role, 80, true)
	v.InstanceKey = strings.TrimSpace(v.InstanceKey)
	topologyText(f, "instance_key", v.InstanceKey, 80, true)
	v.Lifecycle = strings.TrimSpace(v.Lifecycle)
	if !lifecycle(v.Lifecycle) {
		f["lifecycle"] = "Choose active or archived."
	}
	if len(f) > 0 {
		return v, f
	}
	return v, nil
}
func ValidateBinding(v Binding) (Binding, error) {
	f := FieldErrors{}
	if !ValidID(v.EnvironmentID) {
		f["environment_id"] = "Choose an existing environment."
	}
	if v.ID != "" && !ValidID(v.ID) {
		f["id"] = "Invalid identity."
	}
	v.InstanceID = strings.TrimSpace(v.InstanceID)
	if !ValidID(v.InstanceID) {
		f["service_instance_id"] = "Choose an existing record in this environment."
	}
	v.AssetID = strings.TrimSpace(v.AssetID)
	if !ValidID(v.AssetID) {
		f["asset_id"] = "Choose an existing record in this environment."
	}
	v.BindingRole = strings.TrimSpace(v.BindingRole)
	topologyText(f, "binding_role", v.BindingRole, 80, true)
	if len(f) > 0 {
		return v, f
	}
	return v, nil
}
