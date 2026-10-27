package workspace

import "context"

// Server is a read model over canonical inventory identities, not another asset.
type Server struct {
	ID, CustomerID, EnvironmentID, Name, Customer, Environment, Address string
	Clusters                                                            []ServerCluster
}
type ServerCluster struct{ ID, Name, Lifecycle string }
type ServerEndpoint struct {
	Protocol, Host, Status string
	Port                   int
	Preferred              bool
}
type ServerService struct{ ID, InstanceID, Name, Type, Instance, Role, Lifecycle, InstanceLifecycle string }
type ServerDetail struct {
	Server
	Endpoints []ServerEndpoint
	Services  []ServerService
}
type ServerRepository interface {
	Servers(context.Context, Scope, string, int) ([]Server, bool, error)
	ServerDetails(context.Context, Scope, string) (ServerDetail, error)
}
