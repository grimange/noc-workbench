package workspace

import (
	"context"
	"noc-workbench/internal/inventory"
)

// Registration creates canonical inventory records without granting remote authority.
type Registration struct {
	CustomerID, EnvironmentID, Name, Host string
	Port                                  int
}
type RegisteredServer struct {
	Asset    inventory.Asset
	Endpoint inventory.Endpoint
}
type RegistrationRepository interface {
	RegisterServer(context.Context, Principal, Registration) (RegisteredServer, error)
}

func ValidateRegistration(v Registration) (Registration, error) {
	f := inventory.FieldErrors{}
	if !inventory.ValidID(v.CustomerID) {
		f["customer"] = "Choose an active customer."
	}
	if v.EnvironmentID != "" && !inventory.ValidID(v.EnvironmentID) {
		f["placement"] = "Choose a valid registration group."
	}
	// The internal placeholder is used only to reuse canonical field validation.
	a, e := inventory.ValidateAsset(inventory.Asset{EnvironmentID: OperatorID, Name: v.Name, Kind: "server", Lifecycle: "active"})
	if e != nil {
		f["name"] = "Enter a server name of 1–120 plain-text characters."
	}
	ep, e := inventory.ValidateEndpoint(inventory.Endpoint{EnvironmentID: OperatorID, AssetID: OperatorID, Protocol: "ssh", Host: v.Host, Port: v.Port, Status: "active"})
	if e != nil {
		f["address"] = "Enter a valid hostname or IP address and SSH port (1–65535)."
	}
	v.Name, v.Host = a.Name, ep.Host
	if len(f) > 0 {
		return v, f
	}
	return v, nil
}
