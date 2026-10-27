package postgres

import (
	"context"
	"fmt"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
	"testing"
)

func TestIntegrationServerReadModels(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, isolatedDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	c, e := s.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic dashboard customer", ShortCode: "DASH", Status: "active"})
	must(e)
	env, e := s.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Lab", Kind: "lab", Status: "active"})
	must(e)
	a, e := s.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "First server", Kind: "server", Lifecycle: "active"})
	must(e)
	_, e = s.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Protocol: "ssh", Host: "192.0.2.45", Port: 22, Preferred: true, Status: "active"})
	must(e)
	_, e = s.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Protocol: "https", Host: "synthetic.example.invalid", Port: 443, Status: "active"})
	must(e)
	for _, name := range []string{"Alpha", "Beta"} {
		k, err := s.SaveCluster(ctx, inventory.Cluster{EnvironmentID: env.ID, Name: name, Lifecycle: "active"})
		must(err)
		_, err = s.SaveMembership(ctx, inventory.Membership{EnvironmentID: env.ID, ClusterID: k.ID, AssetID: a.ID})
		must(err)
	}
	for n := 0; n < 2; n++ {
		v, err := s.SaveService(ctx, inventory.Service{EnvironmentID: env.ID, Name: fmt.Sprintf("Service %d", n), ServiceType: "web", Lifecycle: "active"})
		must(err)
		for i := 0; i < 2; i++ {
			inst, err := s.SaveInstance(ctx, inventory.Instance{EnvironmentID: env.ID, ServiceID: v.ID, Name: fmt.Sprintf("Instance %d", i), Lifecycle: "active"})
			must(err)
			_, err = s.SaveBinding(ctx, inventory.Binding{EnvironmentID: env.ID, InstanceID: inst.ID, AssetID: a.ID})
			must(err)
		}
	}
	scope := workspace.Scope{Customers: []string{c.ID}}
	for _, raw := range []string{"First", "192.0.2.45", "synthetic.example.invalid", "dashboard customer"} {
		q, err := workspace.Query(raw)
		must(err)
		rows, more, err := s.Servers(ctx, scope, q, 0)
		must(err)
		if len(rows) != 1 || more || rows[0].ID != a.ID || len(rows[0].Clusters) != 2 || rows[0].Address != "192.0.2.45" {
			t.Fatalf("search %s: %+v", raw, rows)
		}
	}
	d, e := s.ServerDetails(ctx, scope, a.ID)
	must(e)
	if len(d.Services) != 4 || len(d.Endpoints) != 2 || len(d.Clusters) != 2 {
		t.Fatalf("relationships %+v", d)
	}
	for _, deny := range []workspace.Scope{{}, {Customers: []string{"00000000-0000-4000-8000-000000000002"}}} {
		rows, _, err := s.Servers(ctx, deny, "", 0)
		must(err)
		if len(rows) != 0 {
			t.Fatal("scope leak")
		}
		if _, err = s.ServerDetails(ctx, deny, a.ID); err == nil {
			t.Fatal("detail scope leak")
		}
	}
	for n := 0; n < 26; n++ {
		_, err := s.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: fmt.Sprintf("Server %02d", n), Kind: "server", Lifecycle: "active"})
		must(err)
	}
	rows, more, e := s.Servers(ctx, scope, "", 0)
	must(e)
	if len(rows) != 25 || !more {
		t.Fatal("first page")
	}
	next, more, e := s.Servers(ctx, scope, "", 25)
	must(e)
	if len(next) != 2 || more {
		t.Fatal("second page")
	}
	for _, x := range next {
		for _, y := range rows {
			if x.ID == y.ID {
				t.Fatal("duplicate page")
			}
		}
	}
	_, e = s.pool.Exec(ctx, `UPDATE asset SET lifecycle='archived' WHERE id=$1`, a.ID)
	must(e)
	if _, e = s.ServerDetails(ctx, scope, a.ID); e == nil {
		t.Fatal("archived server visible")
	}
}
