package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/inventory"
	"testing"
)

func TestIntegrationTopologyRelationships(t *testing.T) {
	ctx := context.Background()
	dsn := isolatedDSN(t)
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	c, err := s.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic topology", ShortCode: "TOPO", Status: "active"})
	must(err)
	e, err := s.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Synthetic lab", Kind: "lab", Status: "active"})
	must(err)
	other, err := s.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Synthetic other", Kind: "test", Status: "active"})
	must(err)
	cluster, err := s.SaveCluster(ctx, inventory.Cluster{EnvironmentID: e.ID, Name: "Synthetic web", Type: "generic", Tags: "synthetic lab", Lifecycle: "active"})
	must(err)
	cluster2, err := s.SaveCluster(ctx, inventory.Cluster{EnvironmentID: e.ID, Name: "Synthetic database", Lifecycle: "active"})
	must(err)
	a, err := s.SaveAsset(ctx, inventory.Asset{EnvironmentID: e.ID, Name: "Synthetic host", Kind: "server", Lifecycle: "active"})
	must(err)
	a2, err := s.SaveAsset(ctx, inventory.Asset{EnvironmentID: e.ID, Name: "Synthetic second host", Kind: "network", Lifecycle: "active"})
	must(err)
	alien, err := s.SaveAsset(ctx, inventory.Asset{EnvironmentID: other.ID, Name: "Synthetic alien", Kind: "appliance", Lifecycle: "active"})
	must(err)
	ep, err := s.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: e.ID, AssetID: a.ID, Protocol: "ssh", Host: "192.0.2.1", Port: 22, Preferred: true, Status: "active"})
	must(err)
	for _, host := range []string{"2001:db8::1", "synthetic.example.invalid"} {
		_, err = s.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: e.ID, AssetID: a.ID, Protocol: "https", Host: host, Port: 443, Status: "active"})
		must(err)
	}
	// Same address on a different asset is valid; identity is not an IP.
	ep.ID = ""
	ep.AssetID = a2.ID
	_, err = s.SaveEndpoint(ctx, ep)
	must(err)
	membership, err := s.SaveMembership(ctx, inventory.Membership{EnvironmentID: e.ID, ClusterID: cluster.ID, AssetID: a.ID, Role: "web"})
	must(err)
	_, err = s.SaveMembership(ctx, inventory.Membership{EnvironmentID: e.ID, ClusterID: cluster2.ID, AssetID: a.ID, Role: "database"})
	must(err)
	service, err := s.SaveService(ctx, inventory.Service{EnvironmentID: e.ID, ClusterID: cluster.ID, Name: "Synthetic web service", ServiceType: "web", Lifecycle: "active"})
	must(err)
	service2, err := s.SaveService(ctx, inventory.Service{EnvironmentID: e.ID, Name: "Synthetic database service", ServiceType: "database", Lifecycle: "active"})
	must(err)
	instance, err := s.SaveInstance(ctx, inventory.Instance{EnvironmentID: e.ID, ServiceID: service.ID, Name: "Synthetic web 1", Role: "worker", InstanceKey: "web-1", Lifecycle: "active"})
	must(err)
	instance2, err := s.SaveInstance(ctx, inventory.Instance{EnvironmentID: e.ID, ServiceID: service.ID, Name: "Synthetic web 2", Lifecycle: "active"})
	must(err)
	instance3, err := s.SaveInstance(ctx, inventory.Instance{EnvironmentID: e.ID, ServiceID: service2.ID, Name: "Synthetic database", Lifecycle: "active"})
	must(err)
	binding, err := s.SaveBinding(ctx, inventory.Binding{EnvironmentID: e.ID, InstanceID: instance.ID, AssetID: a.ID, BindingRole: "primary"})
	must(err)
	for _, v := range []inventory.Binding{{EnvironmentID: e.ID, InstanceID: instance.ID, AssetID: a2.ID}, {EnvironmentID: e.ID, InstanceID: instance2.ID, AssetID: a.ID}, {EnvironmentID: e.ID, InstanceID: instance3.ID, AssetID: a.ID}} {
		_, err = s.SaveBinding(ctx, v)
		must(err)
	}
	// Direct SQL cannot bypass scoped FK, uniqueness, immutable ownership or host validation.
	for _, attack := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO cluster_membership(environment_id,cluster_id,asset_id)VALUES($1,$2,$3)`, []any{e.ID, cluster.ID, alien.ID}},
		{`INSERT INTO service(environment_id,cluster_id,name,service_type)VALUES($1,$2,'Invalid','web')`, []any{other.ID, cluster.ID}},
		{`INSERT INTO service_instance(environment_id,service_id,name)VALUES($1,$2,'Invalid')`, []any{other.ID, service.ID}},
		{`INSERT INTO service_instance_host(environment_id,service_instance_id,asset_id)VALUES($1,$2,$3)`, []any{e.ID, instance.ID, alien.ID}},
		{`INSERT INTO asset_endpoint(environment_id,asset_id,protocol,host,port)VALUES($1,$2,'ssh','192.0.2.4',22)`, []any{other.ID, a.ID}},
		{`UPDATE asset SET environment_id=$1 WHERE id=$2`, []any{other.ID, a.ID}},
		{`UPDATE service_instance SET service_id=$1 WHERE id=$2`, []any{service2.ID, instance.ID}},
		{`UPDATE asset_endpoint SET asset_id=$1 WHERE asset_id=$2`, []any{a2.ID, a.ID}},
		{`INSERT INTO cluster_membership(environment_id,cluster_id,asset_id)VALUES($1,$2,$3)`, []any{e.ID, cluster.ID, a.ID}},
		{`INSERT INTO service_instance_host(environment_id,service_instance_id,asset_id)VALUES($1,$2,$3)`, []any{e.ID, instance.ID, a.ID}},
		{`INSERT INTO asset_endpoint(environment_id,asset_id,protocol,host,port)VALUES($1,$2,'ssh','https://example.invalid',22)`, []any{e.ID, a.ID}},
		{`INSERT INTO asset_endpoint(environment_id,asset_id,protocol,host,port)VALUES($1,$2,'ssh','192.0.2.5',65536)`, []any{e.ID, a.ID}},
		{`INSERT INTO asset_endpoint(environment_id,asset_id,protocol,host,port,preferred)VALUES($1,$2,'ssh','192.0.2.5',22,true)`, []any{e.ID, a.ID}},
		{`DELETE FROM asset WHERE id=$1`, []any{a.ID}},
		{`DELETE FROM environment WHERE id=$1`, []any{e.ID}},
	} {
		if _, err := s.pool.Exec(ctx, attack.q, attack.args...); err == nil {
			t.Fatalf("accepted SQL attack %s", attack.q)
		}
	}
	// Cross-customer scope is also rejected through the same environment FKs.
	c2, err := s.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic other owner", ShortCode: "OTHER", Status: "active"})
	must(err)
	e2, err := s.CreateEnvironment(ctx, inventory.Environment{CustomerID: c2.ID, Name: "Lab", Kind: "lab", Status: "active"})
	must(err)
	if _, err = s.pool.Exec(ctx, `INSERT INTO service_instance_host(environment_id,service_instance_id,asset_id)VALUES($1,$2,$3)`, e2.ID, instance.ID, a.ID); err == nil {
		t.Fatal("cross-customer binding")
	}
	tx, err := s.pool.Begin(ctx)
	must(err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `UPDATE asset SET name='must rollback' WHERE id=$1`, a.ID)
	must(err)
	if _, err = tx.Exec(ctx, `INSERT INTO cluster_membership(environment_id,cluster_id,asset_id)VALUES($1,$2,$3)`, e.ID, cluster.ID, alien.ID); err == nil {
		t.Fatal("invalid transaction")
	}
	if err = tx.Commit(ctx); err == nil {
		t.Fatal("partial transaction committed")
	}
	got, err := s.GetAsset(ctx, e.ID, a.ID)
	must(err)
	if got.Name != a.Name {
		t.Fatal("rollback lost")
	}
	// Typed updates preserve stable IDs; nullable service-cluster assignment stays scoped.
	a.Name = "Synthetic renamed"
	a, err = s.SaveAsset(ctx, a)
	must(err)
	service.ClusterID = ""
	service, err = s.SaveService(ctx, service)
	must(err)
	instance.Role = "secondary"
	instance, err = s.SaveInstance(ctx, instance)
	must(err)
	cluster.Type = "web"
	cluster, err = s.SaveCluster(ctx, cluster)
	must(err)
	// Archival retains edges, prevents new active assignments; removal is always available.
	a.Lifecycle = "archived"
	a, err = s.SaveAsset(ctx, a)
	must(err)
	if _, err = s.SaveBinding(ctx, inventory.Binding{EnvironmentID: e.ID, InstanceID: instance2.ID, AssetID: a.ID, BindingRole: "blocked"}); err == nil {
		t.Fatal("archived reference accepted")
	}
	if _, err = s.pool.Exec(ctx, `UPDATE cluster_membership SET role='blocked' WHERE id=$1`, membership.ID); err == nil {
		t.Fatal("direct SQL archived assignment")
	}
	must(s.RemoveMembership(ctx, e.ID, membership.ID))
	must(s.RemoveBinding(ctx, e.ID, binding.ID))
	if _, err = s.GetAsset(ctx, other.ID, a.ID); err == nil {
		t.Fatal("unscoped read")
	}
	e.Status = "archived"
	_, err = s.UpdateEnvironment(ctx, e)
	must(err)
	if _, err = s.SaveCluster(ctx, inventory.Cluster{EnvironmentID: e.ID, Name: "Blocked", Lifecycle: "active"}); err == nil {
		t.Fatal("archived environment assignment")
	}
	// Repeat migrations and reconnect preserve topology IDs and all relationship counts.
	s.Close()
	s, err = Open(ctx, dsn)
	must(err)
	must(s.Migrate(ctx))
	got, err = s.GetAsset(ctx, e.ID, a.ID)
	must(err)
	if got.Name != a.Name || got.Lifecycle != "archived" {
		t.Fatal("restart persistence")
	}
	endpoints, err := s.ListEndpoints(ctx, e.ID)
	must(err)
	if len(endpoints) != 4 {
		t.Fatal("endpoint count", len(endpoints))
	}
	instances, err := s.ListInstances(ctx, e.ID)
	must(err)
	if len(instances) != 3 {
		t.Fatal("instance count")
	}
	bindings, err := s.ListBindings(ctx, e.ID)
	must(err)
	if len(bindings) != 3 {
		t.Fatal("host binding count")
	}
}

func TestIntegrationTopologyNW004Upgrade(t *testing.T) {
	ctx := context.Background()
	dsn := isolatedDSN(t)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err = conn.Exec(ctx, `CREATE TABLE schema_migration(version text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"migrations/001_sessions.sql", "migrations/002_operator_settings.sql", "migrations/003_customer_environment.sql"} {
		b, _ := migrationFiles.ReadFile(name)
		if _, err = conn.Exec(ctx, string(b)); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if _, err = conn.Exec(ctx, `INSERT INTO schema_migration(version,checksum)VALUES($1,$2)`, name, hex.EncodeToString(sum[:])); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = conn.Exec(ctx, `INSERT INTO customer(id,display_name,short_code)VALUES('00000000-0000-4000-8000-000000000001','Synthetic accepted customer','BASE'); INSERT INTO environment(id,customer_id,name,kind)VALUES('00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000001','Synthetic accepted lab','lab');INSERT INTO operator_setting(id,note)VALUES(1,'Synthetic accepted workspace')`); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if c, err := s.Customer(ctx, "00000000-0000-4000-8000-000000000001"); err != nil || c.ShortCode != "BASE" {
		t.Fatal("customer lost", err)
	}
	if e, err := s.Environment(ctx, "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"); err != nil || e.Name != "Synthetic accepted lab" {
		t.Fatal("environment lost", err)
	}
	if note, err := s.GetNote(ctx); err != nil || note != "Synthetic accepted workspace" {
		t.Fatal("workspace lost", err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
}
