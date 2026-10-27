package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"noc-workbench/internal/integrations/vicidial"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

func vicidialFixture(t *testing.T) (*Store, string, vicidial.Scope, inventory.Cluster) {
	t.Helper()
	ctx := context.Background()
	dsn := isolatedDSN(t)
	s, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	c, e := s.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic VICIdial", ShortCode: "VICI", Status: "active"})
	if e != nil {
		t.Fatal(e)
	}
	env, e := s.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Synthetic lab", Kind: "lab", Status: "active"})
	if e != nil {
		t.Fatal(e)
	}
	cl, e := s.SaveCluster(ctx, inventory.Cluster{EnvironmentID: env.ID, Name: "Synthetic telephony", Lifecycle: "active"})
	if e != nil {
		t.Fatal(e)
	}
	return s, dsn, vicidial.Scope{CustomerID: c.ID, EnvironmentID: env.ID, ClusterID: cl.ID}, cl
}
func TestIntegrationVICIdialMetadataAndRestart(t *testing.T) {
	s, dsn, h, _ := vicidialFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	if _, e := s.VICIdialIntegration(ctx, p, h); !errors.Is(e, inventory.ErrNotFound) {
		t.Fatal("unregistered cluster", e)
	}
	if _, e := s.SaveVICIdialIntegration(ctx, workspace.Principal{}, h, vicidial.Integration{Name: "Denied"}); !errors.Is(e, workspace.ErrDenied) {
		t.Fatal("anonymous mutation", e)
	}
	v, e := s.SaveVICIdialIntegration(ctx, p, h, vicidial.Integration{Name: "Synthetic installation", Actor: "ignored", CustomerID: "ignored"})
	if e != nil {
		t.Fatal(e)
	}
	if v.Enabled || v.Version != "" || v.Revision != 1 || v.Actor != p.ID || v.CustomerID != h.CustomerID {
		t.Fatalf("default/provenance %#v", v)
	}
	old := v
	verified := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	v.Version = "2.14 synthetic"
	v.RevisionSource = "Operator-maintained lab record"
	v.VerifiedAt = &verified
	v.Enabled = true
	v, e = s.SaveVICIdialIntegration(ctx, p, h, v)
	if e != nil {
		t.Fatal(e)
	}
	if v.ID != old.ID || v.Revision != 2 || !v.CreatedAt.Equal(old.CreatedAt) {
		t.Fatal("identity or creation changed")
	}
	if _, e = s.SaveVICIdialIntegration(ctx, p, h, old); e == nil {
		t.Fatal("stale overwrite accepted")
	}
	if _, e = s.SaveVICIdialIntegration(ctx, p, h, vicidial.Integration{Name: "Duplicate"}); e == nil {
		t.Fatal("duplicate registration")
	}
	reopened, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	got, e := reopened.VICIdialIntegration(ctx, p, h)
	if e != nil || got.Revision != 2 || got.Version != v.Version || !got.VerifiedAt.Equal(verified) {
		t.Fatalf("restart lost context %+v %v", got, e)
	}
	var count int
	if e = s.pool.QueryRow(ctx, `SELECT count(*) FROM vicidial_integration WHERE id=$1`, v.ID).Scan(&count); e != nil || count != 2 {
		t.Fatal("immutable history", count, e)
	}
}
func TestIntegrationVICIdialScopeAndSQLGuards(t *testing.T) {
	s, _, h, cl := vicidialFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	v, e := s.SaveVICIdialIntegration(ctx, p, h, vicidial.Integration{Name: "Synthetic", Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	c, e := s.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic foreign", ShortCode: "FOREIGN", Status: "active"})
	if e != nil {
		t.Fatal(e)
	}
	env, e := s.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Synthetic foreign", Kind: "lab", Status: "active"})
	if e != nil {
		t.Fatal(e)
	}
	foreign := vicidial.Scope{CustomerID: c.ID, EnvironmentID: env.ID, ClusterID: cl.ID}
	if _, e = s.VICIdialIntegration(ctx, p, foreign); !errors.Is(e, inventory.ErrNotFound) {
		t.Fatal("cross-customer read", e)
	}
	if _, e = s.SaveVICIdialIntegration(ctx, p, foreign, vicidial.Integration{Name: "Cross customer"}); e == nil {
		t.Fatal("cross-customer write")
	}
	for _, attack := range []struct {
		q    string
		args []any
	}{
		{`UPDATE vicidial_integration SET name='overwrite' WHERE id=$1`, []any{v.ID}},
		{`INSERT INTO vicidial_integration(customer_id,environment_id,cluster_id,name,actor)VALUES($1,$2,$3,'Cross customer',$4)`, []any{c.ID, env.ID, cl.ID, p.ID}},
		{`INSERT INTO vicidial_integration(customer_id,environment_id,cluster_id,name,actor)VALUES($1,$2,$3,'Duplicate',$4)`, []any{h.CustomerID, h.EnvironmentID, h.ClusterID, p.ID}},
		{`INSERT INTO vicidial_integration(id,revision,customer_id,environment_id,cluster_id,name,actor,created_at)VALUES($1,2,$2,$3,$4,'Invalid provenance',$5,$6)`, []any{v.ID, h.CustomerID, h.EnvironmentID, h.ClusterID, p.ID, v.CreatedAt.Add(time.Second)}},
		{`INSERT INTO vicidial_integration(id,revision,customer_id,environment_id,cluster_id,name,version,revision_source,verified_at,actor,created_at)VALUES($1,2,$2,$3,$4,'Future','2.14','Operator',clock_timestamp()+interval '1 hour',$5,$6)`, []any{v.ID, h.CustomerID, h.EnvironmentID, h.ClusterID, p.ID, v.CreatedAt}},
	} {
		if _, e = s.pool.Exec(ctx, attack.q, attack.args...); e == nil {
			t.Fatalf("SQL guard bypass %s", attack.q)
		}
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, `INSERT INTO vicidial_integration(id,revision,customer_id,environment_id,cluster_id,name,actor,created_at)VALUES($1,2,$2,$3,$4,'Rollback',$5,$6)`, v.ID, h.CustomerID, h.EnvironmentID, h.ClusterID, p.ID, v.CreatedAt)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	got, e := s.VICIdialIntegration(ctx, p, h)
	if e != nil || got.Name != "Synthetic" || got.Revision != 1 {
		t.Fatal("rollback changed context", got, e)
	}
	cl.Lifecycle = "archived"
	if _, e = s.SaveCluster(ctx, cl); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SaveVICIdialIntegration(ctx, p, h, v); !errors.Is(e, inventory.ErrInactive) {
		t.Fatal("enabled archived owner", e)
	}
	v.Enabled = false
	if _, e = s.SaveVICIdialIntegration(ctx, p, h, v); e != nil {
		t.Fatal("cannot deactivate archived installation", e)
	}
}
func TestIntegrationVICIdialConcurrentRevision(t *testing.T) {
	s, _, h, _ := vicidialFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	v, e := s.SaveVICIdialIntegration(ctx, p, h, vicidial.Integration{Name: "Synthetic"})
	if e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, e := s.SaveVICIdialIntegration(ctx, p, h, v); results <- e }()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("optimistic revision winners", successes)
	}
	got, e := s.VICIdialIntegration(ctx, p, h)
	if e != nil || got.Revision != 2 {
		t.Fatal("revision chain", got, e)
	}
}

func TestIntegrationVICIdialCanonicalTopologyPreserved(t *testing.T) {
	s, _, h, _ := vicidialFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	other, e := s.SaveCluster(ctx, inventory.Cluster{EnvironmentID: h.EnvironmentID, Name: "Synthetic shared infrastructure", Lifecycle: "active"})
	if e != nil {
		t.Fatal(e)
	}
	var shared inventory.Asset
	for _, node := range []struct{ name, roles string }{{"Synthetic dialer one", "dialer"}, {"Synthetic dialer two", "dialer"}, {"Synthetic combined", "web, database, dialer"}} {
		asset, e := s.SaveAsset(ctx, inventory.Asset{EnvironmentID: h.EnvironmentID, Name: node.name, Kind: "server", Lifecycle: "active"})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.SaveMembership(ctx, inventory.Membership{EnvironmentID: h.EnvironmentID, ClusterID: h.ClusterID, AssetID: asset.ID, Role: node.roles}); e != nil {
			t.Fatal(e)
		}
		shared = asset
	}
	if _, e = s.SaveMembership(ctx, inventory.Membership{EnvironmentID: h.EnvironmentID, ClusterID: other.ID, AssetID: shared.ID, Role: "shared database"}); e != nil {
		t.Fatal(e)
	}
	svc, e := s.SaveService(ctx, inventory.Service{EnvironmentID: h.EnvironmentID, ClusterID: h.ClusterID, Name: "Synthetic documented application", ServiceType: "application", Lifecycle: "active"})
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"Synthetic application one", "Synthetic application two"} {
		instance, e := s.SaveInstance(ctx, inventory.Instance{EnvironmentID: h.EnvironmentID, ServiceID: svc.ID, Name: name, Lifecycle: "active"})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.SaveBinding(ctx, inventory.Binding{EnvironmentID: h.EnvironmentID, InstanceID: instance.ID, AssetID: shared.ID}); e != nil {
			t.Fatal(e)
		}
	}
	v, e := s.SaveVICIdialIntegration(ctx, p, h, vicidial.Integration{Name: "Synthetic optional context", Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	v.Enabled = false
	if _, e = s.SaveVICIdialIntegration(ctx, p, h, v); e != nil {
		t.Fatal(e)
	}
	members, e := s.ListMemberships(ctx, h.EnvironmentID)
	if e != nil || len(members) != 4 {
		t.Fatal("optional metadata replaced canonical memberships", members, e)
	}
	bindings, e := s.ListBindings(ctx, h.EnvironmentID)
	if e != nil || len(bindings) != 2 {
		t.Fatal("optional metadata replaced service hosts", bindings, e)
	}
	assets, e := s.ListAssets(ctx, h.EnvironmentID)
	if e != nil || len(assets) != 3 {
		t.Fatal("optional metadata duplicated assets", assets, e)
	}
	for _, m := range members {
		if m.AssetID == shared.ID && m.ClusterID == h.ClusterID && m.Role != "web, database, dialer" {
			t.Fatal("multi-role documentation changed")
		}
	}
}
