package postgres

import (
	"context"
	"testing"

	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

func TestIntegrationDirectServerRegistration(t *testing.T) {
	ctx := context.Background()
	db, e := Open(ctx, isolatedDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	actor := workspace.Principal{ID: workspace.OperatorID}
	customer := func(name, code string) inventory.Customer {
		t.Helper()
		c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: name, ShortCode: code, Status: "active"})
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	a, b := customer("Synthetic registration A", "REG_A"), customer("Synthetic registration B", "REG_B")
	v := workspace.Registration{CustomerID: a.ID, Name: "Synthetic server", Host: "ssh.example.invalid", Port: 22}
	if _, e := db.RegisterServer(ctx, workspace.Principal{ID: "foreign"}, v); e == nil {
		t.Fatal("foreign registration allowed")
	}
	got, e := db.RegisterServer(ctx, actor, v)
	if e != nil {
		t.Fatal(e)
	}
	if got.Asset.Kind != "server" || got.Endpoint.AssetID != got.Asset.ID || got.Endpoint.Host != v.Host || !got.Endpoint.Preferred {
		t.Fatal("canonical records", got)
	}
	env, e := db.Environment(ctx, a.ID, got.Asset.EnvironmentID)
	if e != nil || env.Name != "Monitoring" {
		t.Fatal("internal placement", env, e)
	}
	counts := func() (a, b, c int) {
		t.Helper()
		if e := db.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM environment),(SELECT count(*) FROM asset),(SELECT count(*) FROM asset_endpoint)`).Scan(&a, &b, &c); e != nil {
			t.Fatal(e)
		}
		return
	}
	x, y, z := counts()
	if _, e := db.RegisterServer(ctx, actor, v); e == nil {
		t.Fatal("duplicate accepted")
	}
	if a, b, c := counts(); a != x || b != y || c != z {
		t.Fatal("duplicate leaked writes")
	}
	v.Name = "Synthetic second"
	v.Host = "second.example.invalid"
	second, e := db.RegisterServer(ctx, actor, v)
	if e != nil || second.Asset.EnvironmentID != env.ID {
		t.Fatal("sole placement not reused", e)
	}
	v.CustomerID = b.ID
	v.EnvironmentID = env.ID
	if _, e := db.RegisterServer(ctx, actor, v); e == nil {
		t.Fatal("crosscustomer placement accepted")
	}
	if _, e := db.pool.Exec(ctx, `UPDATE environment SET customer_id=$1 WHERE id=$2`, b.ID, env.ID); e == nil {
		t.Fatal("ownership constraint lost")
	}
	v.CustomerID = a.ID
	v.EnvironmentID = ""
	v.Host = "third.example.invalid"
	extra, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: a.ID, Name: "Existing second group", Kind: "lab", Status: "active"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := db.RegisterServer(ctx, actor, v); e == nil {
		t.Fatal("ambiguous placement selected silently")
	}
	v.EnvironmentID = extra.ID
	if _, e := db.RegisterServer(ctx, actor, v); e != nil {
		t.Fatal(e)
	}
	for _, host := range []string{"-oProxyCommand=bad", "bad host", "user@host", "https://example.invalid/"} {
		v.Host = host
		if _, e := db.RegisterServer(ctx, actor, v); e == nil {
			t.Fatal("invalid destination", host)
		}
	}
	archivedOwner := customer("Synthetic archived owner", "REG_ARCH")
	archived, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: archivedOwner.ID, Name: "Monitoring", Kind: "lab", Status: "archived"})
	if e != nil {
		t.Fatal(e)
	}
	registered, e := db.RegisterServer(ctx, actor, workspace.Registration{CustomerID: archivedOwner.ID, Name: "Archived-safe registration", Host: "archive-safe.example.invalid", Port: 22})
	if e != nil {
		t.Fatal("archived name blocked registration", e)
	}
	placement, e := db.Environment(ctx, archivedOwner.ID, registered.Asset.EnvironmentID)
	if e != nil || placement.Name != "Monitoring 2" {
		t.Fatal("deterministic placement", placement, e)
	}
	old, e := db.Environment(ctx, archivedOwner.ID, archived.ID)
	if e != nil || old.Status != "archived" {
		t.Fatal("archived record changed", old, e)
	}
	var schedules, profiles int
	if e := db.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM collection_schedule),(SELECT count(*) FROM connection_profile)`).Scan(&schedules, &profiles); e != nil || schedules != 0 || profiles != 0 {
		t.Fatal("registration granted remote authority", e)
	}
}
