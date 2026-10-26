package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
	"strings"
	"testing"
	"time"
)

func TestIntegrationWorkspace(t *testing.T) {
	ctx := context.Background()
	dsn := isolatedDSN(t)
	s, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { s.Close() }()
	p := workspace.Principal{ID: workspace.OperatorID}
	svc := workspace.Service{Repository: s, Policy: workspace.LocalOperatorPolicy{}}
	a, e := s.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic Workspace", ShortCode: "WORK", Status: "active"})
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic Other", ShortCode: "OTHER", Status: "active"})
	if e != nil {
		t.Fatal(e)
	}
	env, e := s.CreateEnvironment(ctx, inventory.Environment{CustomerID: a.ID, Name: "Synthetic lab", Kind: "lab", Status: "active"})
	if e != nil {
		t.Fatal(e)
	}
	c, e := s.SaveCluster(ctx, inventory.Cluster{EnvironmentID: env.ID, Name: "Synthetic cluster", Type: "generic", Lifecycle: "active"})
	if e != nil {
		t.Fatal(e)
	}
	asset, e := s.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic machine", Kind: "server", Tags: "webtier", Lifecycle: "active"})
	if e != nil {
		t.Fatal(e)
	}
	ep, e := s.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: asset.ID, Host: "192.0.2.10", Port: 22, Protocol: "ssh", Status: "active"})
	if e != nil {
		t.Fatal(e)
	}
	service, e := s.SaveService(ctx, inventory.Service{EnvironmentID: env.ID, ClusterID: c.ID, Name: "Synthetic web", ServiceType: "web", Lifecycle: "active"})
	if e != nil {
		t.Fatal(e)
	}
	instance, e := s.SaveInstance(ctx, inventory.Instance{EnvironmentID: env.ID, ServiceID: service.ID, Name: "Synthetic instance", Role: "worker", Lifecycle: "active"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.SaveMembership(ctx, inventory.Membership{EnvironmentID: env.ID, ClusterID: c.ID, AssetID: asset.ID, Role: "web"}); e != nil {
		t.Fatal(e)
	}
	targets := map[string]string{"customers": a.ID, "environments": env.ID, "clusters": c.ID, "assets": asset.ID, "endpoints": ep.ID, "services": service.ID, "instances": instance.ID}
	for kind, id := range targets {
		target, err := svc.Target(ctx, p, kind, id)
		if err != nil {
			t.Fatal(kind, err)
		}
		if err = svc.Change(ctx, p, target, workspace.Change{Operation: "visit"}); err != nil {
			t.Fatal(kind, err)
		}
	}
	ct, e := svc.Target(ctx, p, "clusters", c.ID)
	if e != nil {
		t.Fatal(e)
	}
	change := func(c workspace.Change) {
		t.Helper()
		if e := svc.Change(ctx, p, ct, c); e != nil {
			t.Fatal(c.Operation, e)
		}
	}
	related, e := svc.Related(ctx, p, ct)
	if e != nil || len(related) != 3 {
		t.Fatal("cluster context", related, e)
	}
	if related[0].ID != asset.ID || !strings.Contains(related[0].Summary, "membership role: web") {
		t.Fatal("host roles", related)
	}
	change(workspace.Change{Operation: "pin"})
	change(workspace.Change{Operation: "pin"})
	change(workspace.Change{Operation: "note.save", Body: "Synthetic searchable runbook <script>alert(1)</script>", Visibility: "private"})
	notes, e := svc.Notes(ctx, p, ct)
	if e != nil || len(notes) != 1 || notes[0].PrincipalID != p.ID {
		t.Fatal(notes, e)
	}
	change(workspace.Change{Operation: "note.save", ID: notes[0].ID, Body: "Synthetic runbook changed", Visibility: "shared"})
	change(workspace.Change{Operation: "link.save", Label: "Synthetic RTM", URL: "https://rtm.example.invalid/monitor", Type: "rtm", Pinned: true})
	links, e := svc.Links(ctx, p, ct)
	if e != nil || len(links) != 1 || !links[0].Pinned {
		t.Fatal(links, e)
	}
	change(workspace.Change{Operation: "link.save", ID: links[0].ID, Label: "Synthetic RTM updated", URL: "https://rtm.example.invalid/updated", Type: "rtm"})
	for _, q := range []string{"Synthetic", "192.0.2", "webt", "worker", "runbo"} {
		items, _, err := svc.Search(ctx, p, q, 0)
		if err != nil || len(items) == 0 {
			t.Fatal(q, items, err)
		}
	}
	q, _ := workspace.Query("Synthetic")
	items, _, e := s.WorkspaceSearch(ctx, workspace.Scope{Customers: []string{b.ID}}, p, q, 0)
	if e != nil || len(items) != 1 || items[0].ID != b.ID {
		t.Fatal("scope leaked", items, e)
	}
	items, _, e = s.WorkspaceSearch(ctx, workspace.Scope{}, p, "", 0)
	if e != nil || len(items) != 0 {
		t.Fatal("empty scope leaked", e)
	}
	if _, e = s.WorkspaceTarget(ctx, workspace.Scope{Customers: []string{b.ID}}, "clusters", c.ID); !errors.Is(e, inventory.ErrNotFound) {
		t.Fatal("target scope", e)
	}
	if e = svc.Change(ctx, workspace.Principal{ID: b.ID}, ct, workspace.Change{Operation: "pin"}); !errors.Is(e, workspace.ErrDenied) {
		t.Fatal("unknown principal", e)
	}
	// Real SQL writes must fail for the intended constraint, not a syntax error.
	rejectCode := func(code, sql string, args ...any) {
		t.Helper()
		_, e := s.pool.Exec(ctx, sql, args...)
		var pe *pgconn.PgError
		if !errors.As(e, &pe) || pe.Code != code {
			t.Fatalf("expected constraint rejection: %v", e)
		}
	}
	freshAsset, e := s.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic ownership proof", Kind: "server", Lifecycle: "active"})
	if e != nil {
		t.Fatal(e)
	}
	rejectCode("23503", `INSERT INTO workspace_target(kind,customer_id,environment_id,asset_id) VALUES('assets',$1,$2,$3)`, b.ID, env.ID, freshAsset.ID)
	rejectCode("23514", `INSERT INTO workspace_target(kind,customer_id,environment_id,asset_id) VALUES('assets',$1,NULL,$2)`, a.ID, freshAsset.ID)
	rejectCode("23514", `INSERT INTO workspace_target(kind,customer_id,environment_id,cluster_id) VALUES('assets',$1,$2,$3)`, a.ID, env.ID, c.ID)
	rejectCode("23514", `UPDATE workspace_target SET customer_id=$1 WHERE kind='clusters'`, b.ID)
	rejectCode("23514", `UPDATE operator_note SET principal_id=$1`, b.ID)
	rejectCode("23505", `INSERT INTO workspace_pin(principal_id,target_id) SELECT $1,id FROM workspace_target WHERE kind='clusters'`, p.ID)
	rejectCode("23503", `INSERT INTO operator_note(target_id,principal_id,body,visibility) SELECT id,$1,'orphan','private' FROM workspace_target LIMIT 1`, b.ID)
	rejectCode("23514", `INSERT INTO external_link(target_id,principal_id,label,url,type) SELECT id,$1,'Unsafe','javascript:alert(1)','rtm' FROM workspace_target WHERE kind='clusters'`, p.ID)
	// A valid write followed by a failing scoped FK rolls back atomically.
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, `INSERT INTO operator_note(target_id,principal_id,body,visibility) SELECT id,$1,'rollback sentinel','private' FROM workspace_target WHERE kind='clusters'`, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, `INSERT INTO workspace_target(kind,customer_id,environment_id,asset_id) VALUES('assets',$1,$2,$3)`, b.ID, env.ID, asset.ID)
	if e == nil {
		t.Fatal("invalid transaction accepted")
	}
	_ = tx.Rollback(ctx)
	var count int
	if e = s.pool.QueryRow(ctx, `SELECT count(*) FROM operator_note WHERE body='rollback sentinel'`).Scan(&count); e != nil || count != 0 {
		t.Fatal("rollback lost", e)
	}
	// Deterministic pages and physical retention bound.
	for i := 0; i < 30; i++ {
		v, e := s.CreateCustomer(ctx, inventory.Customer{DisplayName: fmt.Sprintf("Synthetic history %02d", i), ShortCode: fmt.Sprintf("H%02d", i), Status: "active"})
		if e != nil {
			t.Fatal(e)
		}
		tt, _ := svc.Target(ctx, p, "customers", v.ID)
		if e = svc.Change(ctx, p, tt, workspace.Change{Operation: "visit"}); e != nil {
			t.Fatal(e)
		}
	}
	recent, e := svc.Targets(ctx, p, false)
	if e != nil || len(recent) != 20 || recent[0].Label != "Synthetic history 29" {
		t.Fatal("recent ordering", recent, e)
	}
	first, more, e := svc.Search(ctx, p, "history", 0)
	if e != nil || !more || len(first) != 25 {
		t.Fatal("pagination", len(first), more, e)
	}
	second, more, e := svc.Search(ctx, p, "history", 25)
	if e != nil || more || len(second) != 5 || first[24].ID == second[0].ID {
		t.Fatal("second page", second, e)
	}
	s.Close()
	s, e = Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	svc.Repository = s
	if pins, e := svc.Targets(ctx, p, true); e != nil || len(pins) != 1 {
		t.Fatal("pin persistence", pins, e)
	}
	if n, e := svc.Notes(ctx, p, ct); e != nil || len(n) != 1 || n[0].Body != "Synthetic runbook changed" {
		t.Fatal("note persistence", n, e)
	}
	c.Lifecycle = "archived"
	if _, e = s.SaveCluster(ctx, c); e != nil {
		t.Fatal(e)
	}
	rejectCode("23514", `INSERT INTO operator_note(target_id,principal_id,body,visibility) SELECT id,$1,'archived','private' FROM workspace_target WHERE kind='clusters'`, p.ID)
	if e = svc.Change(ctx, p, ct, workspace.Change{Operation: "pin"}); !errors.Is(e, inventory.ErrInactive) {
		t.Fatal("archived pin", e)
	}
	change(workspace.Change{Operation: "unpin"})
	change(workspace.Change{Operation: "note.remove", ID: notes[0].ID})
	change(workspace.Change{Operation: "link.remove", ID: links[0].ID})
}
func TestIntegrationWorkspaceNW005Upgrade(t *testing.T) {
	ctx := context.Background()
	dsn := isolatedDSN(t)
	conn, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(ctx)
	if _, e = conn.Exec(ctx, `CREATE TABLE schema_migration(version text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP)`); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"001_sessions.sql", "002_operator_settings.sql", "003_customer_environment.sql", "004_topology.sql"} {
		name = "migrations/" + name
		b, _ := migrationFiles.ReadFile(name)
		if _, e = conn.Exec(ctx, string(b)); e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		if _, e = conn.Exec(ctx, `INSERT INTO schema_migration(version,checksum)VALUES($1,$2)`, name, hex.EncodeToString(sum[:])); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = conn.Exec(ctx, `INSERT INTO customer(id,display_name,short_code)VALUES('00000000-0000-4000-8000-000000000010','Synthetic existing','BASE');INSERT INTO operator_setting(id,note)VALUES(1,'Synthetic workspace retained');INSERT INTO operator_session(token_hash,csrf_token,expires_at)VALUES(repeat('a',64),repeat('b',64),CURRENT_TIMESTAMP+interval '1 hour')`); e != nil {
		t.Fatal(e)
	}
	s, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if v, e := s.GetNote(ctx); e != nil || v != "Synthetic workspace retained" {
		t.Fatal(v, e)
	}
	if v, e := s.Session(ctx, stringRepeat("a", 64)); e != nil || v.ExpiresAt.Before(time.Now()) {
		t.Fatal("session lost", e)
	}
	if v, e := s.Customer(ctx, "00000000-0000-4000-8000-000000000010"); e != nil || v.ShortCode != "BASE" {
		t.Fatal("customer lost", e)
	}
}
func stringRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestIntegrationWorkspaceBounds(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, isolatedDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p := workspace.Principal{ID: workspace.OperatorID}
	svc := workspace.Service{Repository: s, Policy: workspace.LocalOperatorPolicy{}}
	_, e = s.pool.Exec(ctx, `INSERT INTO customer(display_name,short_code) SELECT 'Synthetic bound '||x,'BOUND_'||x FROM generate_series(1,1030) x;INSERT INTO workspace_target(kind,customer_id) SELECT 'customers',id FROM customer`)
	if e != nil {
		t.Fatal(e)
	}
	rows, more, e := svc.Search(ctx, p, "bound", 1000)
	if e != nil || more || len(rows) != 25 {
		t.Fatal("terminal page", len(rows), more, e)
	}
	_, more, e = svc.Search(ctx, p, "bound", 999)
	if e != nil || more {
		t.Fatal("unaligned terminal page", more, e)
	}
	var id string
	if e = s.pool.QueryRow(ctx, `SELECT id::text FROM customer ORDER BY short_code LIMIT 1`).Scan(&id); e != nil {
		t.Fatal(e)
	}
	target, e := svc.Target(ctx, p, "customers", id)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.pool.Exec(ctx, `INSERT INTO workspace_pin(principal_id,target_id) SELECT $1,id FROM workspace_target ORDER BY resource_id LIMIT 100`, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.pool.Exec(ctx, `INSERT INTO operator_note(principal_id,target_id,body,visibility) SELECT $1,t.id,'Synthetic note '||x,'private' FROM workspace_target t CROSS JOIN generate_series(1,100) x WHERE t.resource_id=$2`, p.ID, id)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.pool.Exec(ctx, `INSERT INTO external_link(principal_id,target_id,label,url,type) SELECT $1,t.id,'Synthetic link '||x,'https://example.invalid/','rtm' FROM workspace_target t CROSS JOIN generate_series(1,100) x WHERE t.resource_id=$2`, p.ID, id)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []workspace.Change{{Operation: "note.save", Body: "overflow", Visibility: "private"}, {Operation: "link.save", Label: "overflow", URL: "https://example.invalid/", Type: "rtm"}} {
		if e = svc.Change(ctx, p, target, c); !errors.Is(e, workspace.ErrLimit) {
			t.Fatal(c.Operation, e)
		}
	}
	if e = s.pool.QueryRow(ctx, `SELECT resource_id::text FROM workspace_target WHERE id NOT IN(SELECT target_id FROM workspace_pin) LIMIT 1`).Scan(&id); e != nil {
		t.Fatal(e)
	}
	unpinned, e := svc.Target(ctx, p, "customers", id)
	if e != nil {
		t.Fatal(e)
	}
	if e = svc.Change(ctx, p, unpinned, workspace.Change{Operation: "pin"}); !errors.Is(e, workspace.ErrLimit) {
		t.Fatal("pin overflow", e)
	}
	var pinID string
	if e = s.pool.QueryRow(ctx, `SELECT t.resource_id::text FROM workspace_pin x JOIN workspace_target t ON t.id=x.target_id LIMIT 1`).Scan(&pinID); e != nil {
		t.Fatal(e)
	}
	pinned, e := svc.Target(ctx, p, "customers", pinID)
	if e != nil {
		t.Fatal(e)
	}
	if e = svc.Change(ctx, p, pinned, workspace.Change{Operation: "pin"}); e != nil {
		t.Fatal("idempotent pin at limit", e)
	}
}
