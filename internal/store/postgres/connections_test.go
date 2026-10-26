package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/testlab"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIntegrationEnrollmentWorkflow(t *testing.T) {
	ctx := context.Background()
	dsn := isolatedDSN(t)
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { db.Close() }()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic enrollment", ShortCode: "ENROLL", Status: "active"})
	must(e)
	env, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Authorized lab", Kind: "lab", Status: "active"})
	must(e)
	asset, e := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic host", Kind: "server", Lifecycle: "active"})
	must(e)
	ep, e := db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: asset.ID, Protocol: "ssh", Host: "127.0.0.1", Port: 2222, Status: "active"})
	must(e)
	catalog := filepath.Join(t.TempDir(), "catalog.json")
	credential := sshcli.Credential{ID: "synthetic", Enabled: true, User: "lab", IdentityFile: "/nonexistent/synthetic", IdentitySHA256: "0000000000000000000000000000000000000000000000000000000000000000"}
	write := func() { b, _ := json.Marshal([]sshcli.Credential{credential}); must(os.WriteFile(catalog, b, 0600)) }
	write()
	svc, e := connections.New(db, db, connections.Catalog(catalog), connections.OperatorPolicy{})
	must(e)
	actor := workspace.Principal{ID: workspace.OperatorID}
	r, e := svc.Create(ctx, actor, c.ID, env.ID, asset.ID, ep.ID, ep.Host, "synthetic")
	must(e)
	act := func(action, fp, evidence string) {
		t.Helper()
		r, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, action, fp, evidence)
		must(e)
	}
	if _, e = svc.Approve(ctx, actor, r.Target(), sshcli.ProfileUse); e == nil {
		t.Fatal("draft authorized network")
	}
	if _, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, "verify", "", ""); e == nil {
		t.Fatal("unapproved verify")
	}
	act("submit", "", "")
	if _, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, "authorize", "", ""); e == nil {
		t.Fatal("missing attestation")
	}
	act("authorize", "", "authorized")
	if _, e = svc.Approve(ctx, actor, r.Target(), sshcli.ExecutePermission); e == nil {
		t.Fatal("unknown host executed")
	}
	// Protected credential revocation and changes are checked without network.
	credential.Enabled = false
	write()
	if _, e = svc.Approve(ctx, actor, r.Target(), sshcli.ProfileUse); !errors.Is(e, connections.ErrCredential) {
		t.Fatal("revocation", e)
	}
	credential.Enabled = true
	write()
	old := r
	ep.Port++
	ep, e = db.SaveEndpoint(ctx, ep)
	must(e)
	if _, e = svc.Approve(ctx, actor, old.Target(), sshcli.ProfileUse); e == nil {
		t.Fatal("stale endpoint approved")
	}
	r, e = db.Enrollment(ctx, ep.ID, r.ID)
	must(e)
	if r.State != "identity_changed" || r.Revision <= old.Revision {
		t.Fatal("invalidation", r.State)
	}
	act("review", "", "")
	act("authorize", "", "authorized")
	// Two duplicate approvals/updates cannot both commit the same revision.
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, "disable", "", "")
			if e == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatal("CAS winners", wins)
	}
	r, e = db.Enrollment(ctx, ep.ID, r.ID)
	must(e)
	if _, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, "verify", "", ""); e == nil {
		t.Fatal("disabled verify")
	}
	// Direct SQL cannot attach an endpoint to a different asset/environment.
	other, e := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Other synthetic host", Kind: "server", Lifecycle: "active"})
	must(e)
	_, e = db.pool.Exec(ctx, `INSERT INTO connection_profile(customer_id,environment_id,asset_id,endpoint_id,state,details)VALUES($1,$2,$3,$4,'draft','{}')`, c.ID, env.ID, other.ID, ep.ID)
	if e == nil {
		t.Fatal("wrong endpoint owner SQL accepted")
	}
	// Empty actor strings cannot bypass generated principal foreign keys/checks.
	_, e = db.pool.Exec(ctx, `UPDATE connection_profile SET state='pending_host_key_verification',revision=revision+1,details=details||'{"AuthorizedBy":"","AuthorizedAt":""}'::jsonb WHERE id=$1`, r.ID)
	if e == nil {
		t.Fatal("empty authorizer accepted by SQL")
	}
	_, e = db.pool.Exec(ctx, `UPDATE connection_profile SET revision=revision+1,details=details||'{"ApprovedKey":"x","ApprovedFingerprint":"x","Evidence":"source","ApprovedBy":"","ApprovedAt":""}'::jsonb WHERE id=$1`, r.ID)
	if e == nil {
		t.Fatal("empty approver accepted by SQL")
	}
	badActor := workspace.Principal{ID: other.ID}
	if _, e = svc.List(ctx, badActor, c.ID, env.ID, asset.ID); e == nil {
		t.Fatal("unknown actor allowed")
	}
	var audits int
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM connection_audit WHERE profile_id=$1`, r.ID).Scan(&audits))
	if audits < 5 {
		t.Fatal("audit missing", audits)
	}
	db.Close()
	db, e = Open(ctx, dsn)
	must(e)
	persisted, e := db.Enrollment(ctx, ep.ID, r.ID)
	must(e)
	if persisted.State != "disabled" {
		t.Fatal("restart state", persisted.State)
	}
	must(db.Migrate(ctx))
	t.Log("PASS lifecycle, permission/no-network gates, revocation, endpoint suspension, optimistic concurrency, direct SQL ownership, audit, restart")
}
func TestIntegrationRealSSHEnrollment(t *testing.T) {
	dsn := isolatedDSN(t)
	lab := testlab.Start(t)
	ctx := context.Background()
	db, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic real SSH", ShortCode: "REALSSH", Status: "active"})
	must(e)
	env, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Loopback lab", Kind: "lab", Status: "active"})
	must(e)
	a, e := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic SSH asset", Kind: "server", Lifecycle: "active"})
	must(e)
	ep, e := db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Protocol: "ssh", Host: "127.0.0.1", Port: lab.Port, Status: "active"})
	must(e)
	svc, e := connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
	must(e)
	actor := workspace.Principal{ID: workspace.OperatorID}
	r, e := svc.Create(ctx, actor, c.ID, env.ID, a.ID, ep.ID, "127.0.0.1", lab.Credential.ID)
	must(e)
	act := func(action, fp, evidence string) {
		t.Helper()
		r, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, action, fp, evidence)
		must(e)
	}
	act("submit", "", "")
	act("authorize", "", "authorized")
	act("inspect", "", "")
	if r.Details.CandidateFingerprint != lab.Fingerprint {
		t.Fatal("server fingerprint mismatch")
	}
	if _, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, "approve", "SHA256:wrong", "Synthetic console evidence"); e == nil {
		t.Fatal("wrong independent fingerprint accepted")
	}
	act("approve", lab.Fingerprint, "Synthetic independently read server host key")
	for i := 0; i < 2; i++ {
		act("verify", "", "")
		if r.State != "connection_verified" || r.Details.LastCategory != "success" || r.Details.VerifiedAt == nil {
			t.Fatal("real probe", r.State, r.Details.LastCategory)
		}
	}
	// Substitute another valid host identity, proving real SSH mismatch fails closed.
	host, _ := os.ReadFile(filepath.Join(lab.Dir, "wrong.pub"))
	fields := strings.Fields(string(host))
	r.Details.ApprovedKey = fields[0] + " " + fields[1]
	r.Details.ApprovedFingerprint, e = sshcli.Fingerprint(r.Details.ApprovedKey)
	must(e)
	r, e = db.SaveEnrollment(ctx, actor, r, r.Revision, "approve")
	must(e)
	act("verify", "", "")
	if r.State != "identity_changed" || r.Details.LastCategory != string(sshcli.ChangedKey) {
		t.Fatal("changed key", r.State, r.Details.LastCategory)
	}
	// Host/port edit even back to its original value never restores old trust.
	ep.Port++
	ep, e = db.SaveEndpoint(ctx, ep)
	must(e)
	ep.Port--
	ep, e = db.SaveEndpoint(ctx, ep)
	must(e)
	latest, e := db.Enrollment(ctx, ep.ID, r.ID)
	must(e)
	if latest.Details.ApprovedKey != "" {
		t.Fatal("trust restored")
	}
	// Review must discard an old candidate, not just its previous approval.
	r = latest
	act("review", "", "")
	act("authorize", "", "authorized")
	if r.Details.CandidateKey != "" || r.Details.InspectedAt != nil {
		t.Fatal("review retained stale inspection")
	}
	if _, e = svc.Act(ctx, actor, ep.ID, r.ID, r.Revision, "approve", lab.Fingerprint, "Old console evidence"); e == nil {
		t.Fatal("old inspection approved after review")
	}
	// A refused loopback inspection is still auditable, without raw diagnostics.
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	must(e)
	ep.Port = listener.Addr().(*net.TCPAddr).Port
	must(listener.Close())
	ep, e = db.SaveEndpoint(ctx, ep)
	must(e)
	r, e = db.Enrollment(ctx, ep.ID, r.ID)
	must(e)
	act("review", "", "")
	act("authorize", "", "authorized")
	act("inspect", "", "")
	if r.Details.AttemptedAt == nil || r.Details.LastCategory == "" || r.Details.CandidateKey != "" {
		t.Fatal("failed inspection evidence missing", r.Details.LastCategory)
	}
	var inspectionAudits int
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM connection_audit WHERE profile_id=$1 AND operation='inspect' AND category<>''`, r.ID).Scan(&inspectionAudits))
	if inspectionAudits != 1 {
		t.Fatal("failed inspection audit missing")
	}
	latest = r
	// Archival prevents all further inspection/authorization even with valid references.
	a.Lifecycle = "archived"
	_, e = db.SaveAsset(ctx, a)
	must(e)
	if _, e = svc.Act(ctx, actor, ep.ID, r.ID, latest.Revision, "review", "", ""); e == nil {
		t.Fatal("archived asset reviewed")
	}
	t.Log("PASS real ordinary-user SSH enrollment: explicit auth, untrusted inspection, independent fingerprint approval, repeated immutable probe, real changed key, revision suspension, archive rejection")
}

type enrollmentHook struct {
	*Store
	before func()
}

func (h *enrollmentHook) SaveEnrollment(ctx context.Context, p workspace.Principal, r connections.Record, rev int64, op string) (connections.Record, error) {
	if h.before != nil {
		f := h.before
		h.before = nil
		f()
	}
	return h.Store.SaveEnrollment(ctx, p, r, rev, op)
}
func TestIntegrationEnrollmentInFlightChanges(t *testing.T) {
	dsn := isolatedDSN(t)
	lab := testlab.Start(t)
	ctx := context.Background()
	db, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic race lab", ShortCode: "RACELAB", Status: "active"})
	must(e)
	env, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Loopback", Kind: "lab", Status: "active"})
	must(e)
	a, e := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic race host", Kind: "server", Lifecycle: "active"})
	must(e)
	ep, e := db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Protocol: "ssh", Host: "127.0.0.1", Port: lab.Port, Status: "active"})
	must(e)
	hook := &enrollmentHook{Store: db}
	svc, e := connections.New(hook, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
	must(e)
	actor := workspace.Principal{ID: workspace.OperatorID}
	r, e := svc.Create(ctx, actor, c.ID, env.ID, a.ID, ep.ID, "127.0.0.1", lab.Credential.ID)
	must(e)
	act := func(action, fp, evidence string) {
		t.Helper()
		r, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, action, fp, evidence)
		must(e)
	}
	act("submit", "", "")
	act("authorize", "", "authorized")
	hook.before = func() { ep.Port++; ep, e = db.SaveEndpoint(ctx, ep); must(e) }
	_, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, "inspect", "", "")
	if !errors.Is(e, connections.ErrConflict) {
		t.Fatal("endpoint changed during inspection", e)
	}
	ep.Port--
	ep, e = db.SaveEndpoint(ctx, ep)
	must(e)
	r, e = db.Enrollment(ctx, ep.ID, r.ID)
	must(e)
	act("review", "", "")
	act("authorize", "", "authorized")
	act("inspect", "", "")
	act("approve", lab.Fingerprint, "Synthetic independently trusted server file")
	// Change and restore the endpoint after a successful SSH result, before CAS.
	hook.before = func() {
		ep.Port++
		ep, e = db.SaveEndpoint(ctx, ep)
		must(e)
		ep.Port--
		ep, e = db.SaveEndpoint(ctx, ep)
		must(e)
	}
	_, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, "verify", "", "")
	if !errors.Is(e, connections.ErrConflict) {
		t.Fatal("stale verification persisted", e)
	}
	r, e = db.Enrollment(ctx, ep.ID, r.ID)
	must(e)
	if r.State == "connection_verified" {
		t.Fatal("stale success")
	}
	act("review", "", "")
	act("authorize", "", "authorized")
	act("inspect", "", "")
	act("approve", lab.Fingerprint, "Synthetic independent server console")
	// Archival competes with completion. No verified success may be committed.
	hook.before = func() { a.Lifecycle = "archived"; _, e = db.SaveAsset(ctx, a); must(e) }
	_, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, "verify", "", "")
	if !errors.Is(e, connections.ErrConflict) {
		t.Fatal("archive race", e)
	}
	t.Log("PASS endpoint changes during inspection/verification and archival before completion reject stale results")
}

func TestIntegrationEnrollmentNW007Upgrade(t *testing.T) {
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
	for _, name := range []string{"001_sessions.sql", "002_operator_settings.sql", "003_customer_environment.sql", "004_topology.sql", "005_operator_workspace.sql"} {
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
