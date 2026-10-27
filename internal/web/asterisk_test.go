package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net/url"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/connections"
	ast "noc-workbench/internal/integrations/asterisk"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in uses only the disposable Asterisk lab on fixed loopback port.
// Its host key comes from the independent server-side key file, never keyscan.
func TestIntegrationAsteriskHTTP(t *testing.T) {
	dir := os.Getenv("NOC_ASTERISK_LAB_DIR")
	if dir == "" {
		t.Skip("NOC_ASTERISK_LAB_DIR authorizes the disposable loopback Asterisk lab")
	}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	key, e := os.ReadFile(filepath.Join(dir, "id_ed25519"))
	must(e)
	pub, e := os.ReadFile(filepath.Join(dir, "host.pub"))
	must(e)
	fields := strings.Fields(string(pub))
	if len(fields) < 2 {
		t.Fatal("host key")
	}
	fp, e := sshcli.Fingerprint(fields[0] + " " + fields[1])
	must(e)
	sum := sha256.Sum256(key)
	cred := sshcli.Credential{ID: "synthetic-asterisk", User: "nwlab", IdentityFile: filepath.Join(dir, "id_ed25519"), IdentitySHA256: hex.EncodeToString(sum[:]), Enabled: true}
	catalog := filepath.Join(t.TempDir(), "catalog.json")
	data, _ := json.Marshal([]sshcli.Credential{cred})
	must(os.WriteFile(catalog, data, 0600))
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	var fixtureDSN string
	var db *postgres.Store
	var enroll *connections.Service
	var discover *collection.Service
	var sch *scheduler.Service
	var c inventory.Customer
	var env inventory.Environment
	var a inventory.Asset
	var ep inventory.Endpoint
	h := inventoryFixtureDatabase(t, func(s *postgres.Store, o *Options, dsn string) {
		fixtureDSN = dsn
		db = s
		enroll, e = connections.New(db, db, connections.Catalog(catalog), connections.OperatorPolicy{})
		must(e)
		discover = collection.NewService(ast.Executor{Next: enroll, Authority: db}, linux.Registry().Extend(ast.Specs()...), db)
		sch = scheduler.New(db, discover)
		o.Enrollment = enroll
		o.Discovery = discover
		o.Scheduler = sch
		c, e = db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic Asterisk", ShortCode: "ASTLAB", Status: "active"})
		must(e)
		env, e = db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Isolated lab", Kind: "lab", Status: "active"})
		must(e)
		a, e = db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic PBX", Kind: "server", Lifecycle: "active"})
		must(e)
		ep, e = db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Host: "127.0.0.1", Port: 22442, Protocol: "ssh", Status: "active"})
		must(e)
	})
	rec, e := enroll.Create(ctx, p, c.ID, env.ID, a.ID, ep.ID, "127.0.0.1", cred.ID)
	must(e)
	for _, action := range []string{"submit", "authorize", "inspect", "approve", "verify"} {
		evidence := "Independent disposable lab console key"
		if action == "authorize" {
			evidence = "authorized"
		}
		rec, e = enroll.Act(ctx, p, ep.ID, rec.ID, rec.Revision, action, fp, evidence)
		must(e)
	}
	if rec.State != "connection_verified" {
		t.Fatal(rec.State)
	}
	path := fmt.Sprintf("/customers/%s/environments/%s/assets/%s/linux", c.ID, env.ID, a.ID)
	cookie := authenticate(t, h)
	page := request(h, "GET", path, nil, cookie)
	csrf := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())
	if len(csrf) != 2 {
		t.Fatal(page.Code, page.Body.String())
	}
	form := func(action string) url.Values {
		return url.Values{"csrf": {csrf[1]}, "profile": {rec.ID}, "endpoint": {ep.ID}, "revision": {fmt.Sprint(rec.Revision)}, "integration_action": {action}}
	}
	if w := request(h, "POST", path, form("collect"), cookie); w.Code != 409 {
		t.Fatal("opt-in bypass", w.Code)
	}
	bad := form("enable")
	bad.Del("csrf")
	if request(h, "POST", path, bad, cookie).Code != 403 {
		t.Fatal("CSRF")
	}
	for _, action := range []string{"enable", "collect"} {
		if w := request(h, "POST", path, form(action), cookie); w.Code != 303 {
			t.Fatal(action, w.Code, w.Body.String())
		}
	}
	scope := collection.HistoryScope{CustomerID: c.ID, EnvironmentID: env.ID, AssetID: a.ID}
	runs, e := db.CollectionHistory(ctx, p, scope, "")
	must(e)
	if len(runs) != 1 || runs[0].SuccessCount != 4 {
		t.Fatalf("real Asterisk collection %+v", runs)
	}
	facts, e := db.LatestEvidence(ctx, p, scope)
	must(e)
	values := map[string]collection.Value{}
	for _, v := range facts {
		values[v.Key] = v.Value
		if v.CommandID != v.CollectorID+".v1" || v.Transport != "ssh" {
			t.Fatal("provenance")
		}
	}
	if values["asterisk.version"].Text != "20.20.1" || values["asterisk.channels.active"].Integer != 0 || values["asterisk.modules.pjsip.available"].Integer != 1 || values["asterisk.pjsip.registrations.count"].Integer != 0 {
		t.Fatal(values)
	}
	prof, e := sch.Save(ctx, p, scheduler.Profile{CustomerID: c.ID, EnvironmentID: env.ID, AssetID: a.ID, Target: rec.Target(), PrincipalID: p.ID, Collectors: []string{"asterisk.identity", "asterisk.channels", "asterisk.modules", "asterisk.pjsip"}, Interval: 60, Budget: 20, Enabled: true, Authorized: true})
	must(e)
	// Advance only this disposable schedule; database admission uses actual UTC.
	conn, e := pgx.Connect(ctx, fixtureDSN)
	must(e)
	_, e = conn.Exec(ctx, `UPDATE collection_schedule SET next_due=clock_timestamp()-interval '1 second' WHERE id=$1`, prof.ID)
	conn.Close(ctx)
	must(e)
	must(sch.Step(ctx, time.Now().UTC()))
	deadline := time.Now().Add(10 * time.Second)
	for {
		runs, e = db.CollectionHistory(ctx, p, scope, "")
		must(e)
		if len(runs) > 1 && !runs[0].EndedAt.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scheduled collection incomplete")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if runs[0].Source != "scheduled" || runs[0].SuccessCount != 4 {
		t.Fatal(runs[0])
	}
	before := len(runs)
	page = request(h, "GET", path, nil, cookie)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Asterisk evidence") || !strings.Contains(page.Body.String(), "20.20.1") {
		t.Fatal(page.Code, page.Body.String())
	}
	runs, e = db.CollectionHistory(ctx, p, scope, "")
	must(e)
	if len(runs) != before {
		t.Fatal("passive execution")
	}
	must(sch.Control(ctx, p, scheduler.Control{Kind: "global", Action: "stop"}))
	if w := request(h, "POST", path, form("collect"), cookie); w.Code != 409 {
		t.Fatal("emergency stop bypass", w.Code)
	}
	must(sch.Control(ctx, p, scheduler.Control{Kind: "global", Action: "release"}))
	if w := request(h, "POST", path, form("disable"), cookie); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w := request(h, "POST", path, form("collect"), cookie); w.Code != 409 {
		t.Fatal("disable bypass")
	}
	if w := request(h, "POST", path, form(""), cookie); w.Code != 303 {
		t.Fatal("Linux regression", w.Code, w.Body.String())
	}
}
