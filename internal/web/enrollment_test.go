package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/testlab"
	"noc-workbench/internal/workspace"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestIntegrationEnrollmentHTTP(t *testing.T) {
	lab := testlab.Start(t)
	ctx := context.Background()
	var svc *connections.Service
	var db *postgres.Store
	var c inventory.Customer
	var env inventory.Environment
	var a inventory.Asset
	var ep inventory.Endpoint
	h := inventoryFixtureWith(t, func(store *postgres.Store, o *Options) {
		db = store
		var e error
		svc, e = connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
		if e != nil {
			t.Fatal(e)
		}
		o.Enrollment = svc
		c, e = db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic HTTP lab", ShortCode: "HTTPSSH", Status: "active"})
		if e != nil {
			t.Fatal(e)
		}
		env, e = db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Synthetic lab", Kind: "lab", Status: "active"})
		if e != nil {
			t.Fatal(e)
		}
		a, e = db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic host", Kind: "server", Lifecycle: "active"})
		if e != nil {
			t.Fatal(e)
		}
		ep, e = db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Host: "127.0.0.1", Port: lab.Port, Protocol: "ssh", Status: "active"})
		if e != nil {
			t.Fatal(e)
		}
	})
	legacyPath := fmt.Sprintf("/customers/%s/environments/%s/assets/%s/ssh", c.ID, env.ID, a.ID)
	path := "/servers/" + a.ID + "/connection"
	if request(h, "GET", path, nil).Code != 401 {
		t.Fatal("unauthenticated GET")
	}
	if request(h, "POST", path, nil).Code != 401 {
		t.Fatal("unauthenticated POST")
	}
	cookie := authenticate(t, h)
	if w := request(h, "GET", legacyPath, nil, cookie); w.Code != 200 {
		t.Fatal("legacy enrollment compatibility", w.Code)
	}
	page := request(h, "GET", path, nil, cookie)
	if page.Code != 200 {
		t.Fatal(page.Code, page.Body.String())
	}
	csrf := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())[1]
	if request(h, "POST", path, url.Values{"action": {"create"}}, cookie).Code != 403 {
		t.Fatal("missing CSRF")
	}
	post := func(v url.Values, code int) {
		t.Helper()
		v.Set("csrf", csrf)
		w := request(h, "POST", path, v, cookie)
		if w.Code != code {
			t.Fatal("HTTP action", v.Get("action"), w.Code, w.Body.String())
		}
	}
	post(url.Values{"action": {"create"}, "endpoint": {ep.ID}, "address": {"127.0.0.1"}, "credential": {lab.Credential.ID}}, 303)
	actor := workspace.Principal{ID: workspace.OperatorID}
	current := func() connections.Record {
		t.Helper()
		list, e := svc.List(ctx, actor, c.ID, env.ID, a.ID)
		if e != nil || len(list) != 1 {
			t.Fatal(list, e)
		}
		return list[0]
	}
	act := func(action, fp, evidence string, code int) {
		t.Helper()
		r := current()
		post(url.Values{"action": {action}, "profile": {r.ID}, "endpoint": {ep.ID}, "revision": {fmt.Sprint(r.Revision)}, "fingerprint": {fp}, "evidence": {evidence}}, code)
	}
	act("verify", "", "", 409)
	act("submit", "", "", 303)
	act("authorize", "", "authorized", 303)
	act("inspect", "", "", 303)
	act("approve", "SHA256:wrong", "Synthetic console evidence", 409)
	act("approve", lab.Fingerprint, "Synthetic independent console <script>escaped</script>", 303)
	act("verify", "", "", 303)
	r := current()
	if r.State != "connection_verified" {
		t.Fatal(r.State, r.Details.LastCategory)
	}
	page = request(h, "GET", path, nil, cookie)
	if strings.Contains(page.Body.String(), "<script>escaped</script>") || strings.Contains(page.Body.String(), lab.Credential.IdentityFile) || strings.Contains(page.Body.String(), lab.Credential.IdentitySHA256) {
		t.Fatal("sensitive reference or XSS")
	}
	act("disable", "", "", 303)
	act("verify", "", "", 409)
	t.Log("PASS authenticated real SSH enrollment HTTP actions, independent fingerprint, state, CSRF, redaction, disabled rejection")
}
func TestEnrollmentAuthenticationBeforeUnavailableService(t *testing.T) {
	h, _ := fixture(t)
	path := "/customers/00000000-0000-4000-8000-000000000001/environments/00000000-0000-4000-8000-000000000001/assets/00000000-0000-4000-8000-000000000001/ssh"
	if w := request(h, http.MethodGet, path, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
}

// Browser execution is opt-in and uses only a disposable PG schema + loopback SSH.
func TestIntegrationEnrollmentBrowser(t *testing.T) {
	script := os.Getenv("NOC_ENROLLMENT_BROWSER_SCRIPT")
	if script == "" {
		t.Skip("set NOC_ENROLLMENT_BROWSER_SCRIPT to the local Playwright harness")
	}
	lab := testlab.Start(t)
	ctx := context.Background()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	origin := "http://" + listener.Addr().String()
	var entry string
	h := inventoryFixtureWith(t, func(db *postgres.Store, o *Options) {
		o.BaseURL = origin
		var e error
		o.Enrollment, e = connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
		if e != nil {
			t.Fatal(e)
		}
		o.Discovery = collection.NewService(o.Enrollment, linux.Registry(), db)
		c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic browser lab", ShortCode: "BROWSER", Status: "active"})
		if e != nil {
			t.Fatal(e)
		}
		env, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Synthetic loopback", Kind: "lab", Status: "active"})
		if e != nil {
			t.Fatal(e)
		}
		a, e := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic browser host", Kind: "server", Lifecycle: "active"})
		if e != nil {
			t.Fatal(e)
		}
		_, e = db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Host: "127.0.0.1", Protocol: "ssh", Port: lab.Port, Status: "active"})
		if e != nil {
			t.Fatal(e)
		}
		entry = fmt.Sprintf("/customers/%s/environments/%s/assets/%s/ssh", c.ID, env.ID, a.ID)
	})
	server := httptest.NewUnstartedServer(h)
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	input, _ := json.Marshal(map[string]string{"origin": origin, "entry": entry, "fingerprint": lab.Fingerprint})
	command := exec.Command("node", script)
	command.Stdin = bytes.NewReader(input)
	output, e := command.CombinedOutput()
	if e != nil {
		t.Fatalf("browser: %v %s", e, output)
	}
	t.Log(string(output))
}
