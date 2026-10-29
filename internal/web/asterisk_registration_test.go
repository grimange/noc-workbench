package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/baseline"
	"noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/collectors/services"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/health"
	ast "noc-workbench/internal/integrations/asterisk"
	ami "noc-workbench/internal/integrations/asteriskami"
	auth "noc-workbench/internal/integrations/asteriskauth"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/testlab"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

func TestAsteriskVerificationRequestBudget(t *testing.T) {
	// Identity and registration snapshots share the explicit collection budget.
	// Passive server reads retain the short deadline and execute no SSH.
	if got := requestBudget("/servers/synthetic/asterisk"); got != 12*time.Second {
		t.Fatalf("Asterisk verification transport/persistence budget: %v", got)
	}
	if got := requestBudget("/servers/synthetic"); got != 3*time.Second {
		t.Fatalf("passive read budget changed: %v", got)
	}
}

func TestRegistrationViewFreshnessAndAuthority(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ev := collection.Evidence{ID: "synthetic", RunID: "new", Observation: collection.Observation{Key: ast.RegistrationKey, Resource: "pjsip_contacts", ProfileID: "p", ProfileVersion: 1, ObservedAt: now, Value: collection.Text(`{"version":"20.20.1","status":"supported","count":0,"pages":0}`)}}
	in := health.Input{At: now, Active: true, Trusted: true, Authority: map[string]int64{"p": 1}, Evidence: []collection.Evidence{ev}}
	out := health.Evaluation{Readings: []health.Reading{{Evidence: ev, Freshness: "fresh", Quality: "valid"}}}
	p := scheduler.Profile{Enabled: true, Authorized: true, Eligible: true, Target: sshcli.Target{ProfileID: "p", ProfileVersion: 1}, Collectors: []string{ast.RegistrationCollector}}
	current := func(d asteriskRegistrationData) bool { return d.Families[3].Current }
	if !current(registrationView(in, out, p, true, false, nil)) {
		t.Fatal("fresh authorized snapshot")
	}
	if current(registrationView(in, out, p, false, false, nil)) || current(registrationView(in, out, p, true, true, nil)) {
		t.Fatal("authorization or pause ignored")
	}
	out.Readings[0].Freshness = "stale"
	if current(registrationView(in, out, p, true, false, nil)) {
		t.Fatal("stale current")
	}
	out.Readings[0].Freshness = "fresh"
	in.Authority["p"] = 2
	if current(registrationView(in, out, p, true, false, nil)) {
		t.Fatal("revision changed")
	}
	in.Authority["p"] = 1
	in.Trusted = false
	if current(registrationView(in, out, p, true, false, nil)) {
		t.Fatal("host trust lost")
	}
	profile120 := p
	profile120.Interval = 120
	if !strings.Contains(registrationView(in, out, profile120, true, false, nil).Status, "120-second target") {
		t.Fatal("actual configured interval missing")
	}
	before := []ast.RegistrationRow{{ID: "a", Registration: "Registered"}, {ID: "b"}}
	after := []ast.RegistrationRow{{ID: "a", Registration: "Unregistered"}, {ID: "c"}}
	changes := registrationChanges(before, after)
	if len(changes) != 3 || !strings.Contains(changes[0], "changed") || !strings.Contains(changes[1], "disappeared") || !strings.Contains(changes[2], "appeared") {
		t.Fatal(changes)
	}
}

type registrationWebExecutor struct {
	resourceExecutor
	denied bool
}

func (x *registrationWebExecutor) Execute(ctx context.Context, p workspace.Principal, target sshcli.Target, id string) (sshcli.Result, error) {
	if !strings.HasPrefix(id, "asterisk.") {
		return x.resourceExecutor.Execute(ctx, p, target, id)
	}
	x.calls.Add(1)
	at := time.Now().UTC()
	if id == "asterisk.auth.v1" {
		b := auth.Batch{Source: "security", Status: "current", Security: true, InspectedAt: at, After: auth.Cursor{Identity: "1:2", Generation: 1, Offset: 1000, Anchor: strings.Repeat("a", 64)}, Bytes: 1000, Events: []auth.Event{{Position: 0, At: at.Add(-time.Second), Type: "InvalidPassword", Account: "phone100", IP: "2001:db8::10", Port: 5061, Technology: "PJSIP", Severity: "authentication_failure", Reason: "InvalidPassword"}}}
		raw, _ := json.Marshal(b)
		return sshcli.Result{StartedAt: at, EndedAt: at, Stdout: raw}, nil
	}
	v := "Asterisk 18.26.4-vici built by synthetic on Linux\n"
	if x.denied {
		v = "Unable to connect to remote asterisk (Permission denied)"
	} else if id == "asterisk.registrations.v1" {
		for _, source := range ast.RegistrationSources {
			v += "\nNW_REGISTRATIONS_" + source + "\n"
			if source == "pjsip_contacts" {
				v += "Contact: <Aor/ContactUri> <Hash> <Status> <RTT(ms)>\nContact: phone/sip:phone@192.0.2.2 abcdef0123 Avail 2.500\nObjects found: 1"
			} else {
				v += "No such command 'unsupported'"
			}
		}
		v += "\nNW_REGISTRATIONS_END\n"
	}
	return sshcli.Result{StartedAt: at, EndedAt: at, Stdout: []byte(v)}, nil
}
func TestIntegrationServerRegistrationHTTP(t *testing.T) {
	lab := testlab.Start(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var rec connections.Record
	var db *postgres.Store
	var sched *scheduler.Service
	var svc *collection.Service
	var amiCredential sshcli.AMICredential
	exec := &registrationWebExecutor{}
	h := inventoryFixtureWith(t, func(store *postgres.Store, o *Options) {
		db = store
		enroll, e := connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
		must(e)
		o.Enrollment = enroll
		registry := linux.Registry().Extend(services.Specs()...).Extend(baseline.Specs()...).Extend(ast.Specs()...).Extend(auth.Specs()...)
		svc = collection.NewService(ast.Executor{Next: baseline.Executor{Next: services.Executor{Next: exec, Authority: db}, Authority: db}, Authority: db}, registry, db)
		o.Discovery = svc
		sched = scheduler.New(db, svc)
		o.Scheduler = sched
		c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic discovery", ShortCode: "ASTREG", Status: "active"})
		must(e)
		env, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Lab", Kind: "lab", Status: "active"})
		must(e)
		a, e := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic installation", Kind: "server", Lifecycle: "active"})
		must(e)
		ep, e := db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Host: "127.0.0.1", Port: lab.Port, Protocol: "ssh", Status: "active"})
		must(e)
		rec, e = enroll.Create(ctx, p, c.ID, env.ID, a.ID, ep.ID, "127.0.0.1", lab.Credential.ID)
		must(e)
		for _, action := range []string{"submit", "authorize", "inspect", "approve", "verify"} {
			reason := "Independent synthetic key"
			if action == "authorize" {
				reason = "baseline"
			}
			rec, e = enroll.Act(ctx, p, ep.ID, rec.ID, rec.Revision, action, lab.Fingerprint, reason)
			must(e)

		}
		amiCredential = sshcli.AMICredential{ID: "synthetic", ProfileID: rec.ID, ProfileVersion: rec.Revision, SSHUser: "amionly", IdentityFile: "/synthetic/key", IdentitySHA256: strings.Repeat("a", 64), Port: 5038, Username: "monitor", Secret: "synthetic-only-secret", Enabled: true}
		catalog := filepath.Join(t.TempDir(), "ami.json")
		data, _ := json.Marshal([]sshcli.AMICredential{amiCredential})
		must(os.WriteFile(catalog, data, 0600))
		o.AMI = &ami.Service{Repository: db, Catalog: catalog}
	})
	cookie := authenticate(t, h)
	path := "/servers/" + rec.AssetID
	if request(h, "POST", path+"/asterisk", nil).Code != 401 || request(h, "POST", path+"/asterisk", nil, cookie).Code != 403 {
		t.Fatal("auth/CSRF")
	}
	page := request(h, "GET", path, nil, cookie)
	if page.Code != 200 || exec.calls.Load() != 0 || !strings.Contains(page.Body.String(), "Asterisk CLI authorization required") {
		t.Fatal("passive authorization view", page.Code)
	}
	token := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())[1]
	snap, e := sched.Status(ctx, p)
	must(e)
	form := url.Values{"csrf": {token}, "profile": {rec.ID}, "endpoint": {rec.EndpointID}, "revision": {fmt.Sprint(rec.Revision)}, "schedule_revision": {fmt.Sprint(snap.Profiles[0].Revision)}, "authorize": {"yes"}}
	form.Set("revision", "0")
	if request(h, "POST", path+"/asterisk", form, cookie).Code != 409 || exec.calls.Load() != 0 {
		t.Fatal("stale enrollment")
	}
	form.Set("revision", fmt.Sprint(rec.Revision))
	must(sched.Control(ctx, p, scheduler.Control{Kind: "asset", ID: rec.AssetID, Paused: true}))
	if request(h, "POST", path+"/asterisk", form, cookie).Code != 409 || exec.calls.Load() != 0 {
		t.Fatal("pause changed")
	}
	must(sched.Control(ctx, p, scheduler.Control{Kind: "asset", ID: rec.AssetID, Paused: false}))
	if response := request(h, "POST", path+"/asterisk", form, cookie); response.Code != 403 || exec.calls.Load() != 0 {
		t.Fatal("missing grant accepted", response.Code)
	}
	connection := path + "/connection"
	grant := url.Values{"csrf": {token}, "action": {"standard"}, "evidence": {"standard"}, "profile": {rec.ID}, "endpoint": {rec.EndpointID}, "revision": {fmt.Sprint(rec.Revision)}}
	if request(h, "POST", connection, nil).Code != 401 || request(h, "POST", connection, nil, cookie).Code != 403 {
		t.Fatal("standard grant authentication/CSRF")
	}
	grant.Set("revision", "0")
	if response := request(h, "POST", connection, grant, cookie); response.Code != 409 {
		t.Fatal("stale standard grant", response.Code)
	}
	grant.Set("revision", fmt.Sprint(rec.Revision))
	grant.Set("profile", workspace.OperatorID)
	if response := request(h, "POST", connection, grant, cookie); response.Code != 404 {
		t.Fatal("foreign standard enrollment", response.Code)
	}
	grant.Set("profile", rec.ID)
	if db.IntegrationAllowed(ctx, p, rec.Target(), "asterisk") == nil || exec.calls.Load() != 0 {
		t.Fatal("rejected standard POST expanded authority")
	}
	if response := request(h, "POST", connection, grant, cookie); response.Code != 303 {
		t.Fatal("standard grant", response.Code, response.Body.String())
	}
	response := request(h, "POST", path+"/asterisk", form, cookie)
	if response.Code != 303 || exec.calls.Load() != 2 {
		t.Fatal("authorization", response.Code, response.Body.String())
	}
	snap, e = sched.Status(ctx, p)
	must(e)
	if len(snap.Profiles) != 1 || snap.Profiles[0].Interval != 60 || len(snap.Profiles[0].Collectors) != 8 {
		t.Fatal(snap)
	}
	before := exec.calls.Load()
	page = request(h, "GET", path, nil, cookie)
	for _, label := range []string{"Asterisk monitoring", "1 observed", "Contact present; registration unknown", "abcdef0123", "Reachable", "asterisk.registrations v1"} {
		if page.Code != 200 || !strings.Contains(page.Body.String(), label) {
			t.Fatal("missing", label, page.Code, page.Body.String())
		}
	}
	// AMI authorization is explicit and passive; no worker is started by GET/POST/SSE.
	amiForm := url.Values{"csrf": {token}, "profile": {rec.ID}, "endpoint": {rec.EndpointID}, "revision": {fmt.Sprint(rec.Revision)}, "credential_ref": {"synthetic"}, "authorize": {"yes"}}
	if request(h, "POST", path+"/ami", nil).Code != 401 || request(h, "POST", path+"/ami", nil, cookie).Code != 403 {
		t.Fatal("AMI auth/CSRF")
	}
	amiForm.Set("revision", "0")
	if request(h, "POST", path+"/ami", amiForm, cookie).Code != 409 {
		t.Fatal("AMI stale revision")
	}
	amiForm.Set("revision", fmt.Sprint(rec.Revision))
	amiForm.Set("credential_ref", "unapproved")
	if request(h, "POST", path+"/ami", amiForm, cookie).Code != 409 {
		t.Fatal("AMI arbitrary credential")
	}
	amiForm.Set("credential_ref", "synthetic")
	if response := request(h, "POST", path+"/ami", amiForm, cookie); response.Code != 303 {
		t.Fatal("AMI grant", response.Code, response.Body.String())
	}
	bindings, e := db.AMIBindings(ctx, p)
	must(e)
	if len(bindings) != 1 || !bindings[0].Eligible {
		t.Fatal(bindings)
	}
	at := time.Now().UTC()
	session, e := db.BeginAMISession(ctx, bindings[0], at)
	must(e)
	must(db.AMITransition(ctx, bindings[0], session, "connected", "", at, 0, false))
	sourceAt := at.Add(-time.Second)
	must(db.PersistAMIEvent(ctx, bindings[0], session, ami.Event{Name: "ContactStatus", Technology: "PJSIP", Endpoint: "synthetic-endpoint", Address: "[2001:db8::50]:5061", State: "Reachable", SourceAt: &sourceAt, ReceivedAt: at, Sequence: 1}, 0))
	page = request(h, "GET", path, nil, cookie)
	for _, label := range []string{"Live AMI events", "connected", "ContactStatus", "synthetic-endpoint", "[2001:db8::50]:5061", "Asterisk UTC", "Revoke AMI forwarding"} {
		if page.Code != 200 || !strings.Contains(page.Body.String(), label) {
			t.Fatal("AMI UI", label, page.Code, page.Body.String())
		}
	}
	if strings.Contains(page.Body.String(), amiCredential.Secret) || strings.Contains(page.Body.String(), amiCredential.IdentityFile) {
		t.Fatal("AMI credential leak")
	}
	consoleBrowser(t, h, cookie, path)
	if exec.calls.Load() != before {
		t.Fatal("passive collection")
	}
	// A failed subsequent snapshot retains the earlier evidence and timestamp.
	exec.denied = true
	_, e = svc.Collect(collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{ast.RegistrationCollector}}), p, rec.Target())
	must(e)
	page = request(h, "GET", path, nil, cookie)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Historical snapshot") || !strings.Contains(page.Body.String(), "permission_denied") {
		t.Fatal("failed attempt history", page.Code)
	}
	exec.denied = false
	grant.Set("auth_logs", "yes")
	if response := request(h, "POST", connection, grant, cookie); response.Code != 303 {
		t.Fatal("consolidated log expansion", response.Code)
	}
	_, e = svc.Collect(collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{auth.Collector}}), p, rec.Target())
	must(e)
	before = exec.calls.Load()
	page = request(h, "GET", path+"?auth_window=60", nil, cookie)
	for _, label := range []string{"Authentication events", "Current collection", "phone100", "2001:db8::10", "5061", "InvalidPassword", "Individual normalized events"} {
		if page.Code != 200 || !strings.Contains(page.Body.String(), label) {
			t.Fatal("auth UI", label, page.Code, page.Body.String())
		}
	}
	if script := os.Getenv("NOC_AUTH_BROWSER"); script != "" {
		t.Setenv("NOC_CONSOLE_BROWSER", script)
		consoleBrowser(t, h, cookie, path+"?auth_window=60")
	}
	if exec.calls.Load() != before {
		t.Fatal("passive auth GET/SSE collected")
	}
	page = request(h, "GET", path+"?auth_account=unmatched", nil, cookie)
	if page.Code != 200 || strings.Contains(page.Body.String(), "<td>phone100</td>") {
		t.Fatal("filter ignored")
	}
	must(sched.Control(ctx, p, scheduler.Control{Kind: "asset", ID: rec.AssetID, Paused: true}))
	page = request(h, "GET", path, nil, cookie)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Authentication monitoring unavailable") {
		t.Fatal("pause coverage")
	}

}
