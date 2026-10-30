package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/health"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/testlab"
	"noc-workbench/internal/workspace"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestEvaluationAuthentication(t *testing.T) {
	h, _ := fixture(t)
	for _, method := range []string{"GET", "POST"} {
		if w := request(h, method, "/customers/a/environments/b/assets/c/evaluation", nil); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
}
func TestIntegrationEvaluationHTTP(t *testing.T) {
	lab := testlab.Start(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	var db *postgres.Store
	var svc *connections.Service
	var discover *collection.Service
	var c inventory.Customer
	var env inventory.Environment
	var asset inventory.Asset
	var ep inventory.Endpoint
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	h := inventoryFixtureWith(t, func(store *postgres.Store, o *Options) {
		db = store
		var e error
		svc, e = connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
		must(e)
		discover = collection.NewService(svc, linux.Registry(), db)
		o.Enrollment = svc
		o.Discovery = discover
		c, e = db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic Linux discovery", ShortCode: "LINUXLAB", Status: "active"})
		must(e)
		env, e = db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Loopback lab", Kind: "lab", Status: "active"})
		must(e)
		asset, e = db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic observed host", Kind: "server", Lifecycle: "active"})
		must(e)
		ep, e = db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: asset.ID, Host: "127.0.0.1", Port: lab.Port, Protocol: "ssh", Status: "active"})
		must(e)
	})
	path := fmt.Sprintf("/customers/%s/environments/%s/assets/%s/linux", c.ID, env.ID, asset.ID)
	cookie := authenticate(t, h)
	page := request(h, "GET", path, nil, cookie)
	if page.Code != 200 {
		t.Fatal(page.Code, page.Body.String())
	}
	// No enrollment and no collection merely by visiting.
	if strings.Contains(page.Body.String(), "Last requested collection</h2>") {
		t.Fatal("automatic collection")
	}
	r, e := svc.Create(ctx, actor, c.ID, env.ID, asset.ID, ep.ID, "127.0.0.1", lab.Credential.ID)
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
		t.Fatal("independent fingerprint mismatch")
	}
	act("approve", lab.Fingerprint, "Synthetic lab console host key")
	// Approval alone is insufficient: discovery requires verified connectivity.
	_, e = svc.Execute(ctx, actor, r.Target(), "linux.uptime.v1")
	if e == nil {
		t.Fatal("unverified discovery executed")
	}
	act("verify", "", "")
	if r.State != "connection_verified" {
		t.Fatal(r.State, r.Details.LastCategory)
	}
	page = request(h, "GET", path, nil, cookie)
	csrfMatch := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())
	if len(csrfMatch) != 2 {
		t.Fatal("missing collect form")
	}
	csrf := csrfMatch[1]
	form := func() url.Values {
		return url.Values{"csrf": {csrf}, "profile": {r.ID}, "endpoint": {r.EndpointID}, "revision": {fmt.Sprint(r.Revision)}}
	}

	if w := request(h, "POST", path, form(), cookie); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	evalPath := strings.TrimSuffix(path, "/linux") + "/evaluation"
	read := func(at time.Time) health.Evaluation {
		t.Helper()
		suffix := "?format=json"
		if !at.IsZero() {
			suffix += "&at=" + url.QueryEscape(at.Format(time.RFC3339Nano))
		}
		w := request(h, "GET", evalPath+suffix, nil, cookie)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var v health.Evaluation
		must(json.Unmarshal(w.Body.Bytes(), &v))
		return v
	}
	at := time.Now().UTC().Add(time.Second)
	first := read(at)
	if first.Health != "unknown" || first.Collection != "completed" || len(first.Readings) < 10 {
		t.Fatal(first)
	}
	w := request(h, "GET", evalPath, nil, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Observation quality and freshness") {
		t.Fatal(w.Code, w.Body.String())
	}
	policy := url.Values{"csrf": {csrf}, "revision": {"0"}, "selector": {"linux.mem.available_bytes"}, "ttl": {"60"}, "rule": {"memory_available_low"}, "threshold": {"0"}, "enabled": {"yes"}}
	bad := url.Values{}
	for k, v := range policy {
		bad[k] = append([]string(nil), v...)
	}
	bad.Del("csrf")
	if request(h, "POST", evalPath, bad, cookie).Code != 403 {
		t.Fatal("CSRF bypass")
	}
	if request(h, "POST", evalPath, policy).Code != 401 {
		t.Fatal("auth bypass")
	}
	forged := httptest.NewRequest("POST", "http://127.0.0.1:8080"+evalPath, strings.NewReader(policy.Encode()))
	forged.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	forged.Header.Set("Origin", "https://invalid.example.invalid")
	forged.AddCookie(cookie)
	rejected := httptest.NewRecorder()
	h.ServeHTTP(rejected, forged)
	if rejected.Code != 403 {
		t.Fatal("Origin bypass", rejected.Code)
	}
	if request(h, "GET", strings.Replace(evalPath, c.ID, workspace.OperatorID, 1), nil, cookie).Code == 200 {
		t.Fatal("scope bypass")
	}
	if w = request(h, "POST", evalPath, policy, cookie); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if request(h, "POST", evalPath, policy, cookie).Code != 409 {
		t.Fatal("stale policy revision")
	}
	now := time.Now().UTC()
	current := read(now)
	stale := read(now.Add(time.Hour))
	for _, v := range stale.Readings {
		if v.Evidence.CollectorID != "linux.identity" && v.Freshness != "stale" {
			t.Fatal(v)
		}
	}
	for _, v := range current.Readings {
		if v.Evidence.Key == "linux.mem.available_bytes" && (v.Health != "healthy" || v.PolicyRevision != 1) {
			t.Fatal(v)
		}
	}
	policy.Set("revision", "1")
	policy.Set("ttl", "300")
	if request(h, "POST", evalPath, policy, cookie).Code != 303 {
		t.Fatal("revision update")
	}
	historical := read(now)
	for _, v := range historical.Readings {
		if v.Evidence.Key == "linux.mem.available_bytes" && v.PolicyRevision != 1 {
			t.Fatal("policy rewrite")
		}
	}
	hscope := collection.HistoryScope{CustomerID: c.ID, EnvironmentID: env.ID, AssetID: asset.ID}
	history, e := db.CollectionHistory(ctx, actor, hscope, "")
	must(e)
	if len(history) != 1 {
		t.Fatal("evaluation dispatched SSH", len(history))
	}

	// NW-013 consumes the real five-collector evidence without further SSH.
	monitorPath := strings.TrimSuffix(path, "/linux") + "/monitoring"
	policy.Set("revision", "2")
	policy.Set("threshold", "9007199254740992")
	if request(h, "POST", evalPath, policy, cookie).Code != 303 {
		t.Fatal("alert health policy")
	}
	evidence, e := db.EvaluationEvidence(ctx, actor, hscope, time.Now().Add(time.Second))
	must(e)
	var policyID string
	for _, p := range evidence.Policies {
		if p.Selector == "linux.mem.available_bytes" {
			policyID = p.ID
		}
	}
	alertForm := url.Values{"csrf": {csrf}, "action": {"rule"}, "policy": {policyID}, "revision": {"0"}, "severity": {"warning"}, "debounce": {"0"}, "enabled": {"yes"}}
	if request(h, "POST", monitorPath, alertForm, cookie).Code != 303 {
		t.Fatal("rule create")
	}
	if request(h, "POST", monitorPath, url.Values{"action": {"rule"}}, cookie).Code != 403 {
		t.Fatal("rule csrf")
	}
	if request(h, "POST", monitorPath, alertForm).Code != 401 {
		t.Fatal("unauthenticated rule mutation")
	}
	badOrigin := httptest.NewRequest("POST", monitorPath, strings.NewReader(alertForm.Encode()))
	badOrigin.Host = "127.0.0.1:8080"
	badOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badOrigin.Header.Set("Origin", "https://invalid.example.invalid")
	badOrigin.AddCookie(cookie)
	rejected = httptest.NewRecorder()
	h.ServeHTTP(rejected, badOrigin)
	if rejected.Code != 403 {
		t.Fatal("rule Origin", rejected.Code)
	}
	must(db.EvaluateAlerts(ctx, hscope, time.Now().Add(time.Second)))
	av, e := db.AlertView(ctx, actor, hscope)
	must(e)
	if len(av.Alerts) != 1 || av.Alerts[0].State != "active" {
		t.Fatal(av)
	}
	mw := request(h, "GET", monitorPath, nil, cookie)
	if mw.Code != 200 || !strings.Contains(mw.Body.String(), "Historical samples") {
		t.Fatal(mw.Code, mw.Body.String())
	}
	var data monitoringData
	mw = request(h, "GET", monitorPath+"?format=json", nil, cookie)
	must(json.Unmarshal(mw.Body.Bytes(), &data))
	if len(data.Series.Samples) != 1 {
		t.Fatal("real history chart sample", data.Series)
	}
	// Alert navigation retains the selected history evidence and range.
	paged := request(h, "GET", monitorPath+"?format=json&offset=100&key=linux.filesystem.utilization_percent&resource=%2F&hours=168", nil, cookie)
	if paged.Code != 200 {
		t.Fatal("alert page", paged.Code, paged.Body.String())
	}
	var pd monitoringData
	must(json.Unmarshal(paged.Body.Bytes(), &pd))
	u, e := url.Parse(pd.Previous)
	must(e)
	if u.Query().Get("key") != "linux.filesystem.utilization_percent" || u.Query().Get("resource") != "/" || u.Query().Get("hours") != "168" || u.Query().Get("offset") != "0" {
		t.Fatal("pagination lost history", pd.Previous)
	}
	for _, route := range []string{"/", "/alerts"} {
		view := request(h, "GET", route, nil, cookie)
		if view.Code != 200 || !strings.Contains(view.Body.String(), "1 active") || !strings.Contains(view.Body.String(), "1 unacknowledged") {
			t.Fatal("missing alert visibility", route, view.Code)
		}
	}
	ack := url.Values{"csrf": {csrf}, "action": {"acknowledge"}, "alert": {av.Alerts[0].ID}}
	if request(h, "POST", monitorPath, ack, cookie).Code != 303 {
		t.Fatal("acknowledgment")
	}
	av, e = db.AlertView(ctx, actor, hscope)
	must(e)
	if av.Alerts[0].AcknowledgedAt == nil {
		t.Fatal("ack not durable")
	}
	if request(h, "GET", strings.Replace(monitorPath, c.ID, workspace.OperatorID, 1), nil, cookie).Code == 200 {
		t.Fatal("monitor scope")
	}
	history, e = db.CollectionHistory(ctx, actor, hscope, "")
	must(e)
	if len(history) != 1 {
		t.Fatal("monitoring initiated collection")
	}
	// Authenticated SSE uses real streaming ResponseController writes. Reconnect
	// always requests reconciliation and carries no sensitive evidence payload.
	streamServer := httptest.NewServer(h)
	for range 2 {
		streamCtx, stopStream := context.WithTimeout(ctx, 3*time.Second)
		req, err := http.NewRequestWithContext(streamCtx, "GET", streamServer.URL+strings.TrimSuffix(path, "/linux")+"/events", nil)
		must(err)
		req.Host = "127.0.0.1:8080"
		req.AddCookie(cookie)
		response, err := streamServer.Client().Do(req)
		must(err)
		if response.StatusCode != 200 || response.Header.Get("X-Accel-Buffering") != "no" {
			t.Fatal("SSE headers", response.StatusCode)
		}
		line, err := bufio.NewReader(response.Body).ReadString('\n')
		must(err)
		if line != "event: reconcile\n" {
			t.Fatal("missing reconcile", line)
		}
		response.Body.Close()
		stopStream()
	}
	// Exactly 32 streams can coexist; a 33rd is rejected, never queued unboundedly.
	responses := make([]*http.Response, 0, 32)
	for range 32 {
		req, err := http.NewRequest("GET", streamServer.URL+strings.TrimSuffix(path, "/linux")+"/events", nil)
		must(err)
		req.Host = "127.0.0.1:8080"
		req.AddCookie(cookie)
		response, err := streamServer.Client().Do(req)
		must(err)
		if response.StatusCode != 200 {
			t.Fatal("stream capacity", response.StatusCode)
		}
		responses = append(responses, response)
	}
	req, err := http.NewRequest("GET", streamServer.URL+strings.TrimSuffix(path, "/linux")+"/events", nil)
	must(err)
	req.Host = "127.0.0.1:8080"
	req.AddCookie(cookie)
	excess, err := streamServer.Client().Do(req)
	must(err)
	excess.Body.Close()
	if excess.StatusCode != 429 {
		t.Fatal("unbounded streams", excess.StatusCode)
	}
	for _, response := range responses {
		response.Body.Close()
	}
	streamServer.Close()

	_, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, "disable", "", "")
	must(e)
	unknown := read(time.Now().UTC().Add(time.Second))
	for _, v := range unknown.Readings {
		if v.Health != "unknown" {
			t.Fatal("disabled authority condition", v)
		}
	}
	// Session revocation terminates an already authenticated stream at its next tick.
	revokedServer := httptest.NewServer(h)
	defer revokedServer.Close()
	streamCtx, cancelStream := context.WithTimeout(ctx, 8*time.Second)
	defer cancelStream()
	req, err = http.NewRequestWithContext(streamCtx, "GET", revokedServer.URL+strings.TrimSuffix(path, "/linux")+"/events", nil)
	must(err)
	req.Host = "127.0.0.1:8080"
	req.AddCookie(cookie)
	live, err := revokedServer.Client().Do(req)
	must(err)
	defer live.Body.Close()
	if live.StatusCode != 200 {
		t.Fatal("stream after capacity release", live.StatusCode)
	}
	if request(h, "POST", "/logout", url.Values{"csrf": {csrf}}, cookie).Code != 303 {
		t.Fatal("logout revocation")
	}
	_, err = io.ReadAll(live.Body)
	must(err)
	if streamCtx.Err() != nil {
		t.Fatal("revoked stream continued")
	}
}
