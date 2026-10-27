package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	api "noc-workbench/internal/integrations/vicidialapi"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/workspace"
)

func TestIntegrationVICIdialAPIHTTP(t *testing.T) {
	var db *postgres.Store
	catalog := filepath.Join(t.TempDir(), "api.json")
	calls := atomic.Int32{}
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = r.ParseForm()
		switch r.Form.Get("function") {
		case "version":
			_, _ = w.Write([]byte("VERSION: 2.14-210|BUILD: 260925-1400|DATE: 2026-10-27 08:00:00|EPOCH: 1793088000|DST: 0|TZ: 0|TZNOW: 0|\n"))
		case "campaigns_list":
			_, _ = w.Write([]byte("campaign_id|campaign_name|active|user_group|dial_method|dial_level|lead_order|dial_statuses|dial_timeout|dial_prefix|manual_dial_prefix|three_way_dial_prefix\nSYNTH01|Synthetic|Y|SYNTH|MANUAL|1|DOWN|NEW|60|9||\n"))
		case "logged_in_agents":
			_, _ = w.Write([]byte("user|campaign_id|session_id|status|lead_id|callerid|calls_today|full_name|user_group|user_level\nsynthetic01|SYNTH01|1001|INCALL|123|discard-this-caller|0|Private synthetic name|SYNTH|1\n"))
		default:
			t.Error("unapproved function")
		}
	}))
	defer fixture.Close()
	h := inventoryFixtureWith(t, func(s *postgres.Store, o *Options) {
		db = s
		shared := collection.NewService(nil, nil)
		o.Scheduler = scheduler.New(s, shared)
		o.VICIdialAPI = api.NewService(s, shared, catalog)
	})
	cookie := authenticate(t, h)
	csrf := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(request(h, "GET", "/customers", nil, cookie).Body.String())[1]
	post := func(path string, v url.Values) string {
		t.Helper()
		v.Set("csrf", csrf)
		w := request(h, "POST", path, v, cookie)
		if w.Code != 303 {
			t.Fatalf("post %s: %d %s", path, w.Code, w.Body.String())
		}
		return strings.Split(w.Header().Get("Location"), "?")[0]
	}
	cp := post("/customers", url.Values{"display_name": {"Synthetic API"}, "short_code": {"APIWEB"}, "status": {"active"}})
	ep := post(cp+"/environments", url.Values{"name": {"Synthetic lab"}, "kind": {"lab"}, "status": {"active"}})
	cluster := post(ep+"/topology/clusters/new", url.Values{"name": {"Synthetic API cluster"}, "type": {"generic"}, "lifecycle": {"active"}})
	id := func(p string) string { return p[strings.LastIndex(p, "/")+1:] }
	base := ep + "/clusters/" + id(cluster) + "/vicidial"
	post(base, url.Values{"revision": {"0"}, "name": {"Synthetic installation"}, "enabled": {"yes"}})
	path := base + "/api"
	if w := request(h, "GET", path, nil, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "Collection disabled") {
		t.Fatalf("empty page %d %s", w.Code, w.Body.String())
	}
	for _, suffix := range []string{"", "/events"} {
		if request(h, "GET", path+suffix, nil).Code != 401 {
			t.Fatal("unauthenticated route")
		}
	}
	if request(h, "POST", path, nil, cookie).Code != 403 {
		t.Fatal("CSRF bypass")
	}
	post(path, url.Values{"revision": {"0"}, "action": {"configure"}, "credential_reference": {"synthetic_api"}, "enabled": {"yes"}})
	scope := collection.Source{CustomerID: id(cp), EnvironmentID: id(ep), ClusterID: id(cluster)}
	v, e := db.SourceConfiguration(context.Background(), workspace.Principal{ID: workspace.OperatorID}, scope)
	if e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal([]map[string]any{{"ID": "synthetic_api", "IntegrationID": v.ID, "Revision": v.Revision, "Enabled": true, "Endpoint": fixture.URL + "/vicidial/non_agent_api.php", "ApprovedIP": "127.0.0.1", "Campaign": "SYNTH01", "User": "synthetic_user", "Password": "synthetic-private-api-password", "Synthetic": true, "ExpiresAt": time.Now().Add(time.Hour), "LoggingReviewDigest": strings.Repeat("a", 64), "ContractVersion": api.DocumentedVersion, "ContractBuild": api.DocumentedBuild}})
	if e = os.WriteFile(catalog, data, 0600); e != nil {
		t.Fatal(e)
	}
	if request(h, "GET", path, nil, cookie).Code != 200 || calls.Load() != 0 {
		t.Fatal("passive request made network call")
	}
	post(path, url.Values{"revision": {"1"}, "action": {"collect"}})
	if calls.Load() != 3 {
		t.Fatal("collection functions", calls.Load())
	}
	w := request(h, "GET", path, nil, cookie)
	body := w.Body.String()
	for _, text := range []string{"vicidial.api.version", "2.14-210", "vicidial.agents.visible_logged_in_count", "fresh", "completed", "http_fixture", "Unknown"} {
		if !strings.Contains(body, text) {
			t.Fatalf("missing %s: %d %s", text, w.Code, body)
		}
	}
	for _, secret := range []string{"synthetic-private-api-password", "Private synthetic name", "discard-this-caller", fixture.URL} {
		if strings.Contains(body, secret) {
			t.Fatal("sensitive data exposed", secret)
		}
	}
	for _, q := range []string{"?key=arbitrary", "?hours=99999"} {
		if request(h, "GET", path+q, nil, cookie).Code != 400 {
			t.Fatal("unbounded chart query")
		}
	}
	post(path, url.Values{"revision": {"1"}, "schedule_revision": {"0"}, "action": {"schedule"}, "interval": {"120"}, "authorize": {"yes"}})
	post(path, url.Values{"revision": {"1"}, "schedule_revision": {"1"}, "action": {"pause"}})
	if calls.Load() != 3 {
		t.Fatal("configuration caused collection")
	}
	// Authenticated SSE starts with authoritative reconciliation and ends promptly on disconnect.
	live := httptest.NewServer(h)
	defer live.Close()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", live.URL+path+"/events", nil)
	req.Host = "127.0.0.1:8080"
	req.AddCookie(cookie)
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		cancel()
		resp.Body.Close()
		t.Fatalf("SSE %d", resp.StatusCode)
	}
	b := make([]byte, 1024)
	n, e := resp.Body.Read(b)
	cancel()
	resp.Body.Close()
	if e != nil || !strings.Contains(string(b[:n]), "reconcile") {
		t.Fatal("SSE reconciliation", e, string(b[:n]))
	}
	alien := post(cp+"/environments", url.Values{"name": {"Other lab"}, "kind": {"lab"}, "status": {"active"}})
	if request(h, "GET", strings.Replace(path, ep, alien, 1), nil, cookie).Code != 404 {
		t.Fatal("cross-environment read")
	}
	if request(h, "GET", strings.Replace(path, ep, alien, 1)+"/events", nil, cookie).Code != 403 {
		t.Fatal("cross-environment SSE")
	}
	if calls.Load() != 3 {
		t.Fatal("reads/SSE caused API execution")
	}
}
