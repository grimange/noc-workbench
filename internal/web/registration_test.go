package web

import (
	"net/url"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/workspace"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestIntegrationDirectRegistrationHTTP(t *testing.T) {
	h := inventoryFixture(t)
	if request(h, "GET", "/servers/new", nil).Code != 401 || request(h, "POST", "/servers/new", nil).Code != 401 {
		t.Fatal("registration authentication")
	}
	cookie := authenticate(t, h)
	page := request(h, "GET", "/servers/new", nil, cookie)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Register and configure connection") {
		t.Fatal("direct registration missing", page.Code)
	}
	csrf := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())[1]
	customer := request(h, "POST", "/customers", url.Values{"csrf": {csrf}, "display_name": {"Synthetic direct owner"}, "short_code": {"DIRECT"}, "status": {"active"}, "return": {"registration"}}, cookie)
	if customer.Code != 303 || !strings.HasPrefix(customer.Header().Get("Location"), "/servers/new?customer=") {
		t.Fatal("contextual customer", customer.Code)
	}
	u, _ := url.Parse(customer.Header().Get("Location"))
	id := u.Query().Get("customer")
	f := url.Values{"csrf": {csrf}, "customer": {id}, "name": {"Synthetic direct server"}, "host": {"ssh.example.invalid"}, "port": {"22"}}
	bad := url.Values{"customer": {id}}
	if request(h, "POST", "/servers/new", bad, cookie).Code != 403 {
		t.Fatal("registration CSRF")
	}
	f.Set("host", "user@host")
	if request(h, "POST", "/servers/new", f, cookie).Code != 422 {
		t.Fatal("invalid destination accepted")
	}
	f.Set("host", "ssh.example.invalid")
	result := request(h, "POST", "/servers/new", f, cookie)
	if result.Code != 303 || !strings.HasSuffix(result.Header().Get("Location"), "/connection") {
		t.Fatal("direct registration", result.Code, result.Body.String())
	}
	if request(h, "POST", "/servers/new", f, cookie).Code != 422 {
		t.Fatal("duplicate registration")
	}
	asset := strings.TrimSuffix(strings.TrimPrefix(result.Header().Get("Location"), "/servers/"), "/connection")
	for _, path := range []string{"/servers/" + asset, "/servers/" + asset + "/connection", "/servers/" + asset + "/history", "/servers/" + asset + "/collection"} {
		if request(h, "GET", path, nil).Code != 401 {
			t.Fatal("direct path authentication", path)
		}
	}
	// Retired destinations authenticate before redirects and reject writes.
	for path, dest := range map[string]string{"/workspace": "/servers", "/settings": "/", "/monitoring": "/alerts"} {
		if request(h, "GET", path, nil).Code != 401 {
			t.Fatal("retired auth", path)
		}
		w := request(h, "GET", path, nil, cookie)
		if w.Code != 303 || w.Header().Get("Location") != dest {
			t.Fatal("compatibility", path, w.Code)
		}
	}
}
func TestDirectCollectionBudget(t *testing.T) {
	for _, path := range []string{"/servers/id/collection", "/servers/id/connection"} {
		if requestBudget(path) != 12*time.Second {
			t.Fatal("direct action lost execution budget", path)
		}
	}
}

func TestContextualInheritedClusterPause(t *testing.T) {
	server := workspace.Server{ID: "server", CustomerID: "owner", Clusters: []workspace.ServerCluster{{ID: "cluster", Name: "Declared group"}}}
	profile := scheduler.Profile{ID: "profile", Enabled: true, Authorized: true, Paused: true}
	snap := scheduler.Status{Snapshot: scheduler.Snapshot{Controls: []scheduler.Control{{Kind: "cluster", ID: "cluster", Paused: true}}}}
	m := maintenance(server, profile, snap)
	if len(m.Blockers) != 1 || m.ProfilePaused || m.CanResume {
		t.Fatal("cluster pause became server-owned", m)
	}
	snap.Controls = append(snap.Controls, scheduler.Control{Kind: "asset", ID: "server", Paused: true})
	m = maintenance(server, profile, snap)
	if len(m.Blockers) != 2 || !m.CanResume || !m.AssetPaused {
		t.Fatal("combined cluster and asset pause", m)
	}
	snap.Controls = snap.Controls[:1]
	m = maintenance(server, profile, snap)
	if len(m.Blockers) != 1 || m.CanResume {
		t.Fatal("cluster pause lost after asset resume", m)
	}
}
