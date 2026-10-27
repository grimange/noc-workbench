package vicidialapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type authorityFunc func(context.Context, string, int64) (Grant, error)

func (f authorityFunc) AuthorizeAPI(ctx context.Context, id string, r int64) (Grant, error) {
	return f(ctx, id, r)
}
func fixtureClient(t *testing.T, handler http.HandlerFunc) (*Client, *Grant) {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	g := &Grant{IntegrationID: "synthetic", Endpoint: s.URL + "/vicidial/non_agent_api.php", Campaign: "SYNTH01", Username: "synthetic", Password: "secret-canary", Revision: 1, ApprovedIP: netip.MustParseAddr(u.Hostname()), Enabled: true, Synthetic: true, LoggingReviewDigest: strings.Repeat("a", 64), ContractVersion: DocumentedVersion, ContractBuild: DocumentedBuild}
	c := NewClient(authorityFunc(func(context.Context, string, int64) (Grant, error) { return *g, nil }))
	return c, g
}
func TestFixedPOST(t *testing.T) {
	var calls atomic.Int32
	c, _ := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.Path != "/vicidial/non_agent_api.php" || r.Header.Get("Authorization") != "" {
			t.Error("unsafe request shape")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if len(r.Form) != 8 || r.Form.Get("function") != "logged_in_agents" || r.Form.Get("campaigns") != "SYNTH01" || r.Form.Get("pass") != "secret-canary" || r.Form.Get("show_sub_status") != "NO" {
			t.Error("incorrect fixed parameters")
		}
		fmt.Fprint(w, agentFixture)
	})
	obs, err := c.Collect(context.Background(), "synthetic", 1, Agents)
	if err != nil {
		t.Fatal(err)
	}
	if err != nil || len(obs) != 3 {
		t.Fatal(err)
	}
	if _, err := c.Collect(context.Background(), "synthetic", 1, Version); code(err) != "rate_limited" {
		t.Fatal(err)
	}
	if _, err := c.Collect(context.Background(), "synthetic", 1, Operation("add_lead")); code(err) != "unsupported_function" {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}
func TestPrecontactRejection(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*Grant)
	}{
		{"disabled", "authorization_rejected", func(g *Grant) { g.Enabled = false }},
		{"stale", "authorization_rejected", func(g *Grant) { g.Revision = 2 }},
		{"other scope", "authorization_rejected", func(g *Grant) { g.IntegrationID = "other" }},
		{"logging unreviewed", "credential_logging_unverified", func(g *Grant) { g.LoggingReviewDigest = "" }},
		{"metadata IP", "invalid_destination", func(g *Grant) { g.ApprovedIP = netip.MustParseAddr("169.254.169.254") }},
		{"credentials URL", "invalid_destination", func(g *Grant) { g.Endpoint = "https://user:secret@example.invalid/vicidial/non_agent_api.php" }},
		{"query injection", "invalid_destination", func(g *Grant) { g.Endpoint += "?function=add_lead" }},
		{"path", "invalid_destination", func(g *Grant) { g.Endpoint += "/other" }},
		{"scheme", "invalid_destination", func(g *Grant) { g.Endpoint = "file:///vicidial/non_agent_api.php" }},
		{"public plaintext", "invalid_destination", func(g *Grant) { g.Synthetic = false }},
		{"campaign injection", "invalid_configuration", func(g *Grant) { g.Campaign = "A|OTHER" }},
		{"revision unknown", "unsupported_revision", func(g *Grant) { g.ContractBuild = "unknown" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c, g := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
			tc.change(g)
			if _, err := c.Collect(context.Background(), "synthetic", 1, Agents); code(err) != tc.want {
				t.Fatalf("%v", err)
			}
			if calls.Load() != 0 {
				t.Fatal("unauthorized contact")
			}
		})
	}
}
func TestHTTPFailures(t *testing.T) {
	for _, tc := range []struct {
		status     int
		body, want string
	}{
		{200, "ERROR: Invalid Username/Password: synthetic|", "authentication_failed"},
		{200, "ERROR: ignored secret-canary", "application_error"},
		{200, "not an API response", "invalid_response"},
		{200, strings.Repeat("x", MaxResponse+1), "response_limit"}, {401, "secret-canary", "authentication_failed"}, {403, "secret-canary", "permission_denied"}, {500, "secret-canary", "temporarily_unavailable"}, {302, "secret-canary", "redirect_rejected"}, {404, "secret-canary", "http_error"},
	} {
		t.Run(fmt.Sprint(tc.status, tc.want), func(t *testing.T) {
			c, _ := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://169.254.169.254/")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			if _, err := c.Collect(context.Background(), "synthetic", 1, Version); code(err) != tc.want || strings.Contains(fmt.Sprint(err), "secret-canary") {
				t.Fatal(err)
			}
		})
	}
}
func TestCancellationAndSerialization(t *testing.T) {
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	c, _ := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
		close(cancelled)
	})
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := c.Collect(ctx, "synthetic", 1, Version)
		if code(err) != "cancelled" {
			t.Error(err)
		}
	}()
	<-entered
	if _, err := c.Collect(context.Background(), "synthetic", 1, Version); code(err) != "busy" {
		t.Fatal(err)
	}
	cancel()
	wg.Wait()
	<-cancelled
	c.mu.Lock()
	active := len(c.active)
	c.mu.Unlock()
	if active != 0 {
		t.Fatal("capacity leaked")
	}
}
func TestDestinationChange(t *testing.T) {
	c, g := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected contact") })
	u, _ := url.Parse(g.Endpoint)
	g.Endpoint = strings.Replace(g.Endpoint, u.Hostname(), "localhost", 1)
	// localhost resolves to more than the single approved IPv4 address on this
	// host; use a deliberately different pin to make rejection deterministic.
	g.ApprovedIP = netip.MustParseAddr("127.0.0.2")
	if _, err := c.Collect(context.Background(), "synthetic", 1, Version); code(err) != "transport_failed" {
		t.Fatal(err)
	}
}

func TestDeadline(t *testing.T) {
	entered := make(chan struct{})
	disconnected := make(chan struct{})
	c, _ := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
		close(disconnected)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := c.Collect(ctx, "synthetic", 1, Version)
	if code(err) != "timeout" {
		t.Fatal(err)
	}
	<-entered
	<-disconnected
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.active) != 0 {
		t.Fatal("capacity leaked")
	}
}

func TestTLSVerification(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted certificate accepted") }))
	defer s.Close()
	u, _ := url.Parse(s.URL)
	g := Grant{IntegrationID: "synthetic", Endpoint: s.URL + "/vicidial/non_agent_api.php", Campaign: "SYNTH01", Username: "synthetic", Password: "secret-canary", Revision: 1, ApprovedIP: netip.MustParseAddr(u.Hostname()), Enabled: true, Synthetic: true, LoggingReviewDigest: strings.Repeat("a", 64)}
	c := NewClient(authorityFunc(func(context.Context, string, int64) (Grant, error) { return g, nil }))
	if _, err := c.Collect(context.Background(), "synthetic", 1, Version); code(err) != "transport_failed" {
		t.Fatal(err)
	}
}

func TestCapacityAndBookkeepingBounds(t *testing.T) {
	c, _ := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("request exceeded capacity") })
	for i := 0; i < 5; i++ {
		c.active[fmt.Sprint(i)] = true
	}
	if _, err := c.Collect(context.Background(), "synthetic", 1, Version); code(err) != "busy" {
		t.Fatal(err)
	}
	clear(c.active)
	now := time.Unix(200, 0)
	c.now = func() time.Time { return now }
	for i := 0; i < 1000; i++ {
		c.last[fmt.Sprint(i)] = now
	}
	if _, err := c.Collect(context.Background(), "synthetic", 1, Version); code(err) != "busy" {
		t.Fatal(err)
	}
	if len(c.last) != 1000 {
		t.Fatal("unbounded bookkeeping")
	}
}
