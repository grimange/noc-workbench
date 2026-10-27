package vicidialapi

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"noc-workbench/internal/collection"
	"strings"
	"sync"
	"time"
)

// Grant is supplied by an authority after checking current principal, owning
// cluster, configuration revision and credential reference. It is never decoded
// from collection request parameters. Authorization must run before each request.
type Grant struct {
	IntegrationID, Endpoint, Campaign, Username string
	Password                                    string `json:"-"`
	Revision                                    int64
	ApprovedIP                                  netip.Addr
	Enabled                                     bool
	// LoggingReviewDigest identifies independently reviewed endpoint source with
	// credential-redacting logging. Unreviewed upstream version probes are unsafe:
	// known upstream builds log even POST authentication parameters in their DB.
	LoggingReviewDigest            string
	ContractVersion, ContractBuild string
	// Synthetic allows HTTP on exactly one loopback destination for a disposable
	// fixture. There is deliberately no public plaintext or unverified VPN mode.
	Synthetic bool
}

type Authority interface {
	AuthorizeAPI(context.Context, string, int64) (Grant, error)
}

type Client struct {
	authority Authority
	mu        sync.Mutex
	active    map[string]bool
	last      map[string]time.Time
	now       func() time.Time
	resolver  *net.Resolver
}

// String and GoString prevent accidental diagnostic formatting of credentials.
func (g Grant) String() string   { return "VICIdial API authorization (redacted)" }
func (g Grant) GoString() string { return g.String() }

func NewClient(authority Authority) *Client {
	return &Client{authority: authority, active: map[string]bool{}, last: map[string]time.Time{}, now: time.Now, resolver: net.DefaultResolver}
}

func validGrant(g Grant, id string, revision int64) (*url.URL, error) {
	if !g.Enabled || g.IntegrationID != id || id == "" || g.Revision != revision || revision < 1 {
		return nil, fail("authorization_rejected")
	}
	if len(g.LoggingReviewDigest) != 64 {
		return nil, fail("credential_logging_unverified")
	}
	for _, r := range g.LoggingReviewDigest {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return nil, fail("credential_logging_unverified")
		}
	}
	if !campaignID.MatchString(g.Campaign) || len(g.Username) < 2 || len(g.Username) > 20 || len(g.Password) < 1 || len(g.Password) > 256 || strings.ContainsAny(g.Username+g.Password, "\r\n\x00") {
		return nil, fail("invalid_configuration")
	}
	u, err := url.Parse(g.Endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path != "/vicidial/non_agent_api.php" || u.RawPath != "" || u.Hostname() == "" || len(g.Endpoint) > 2048 {
		return nil, fail("invalid_destination")
	}
	ip := g.ApprovedIP.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return nil, fail("invalid_destination")
	}
	if g.Synthetic {
		if !ip.IsLoopback() || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fail("invalid_destination")
		}
	} else if u.Scheme != "https" || ip.IsLoopback() || !ip.IsGlobalUnicast() {
		return nil, fail("invalid_destination")
	}
	return u, nil
}

// Collect accepts a typed operation only and returns minimized typed evidence.
// Raw response bodies never cross the adapter boundary. Every request is POST to the fixed path,
// with no redirects, environment proxy, cookies, raw errors or payload logging.
// The caller owns shared collection admission and durable begin/finish records.
func (c *Client) Collect(ctx context.Context, id string, revision int64, op Operation) ([]collection.Observation, error) {
	if !supported(op) {
		return nil, fail("unsupported_function")
	}
	if c.authority == nil {
		return nil, fail("authorization_rejected")
	}
	g, err := c.authority.AuthorizeAPI(ctx, id, revision)
	if err != nil {
		return nil, fail("authorization_rejected")
	}
	u, err := validGrant(g, id, revision)
	if err != nil {
		return nil, err
	}
	if op != Version && (g.ContractVersion != DocumentedVersion || g.ContractBuild != DocumentedBuild) {
		return nil, fail("unsupported_revision")
	}
	c.mu.Lock()
	// A single integration is serialized across all operations. A finite map and
	// conservative request spacing bound adapter resources independent of callers.
	if c.active[id] || len(c.active) >= 5 {
		c.mu.Unlock()
		return nil, fail("busy")
	}
	now := c.now()
	if at, ok := c.last[id]; ok && now.Sub(at) < time.Second {
		c.mu.Unlock()
		return nil, fail("rate_limited")
	}
	if len(c.last) >= 1000 { // Evict only expired entries; never grow an unbounded ID cache.
		for key, at := range c.last {
			if now.Sub(at) >= time.Minute && !c.active[key] {
				delete(c.last, key)
			}
		}
		if len(c.last) >= 1000 {
			c.mu.Unlock()
			return nil, fail("busy")
		}
	}
	c.active[id] = true
	c.last[id] = now
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.active, id); c.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	approved := g.ApprovedIP.Unmap()
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
		MaxResponseHeaderBytes: 16 * 1024,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			ips, err := c.resolver.LookupNetIP(ctx, "ip", u.Hostname())
			if err != nil || len(ips) == 0 {
				return nil, fail("destination_changed")
			}
			for _, ip := range ips {
				if ip.Unmap() != approved {
					return nil, fail("destination_changed")
				}
			}
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			return dialer.DialContext(ctx, network, net.JoinHostPort(approved.String(), port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := url.Values{"function": {string(op)}, "source": {"noc-workbench"}, "user": {g.Username}, "pass": {g.Password}}
	if op != Version {
		form.Set("stage", "pipe")
		form.Set("header", "YES")
	}
	if op == Campaigns {
		form.Set("campaign_id", g.Campaign)
	}
	if op == Agents {
		form.Set("campaigns", g.Campaign)
		form.Set("show_sub_status", "NO")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fail("invalid_configuration")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() == context.Canceled {
			return nil, fail("cancelled")
		}
		if ctx.Err() != nil {
			return nil, fail("timeout")
		}
		return nil, fail("transport_failed")
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == 401:
		return nil, fail("authentication_failed")
	case resp.StatusCode == 403:
		return nil, fail("permission_denied")
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, fail("redirect_rejected")
	case resp.StatusCode >= 500:
		return nil, fail("temporarily_unavailable")
	case resp.StatusCode != 200:
		return nil, fail("http_error")
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return nil, fail("unsupported_response")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		if ctx.Err() == context.Canceled {
			return nil, fail("cancelled")
		}
		if ctx.Err() != nil {
			return nil, fail("timeout")
		}
		return nil, fail("transport_failed")
	}
	if len(body) > MaxResponse {
		return nil, fail("response_limit")
	}
	return Parse(op, body, g.Campaign)
}
