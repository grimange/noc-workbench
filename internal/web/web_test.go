package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"noc-workbench/internal/security"
	"noc-workbench/internal/store/postgres"
)

type memoryStore struct {
	credential string
	sessions   map[string]postgres.Session
	label      string
	fail       bool
}

func (m *memoryStore) Ping(context.Context) error {
	if m.fail {
		return errors.New("secret database DSN")
	}
	return nil
}
func (m *memoryStore) CreateSession(_ context.Context, s postgres.Session) error {
	if m.fail {
		return postgres.ErrUnavailable
	}
	m.sessions[s.TokenHash] = s
	return nil
}
func (m *memoryStore) Session(_ context.Context, h string) (postgres.Session, error) {
	if m.fail {
		return postgres.Session{}, postgres.ErrUnavailable
	}
	s, ok := m.sessions[h]
	if !ok {
		return s, postgres.ErrNotFound
	}
	return s, nil
}
func (m *memoryStore) DeleteSession(_ context.Context, h string) error {
	if m.fail {
		return postgres.ErrUnavailable
	}
	delete(m.sessions, h)
	return nil
}
func (m *memoryStore) GetNote(context.Context) (string, error) {
	if m.fail {
		return "", postgres.ErrUnavailable
	}
	return m.label, nil
}
func (m *memoryStore) SetNote(_ context.Context, v string) error {
	if m.fail {
		return postgres.ErrUnavailable
	}
	m.label = v
	return nil
}
func fixture(t *testing.T) (http.Handler, *memoryStore) {
	t.Helper()
	hash, e := bcrypt.GenerateFromPassword([]byte("synthetic-test-password"), 10)
	if e != nil {
		t.Fatal(e)
	}
	m := &memoryStore{credential: string(hash), sessions: map[string]postgres.Session{}}
	return New(m, Options{BaseURL: "http://127.0.0.1:8080", PasswordHash: string(hash), SessionTTL: time.Hour}), m
}
func request(h http.Handler, method, path string, data url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(data.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if method == "POST" {
		r.Header.Set("Origin", "http://127.0.0.1:8080")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func authenticate(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	w := request(h, "GET", "/login", nil)
	c := w.Result().Cookies()[0]
	w = request(h, "POST", "/login", url.Values{"csrf": {c.Value}, "password": {"synthetic-test-password"}}, c)
	if w.Code != 303 {
		t.Fatalf("login %d %s", w.Code, w.Body.String())
	}
	for _, c = range w.Result().Cookies() {
		if c.Name == "nw_session" {
			return c
		}
	}
	t.Fatal("missing session")
	return nil
}
func TestAuthenticationCSRFAndLogout(t *testing.T) {
	h, m := fixture(t)
	if w := request(h, "POST", "/settings", url.Values{"label": {"bad"}}); w.Code != 401 {
		t.Fatalf("unauthorized %d", w.Code)
	}
	if w := request(h, "POST", "/login", url.Values{"password": {"synthetic-test-password"}}); w.Code != 403 {
		t.Fatalf("login CSRF %d", w.Code)
	}
	login := request(h, "GET", "/login", nil).Result().Cookies()[0]
	if w := request(h, "POST", "/login", url.Values{"csrf": {login.Value}, "password": {"wrong"}}, login); w.Code != 401 {
		t.Fatalf("bad password %d", w.Code)
	}
	c := authenticate(t, h)
	if !c.HttpOnly || c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags %+v", c)
	}
	s := m.sessions[security.Hash(c.Value+m.credential)]
	if s.TokenHash == c.Value || len(s.TokenHash) != 64 {
		t.Fatal("token stored raw")
	}
	for _, token := range []string{"", strings.Repeat("a", 64)} {
		if w := request(h, "POST", "/settings", url.Values{"csrf": {token}, "label": {"bad"}}, c); w.Code != 403 {
			t.Fatalf("CSRF %d", w.Code)
		}
	}
	if w := request(h, "POST", "/settings", url.Values{"csrf": {s.CSRFToken}, "label": {"<script>test</script>"}}, c); w.Code != 303 {
		t.Fatalf("mutation %d", w.Code)
	}
	w := request(h, "GET", "/", nil, c)
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>") || !strings.Contains(w.Body.String(), "&lt;script&gt;") {
		t.Fatal("HTML escaping/landing")
	}
	if w = request(h, "POST", "/logout", url.Values{"csrf": {s.CSRFToken}}, c); w.Code != 303 {
		t.Fatal("logout")
	}
	if w = request(h, "GET", "/", nil, c); w.Code != 401 {
		t.Fatal("session survived logout")
	}
}
func TestExpiryStorageFailureAndHostOrigin(t *testing.T) {
	h, m := fixture(t)
	c := authenticate(t, h)
	s := m.sessions[security.Hash(c.Value+m.credential)]
	s.ExpiresAt = time.Now().Add(-time.Second)
	m.sessions[s.TokenHash] = s
	if w := request(h, "GET", "/", nil, c); w.Code != 401 {
		t.Fatal("expired session accepted")
	}
	m.fail = true
	for _, path := range []string{"/", "/healthz"} {
		w := request(h, "GET", path, nil, c)
		if w.Code != 503 || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("failure %s %d", path, w.Code)
		}
	}
	for _, origin := range []string{"", "http://evil.example.invalid"} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/settings", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("origin accepted")
		}
	}
	r := httptest.NewRequest("GET", "http://evil.example.invalid/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("host accepted")
	}
}
func TestHealthAssetsAndLimits(t *testing.T) {
	h, _ := fixture(t)
	for _, path := range []string{"/healthz", "/login", "/static/app.css"} {
		w := request(h, "GET", path, nil)
		if w.Code != 200 {
			t.Fatalf("%s %d", path, w.Code)
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Fatal("missing CSP")
		}
	}
	if w := request(h, "GET", "/", nil); w.Code != 303 {
		t.Fatal("home not protected")
	}
	c := authenticate(t, h)
	w := request(h, "POST", "/settings", url.Values{"label": {strings.Repeat("a", 9000)}}, c)
	if w.Code != 400 {
		t.Fatalf("oversized %d", w.Code)
	}
}
func TestSecureCookiesAndSessionRotation(t *testing.T) {
	h, m := fixture(t)
	c1 := authenticate(t, h)
	login := request(h, "GET", "/login", nil).Result().Cookies()[0]
	w := request(h, "POST", "/login", url.Values{"csrf": {login.Value}, "password": {"synthetic-test-password"}}, login, c1)
	if w.Code != 303 {
		t.Fatal("reauth")
	}
	if _, ok := m.sessions[security.Hash(c1.Value+m.credential)]; ok {
		t.Fatal("old session not revoked")
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("synthetic-test-password"), 10)
	h = New(m, Options{BaseURL: "https://127.0.0.1:8080", PasswordHash: string(hash), SessionTTL: time.Hour, SecureCookie: true})
	r := httptest.NewRequest("GET", "https://127.0.0.1:8080/login", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !w.Result().Cookies()[0].Secure {
		t.Fatal("HTTPS cookie insecure")
	}
}
func TestLoginRateLimit(t *testing.T) {
	h, _ := fixture(t)
	c := request(h, "GET", "/login", nil).Result().Cookies()[0]
	for i := 0; i < 11; i++ {
		w := request(h, "POST", "/login", url.Values{"csrf": {c.Value}, "password": {"wrong"}}, c)
		expected := 401
		if i == 10 {
			expected = 429
		}
		if w.Code != expected {
			t.Fatalf("attempt%d: %d", i, w.Code)
		}
	}
}

func TestPasswordRotationRevokesSessions(t *testing.T) {
	h, m := fixture(t)
	c := authenticate(t, h)
	replacement, err := bcrypt.GenerateFromPassword([]byte("different-synthetic-password"), 10)
	if err != nil {
		t.Fatal(err)
	}
	h = New(m, Options{BaseURL: "http://127.0.0.1:8080", PasswordHash: string(replacement), SessionTTL: time.Hour})
	if w := request(h, "GET", "/", nil, c); w.Code != 401 {
		t.Fatalf("old credential session still valid: %d", w.Code)
	}
}

// Exercise real TLS and a distinct loopback proxy/backend pair. Forwarded
// headers do not select the origin; the configured Host and Origin remain exact.
func TestHTTPSProxyAuthentication(t *testing.T) {
	_, m := fixture(t)
	backend := httptest.NewUnstartedServer(nil)
	target := &url.URL{Scheme: "http", Host: backend.Listener.Addr().String()}
	proxy := httptest.NewUnstartedServer(httputil.NewSingleHostReverseProxy(target))
	origin := "https://" + proxy.Listener.Addr().String()
	backend.Config.Handler = New(m, Options{BaseURL: origin, PasswordHash: m.credential, SessionTTL: time.Hour, SecureCookie: true})
	backend.Start()
	defer backend.Close()
	proxy.StartTLS()
	defer proxy.Close()
	client := proxy.Client() // Trust only httptest's synthetic TLS certificate.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	client.Timeout = 3 * time.Second
	response, err := client.Get(origin + "/login")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	login := response.Cookies()[0]
	if response.StatusCode != 200 || !login.Secure || !login.HttpOnly || login.SameSite != http.SameSiteStrictMode {
		t.Fatal("insecure HTTPS login response")
	}
	post := func(path string, form url.Values, requestOrigin string) (int, string) {
		t.Helper()
		req, err := http.NewRequest("POST", origin+path, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", requestOrigin)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}
	status, html := post("/login", url.Values{"csrf": {login.Value}, "password": {"synthetic-test-password"}}, origin)
	if status != 200 || !strings.Contains(html, "Workspace settings") {
		t.Fatalf("HTTPS login: %d", status)
	}
	_, tail, found := strings.Cut(html, `name="csrf" value="`)
	csrf, _, _ := strings.Cut(tail, `"`)
	if !found || len(csrf) != 64 {
		t.Fatal("HTTPS session CSRF missing")
	}
	form := url.Values{"csrf": {csrf}, "label": {"synthetic TLS workspace"}}
	if status, _ := post("/settings", form, "http://"+target.Host); status != 403 {
		t.Fatalf("backend origin accepted through TLS proxy: %d", status)
	}
	if status, html := post("/settings", form, origin); status != 200 || !strings.Contains(html, "synthetic TLS workspace") {
		t.Fatalf("HTTPS authorized mutation: %d", status)
	}
	if status, _ := post("/logout", url.Values{"csrf": {csrf}}, origin); status != 200 {
		t.Fatalf("HTTPS logout: %d", status)
	}
}
