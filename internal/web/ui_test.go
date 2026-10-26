package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestLoginFeedbackPreservesSecurityAndRetry(t *testing.T) {
	h, _ := fixture(t)
	login := request(h, "GET", "/login", nil).Result().Cookies()[0]
	password := "<script>private-submitted-password</script>"
	w := request(h, "POST", "/login", url.Values{"csrf": {login.Value}, "password": {password}}, login)
	if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("inline failure response: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	body := w.Body.String()
	for _, expected := range []string{`role="alert"`, `aria-invalid="true"`, `aria-describedby="password-help login-error"`, `name="csrf" value="` + login.Value + `"`, `for="password"`} {
		if !strings.Contains(body, expected) {
			t.Errorf("missing accessible retry markup %q", expected)
		}
	}
	if strings.Contains(body, password) || strings.Contains(body, "private-submitted-password") || len(w.Result().Cookies()) != 0 {
		t.Fatal("failed login leaked input or changed cookies")
	}
	// An incorrect password must not consume the valid login CSRF token.
	w = request(h, "POST", "/login", url.Values{"csrf": {login.Value}, "password": {"synthetic-test-password"}}, login)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("retry failed: %d", w.Code)
	}
}

func TestLoginThrottlingHasAccessibleFeedback(t *testing.T) {
	h, _ := fixture(t)
	login := request(h, "GET", "/login", nil).Result().Cookies()[0]
	for i := 0; i < 10; i++ {
		request(h, "POST", "/login", url.Values{"csrf": {login.Value}, "password": {"wrong"}}, login)
	}
	w := request(h, "POST", "/login", url.Values{"csrf": {login.Value}, "password": {"wrong"}}, login)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "60" || !strings.Contains(w.Body.String(), `role="alert"`) {
		t.Fatal("throttling lost status, retry header or accessible feedback")
	}
}

func TestUIAssetsRespectContentSecurityPolicy(t *testing.T) {
	h, _ := fixture(t)
	for _, path := range []string{"/login", "/static/app.css", "/static/app.js"} {
		w := request(h, "GET", path, nil)
		policy := w.Header().Get("Content-Security-Policy")
		if w.Header().Get("Referrer-Policy") != "same-origin" {
			t.Fatal("native same-origin form submissions require a non-opaque Origin")
		}
		if w.Code != 200 || !strings.Contains(policy, "script-src 'self'") || !strings.Contains(policy, "default-src 'none'") || strings.Contains(policy, "unsafe-inline") || strings.Contains(policy, "unsafe-eval") {
			t.Fatalf("asset/CSP regression at %s", path)
		}
	}
}

func TestOpaqueOriginRemainsForbidden(t *testing.T) {
	h, _ := fixture(t)
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/login", strings.NewReader("password=synthetic-test-password"))
	r.Header.Set("Origin", "null")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("opaque Origin accepted: %d", w.Code)
	}
}
