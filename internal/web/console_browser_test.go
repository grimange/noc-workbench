package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

// Browser verification is opt-in and uses only the existing synthetic SSH/DB fixture.
func consoleBrowser(t *testing.T, h http.Handler, cookie *http.Cookie, entry string, resource ...bool) {
	t.Helper()
	script := os.Getenv("NOC_CONSOLE_BROWSER")
	if len(resource) > 0 && resource[0] {
		script = os.Getenv("NOC_RESOURCE_BROWSER")
	}
	if script == "" {
		return
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "127.0.0.1:8080"
		if r.Header.Get("Origin") != "" {
			r.Header.Set("Origin", "http://127.0.0.1:8080")
		}
		h.ServeHTTP(w, r)
	}))
	defer server.Close()
	payload, _ := json.Marshal(map[string]any{"origin": server.URL, "session": cookie.Value, "entry": entry, "queries": []string{"Synthetic installation", "127.0.0.1", "Synthetic discovery"}, "synthetic": true})
	cmd := exec.Command("node", script)
	cmd.Env = append(os.Environ(), "TMPDIR=/tmp")
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Chrome console: %v %s", err, out)
	}
	t.Log(string(out))
}
