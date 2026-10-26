package app

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func configEnv(t *testing.T) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("synthetic-test-password"), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"NOC_LISTEN", "NOC_BASE_URL", "NOC_SESSION_TTL", "NOC_STARTUP_TIMEOUT"} {
		t.Setenv(key, "")
	}
	t.Setenv("NOC_DATABASE_URL", "postgres://synthetic:synthetic@127.0.0.1:55432/noc?sslmode=disable")
	t.Setenv("NOC_PASSWORD_HASH", string(hash))
}

func TestLoadDefaults(t *testing.T) {
	configEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8080" || c.SessionTTL != 8*time.Hour || c.StartupTimeout != 10*time.Second || c.SecureCookie {
		t.Fatalf("unexpected non-secret defaults: listen=%s ttl=%s startup=%s secure=%v", c.Listen, c.SessionTTL, c.StartupTimeout, c.SecureCookie)
	}
}

func TestHTTPSAndIPv6(t *testing.T) {
	configEnv(t)
	t.Setenv("NOC_LISTEN", "[::1]:8080")
	t.Setenv("NOC_BASE_URL", "https://[::1]:8443")
	t.Setenv("NOC_DATABASE_URL", "postgres://synthetic:synthetic@[::1]:55432/noc?sslmode=require")
	c, err := Load()
	if err != nil || !c.SecureCookie {
		t.Fatalf("HTTPS config rejected or insecure: err=%v secure=%v", err, c.SecureCookie)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	configEnv(t)
	for _, tc := range []struct{ key, value string }{
		{"NOC_LISTEN", "0.0.0.0:8080"},
		{"NOC_LISTEN", "192.0.2.1:8080"},
		{"NOC_LISTEN", "localhost:8080"},
		{"NOC_LISTEN", "127.0.0.1:0"},
		{"NOC_LISTEN", "127.0.0.1:65536"},
		{"NOC_LISTEN", "127.0.0.1:08080"},
		{"NOC_BASE_URL", "http://127.0.0.1:8081"},
		{"NOC_BASE_URL", "http://synthetic:secret@127.0.0.1:8080"},
		{"NOC_BASE_URL", "http://127.0.0.1:8080/"},
		{"NOC_BASE_URL", "http://127.0.0.1:8080?"},
		{"NOC_BASE_URL", "http://127.0.0.1:8080#fragment"},
		{"NOC_BASE_URL", "ftp://127.0.0.1:8080"},
		{"NOC_BASE_URL", "https://127.0.0.1:8080"},
		{"NOC_BASE_URL", "https://192.0.2.1:8443"},
		{"NOC_BASE_URL", "https://localhost:8443"},
		{"NOC_BASE_URL", "https://127.0.0.1"},
		{"NOC_BASE_URL", "https://127.0.0.1:443"},
		{"NOC_DATABASE_URL", ""},
		{"NOC_DATABASE_URL", "postgres://synthetic:secret@192.0.2.1:5432/noc?sslmode=disable"},
		{"NOC_DATABASE_URL", "host=127.0.0.1 password=secret"},
		{"NOC_DATABASE_URL", "postgres://synthetic:secret@localhost:5432/noc?sslmode=disable"},
		{"NOC_DATABASE_URL", "postgres://synthetic@127.0.0.1:5432/noc?sslmode=disable"},
		{"NOC_DATABASE_URL", "postgres://synthetic:secret@127.0.0.1:5432/noc"},
		{"NOC_DATABASE_URL", "postgres://synthetic:secret@127.0.0.1:5432/noc?sslmode=allow"},
		{"NOC_DATABASE_URL", "postgres://synthetic:secret@127.0.0.1:5432/noc?sslmode=disable&host=192.0.2.1"},
		{"NOC_DATABASE_URL", "postgres://synthetic:secret@127.0.0.1:5432/noc?sslmode=disable&sslmode=require"},
		{"NOC_DATABASE_URL", "postgres://synthetic:secret@127.0.0.1:5432/noc?sslmode=disable&service=external"},
		{"NOC_DATABASE_URL", "postgres://synthetic:secret@127.0.0.1:5432/noc?sslmode=disable&bad=%zz"},
		{"NOC_PASSWORD_HASH", "secret"},
		{"NOC_PASSWORD_HASH", "$2a$14$malformed"},
		{"NOC_SESSION_TTL", "59s"},
		{"NOC_SESSION_TTL", "25h"},
		{"NOC_SESSION_TTL", "garbage"},
		{"NOC_STARTUP_TIMEOUT", "100ms"},
		{"NOC_STARTUP_TIMEOUT", "61s"},
	} {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			_, err := Load()
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), tc.value) && len(tc.value) > 20 {
				t.Fatal("configuration error leaks a supplied value")
			}
		})
	}
}
