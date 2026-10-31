package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
	"noc-workbench/internal/store/postgres"
)

// Own a disposable schema, even when integration tests share a database.
func inventoryFixture(t *testing.T) http.Handler { return inventoryFixtureWith(t, nil) }
func inventoryFixtureWith(t *testing.T, configure func(*postgres.Store, *Options)) http.Handler {
	return inventoryFixtureDatabase(t, func(db *postgres.Store, o *Options, _ string) {
		if configure != nil {
			configure(db, o)
		}
	})
}
func inventoryFixtureDatabase(t *testing.T, configure func(*postgres.Store, *Options, string)) http.Handler {
	return inventoryFixtureDatabaseRuntime(t, configure, nil)
}
func inventoryFixtureDatabaseRuntime(t *testing.T, configure func(*postgres.Store, *Options, string), settings map[string]string) http.Handler {
	t.Helper()
	dsn := os.Getenv("NOC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PostgreSQL integration requires NOC_TEST_DATABASE_URL")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid test URL")
	}
	ip := net.ParseIP(u.Hostname())
	if (u.Scheme != "postgres" && u.Scheme != "postgresql") || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
		t.Fatal("test database must be loopback PostgreSQL")
	}
	for key := range u.Query() {
		if key != "sslmode" {
			t.Fatal("unsupported test URL parameter")
		}
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "nw_web_test_" + hex.EncodeToString(suffix[:])
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	t.Cleanup(func() {
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Error("cleanup connection")
			return
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, "DROP SCHEMA "+ident+" CASCADE"); err != nil {
			t.Error("cleanup schema")
		}
	})
	q := u.Query()
	q.Set("search_path", schema)
	for key, value := range settings {
		q.Set(key, value)
	}
	u.RawQuery = q.Encode()
	db, err := postgres.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	hash, err := bcrypt.GenerateFromPassword([]byte("synthetic-test-password"), 10)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{BaseURL: "http://127.0.0.1:8080", PasswordHash: string(hash), SessionTTL: time.Hour}
	if configure != nil {
		configure(db, &options, u.String())
	}
	return New(db, options)
}

func TestIntegrationInventoryHTTP(t *testing.T) {
	h := inventoryFixture(t)
	for _, p := range []string{"/customers", "/customers/new", "/customers/invalid", "/customers/invalid/environments/new"} {
		if w := request(h, "GET", p, nil); w.Code != 401 {
			t.Fatalf("unauthorized GET %s: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/customers", "/customers/invalid/edit", "/customers/invalid/environments", "/customers/invalid/environments/invalid/edit"} {
		if w := request(h, "POST", p, nil); w.Code != 401 {
			t.Fatalf("unauthorized POST %s: %d", p, w.Code)
		}
	}
	cookie := authenticate(t, h)
	page := request(h, "GET", "/customers", nil, cookie)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "No customers yet") {
		t.Fatalf("empty state: %d %s", page.Code, page.Body.String())
	}
	match := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())
	if len(match) != 2 {
		t.Fatal("missing CSRF")
	}
	csrf := match[1]
	post := func(path string, v url.Values, code int) string {
		t.Helper()
		v.Set("csrf", csrf)
		w := request(h, "POST", path, v, cookie)
		if w.Code != code {
			t.Fatalf("POST %s: got %d want %d: %s", path, w.Code, code, w.Body.String())
		}
		return w.Header().Get("Location")
	}
	for _, p := range []string{"/customers", "/customers/invalid/edit", "/customers/invalid/environments", "/customers/invalid/environments/invalid/edit"} {
		if w := request(h, "POST", p, nil, cookie); w.Code != 403 {
			t.Fatalf("missing CSRF %s: %d", p, w.Code)
		}
	}
	customer := func(name, code string) url.Values {
		return url.Values{"display_name": {name}, "short_code": {code}, "notes": {"<script>synthetic</script>"}, "status": {"active"}}
	}
	post("/customers", customer("", "BAD"), 422)
	path := strings.Split(post("/customers", customer("Synthetic <Customer>", "SYN"), 303), "?")[0]
	other := strings.Split(post("/customers", customer("Synthetic Other", "OTHER"), 303), "?")[0]
	post("/customers", customer("synthetic <customer>", "NEW"), 422)
	post("/customers", customer("Another", "syn"), 422)
	body := request(h, "GET", path+"/edit", nil, cookie).Body.String()
	if strings.Contains(body, "<script>synthetic") || !strings.Contains(body, "&lt;Customer&gt;") || !strings.Contains(body, "&lt;script&gt;synthetic") {
		t.Fatal("unescaped customer")
	}
	large := customer("Updated synthetic", "SYN")
	large.Set("notes", strings.Repeat("&", 4096))
	post(path+"/edit", large, 303)
	if body := request(h, "GET", path+"/edit", nil, cookie).Body.String(); !strings.Contains(body, strings.Repeat("&amp;", 4096)) {
		t.Fatal("large encoded note lost")
	}
	large.Set("notes", strings.Repeat("&", 4097))
	post(path+"/edit", large, 422)
	large.Set("notes", strings.Repeat("&", 6000))
	post(path+"/edit", large, 400)
	post(path+"/edit", customer("Updated synthetic", "SYN"), 303)
	env := url.Values{"name": {"Synthetic <lab>"}, "kind": {"lab"}, "status": {"active"}}
	ep := strings.Split(post(path+"/environments", env, 303), "?")[0]
	post(path+"/environments", env, 422)
	post(path+"/environments", url.Values{"name": {"Bad"}, "kind": {"invalid"}, "status": {"active"}}, 422)
	post(path+"/environments", url.Values{"name": {"Bad owner"}, "kind": {"lab"}, "status": {"active"}, "customer_id": {strings.TrimPrefix(other, "/customers/")}}, 403)
	eid := ep[strings.LastIndex(ep, "/")+1:]
	for _, p := range []string{other + "/environments/" + eid, other + "/environments/" + eid + "/edit", "/customers/invalid"} {
		if w := request(h, "GET", p, nil, cookie); w.Code != 404 {
			t.Fatalf("scope %s: %d", p, w.Code)
		}
	}
	post(other+"/environments/"+eid+"/edit", env, 404)
	if body := request(h, "GET", ep+"/edit", nil, cookie).Body.String(); !strings.Contains(body, "Synthetic &lt;lab&gt;") {
		t.Fatal("unescaped environment")
	}
	env.Set("name", "Renamed synthetic")
	env.Set("kind", "production")
	env.Set("status", "archived")
	post(ep+"/edit", env, 303)
	archived := customer("Updated synthetic", "SYN")
	archived.Set("status", "archived")
	post(path+"/edit", archived, 303)
	post(ep+"/edit", env, 409)
	post(path+"/environments", env, 409)
	if w := request(h, "GET", ep, nil, cookie); w.Code != 303 || !strings.Contains(w.Header().Get("Location"), "/manage/records?") {
		t.Fatal("archive lost child")
	}
	archived.Set("status", "active")
	post(path+"/edit", archived, 303)
	env.Set("status", "active")
	post(ep+"/edit", env, 303)
	post("/logout", url.Values{}, 303)
	if w := request(h, "GET", path, nil, cookie); w.Code != 401 {
		t.Fatal("logout session survived")
	}
}
