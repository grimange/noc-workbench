package web

import (
	"context"
	"net/http"
	"net/url"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/store/postgres"
	"strings"
	"testing"
)

func dashboardFixture(t *testing.T) (http.Handler, *http.Cookie, string) {
	t.Helper()
	var db *postgres.Store
	h := inventoryFixtureWith(t, func(s *postgres.Store, _ *Options) { db = s })
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic dashboard owner", ShortCode: "DASH", Status: "active"})
	must(e)
	env, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Lab", Kind: "lab", Status: "active"})
	must(e)
	a, e := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic server", Kind: "server", Lifecycle: "active"})
	must(e)
	_, e = db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Protocol: "ssh", Host: "192.0.2.45", Port: 22, Preferred: true, Status: "active"})
	must(e)
	for _, name := range []string{"Alpha cluster", "Beta cluster"} {
		k, err := db.SaveCluster(ctx, inventory.Cluster{EnvironmentID: env.ID, Name: name, Lifecycle: "active"})
		must(err)
		_, err = db.SaveMembership(ctx, inventory.Membership{EnvironmentID: env.ID, ClusterID: k.ID, AssetID: a.ID})
		must(err)
	}
	service, e := db.SaveService(ctx, inventory.Service{EnvironmentID: env.ID, Name: "Synthetic application", ServiceType: "web", Lifecycle: "active"})
	must(e)
	instance, e := db.SaveInstance(ctx, inventory.Instance{EnvironmentID: env.ID, ServiceID: service.ID, Name: "Synthetic instance", Lifecycle: "active"})
	must(e)
	_, e = db.SaveBinding(ctx, inventory.Binding{EnvironmentID: env.ID, AssetID: a.ID, InstanceID: instance.ID})
	must(e)
	return h, authenticate(t, h), "/servers/" + a.ID
}
func TestIntegrationDashboardAndServer(t *testing.T) {
	h, cookie, path := dashboardFixture(t)
	for _, p := range []string{path, "/settings"} {
		if request(h, "GET", p, nil).Code != 401 {
			t.Fatal("authentication missing")
		}
	}
	listDenied := request(h, "GET", "/servers", nil)
	if listDenied.Code != http.StatusSeeOther || listDenied.Header().Get("Location") != "/login" {
		t.Fatal("server list must redirect unauthenticated navigation to login")
	}
	if request(h, "GET", "/servers", nil, &http.Cookie{Name: "nw_session", Value: "invalid"}).Code != http.StatusUnauthorized {
		t.Fatal("server list accepted invalid session")
	}
	for _, q := range []string{"", "Synthetic server", "192.0.2.45", "dashboard owner"} {
		w := request(h, "GET", "/?q="+url.QueryEscape(q), nil, cookie)
		if w.Code != 200 || !strings.Contains(w.Body.String(), path) {
			t.Fatalf("search %q %d %s", q, w.Code, w.Body.String())
		}
		for _, text := range []string{"Dashboard", "Alpha cluster", "Beta cluster", "Synthetic dashboard owner"} {
			if !strings.Contains(w.Body.String(), text) {
				t.Fatal("missing", text)
			}
		}
	}
	list := request(h, "GET", "/servers?q=Synthetic", nil, cookie)
	if list.Code != 200 || !strings.Contains(list.Body.String(), path) || !strings.Contains(list.Body.String(), `href="/servers" aria-current="page"`) {
		t.Fatal("server list alias", list.Body.String())
	}
	w := request(h, "GET", path, nil, cookie)
	if w.Code != 200 {
		t.Fatalf("details %d %s", w.Code, w.Body.String())
	}
	for _, text := range []string{"Synthetic application", "Synthetic instance", "Unknown — service health not established", "Unknown — no retained observations", "192.0.2.45"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Fatal("missing", text)
		}
	}
	if strings.Contains(w.Body.String(), "Last known value:") {
		t.Fatal("fabricated observation")
	}
	for _, q := range []string{"?offset=-1", "?offset=1", "?q=" + strings.Repeat("x", 121)} {
		if request(h, "GET", "/"+q, nil, cookie).Code != 400 {
			t.Fatal("invalid query accepted")
		}
	}
	if request(h, "GET", "/servers/invalid", nil, cookie).Code != 404 {
		t.Fatal("invalid identity")
	}
	if w = request(h, "GET", "/settings", nil, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "Workspace settings") {
		t.Fatal("settings unavailable")
	}
}
