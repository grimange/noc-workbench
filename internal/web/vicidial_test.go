package web

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestIntegrationVICIdialContextHTTP(t *testing.T) {
	h := inventoryFixture(t)
	cookie := authenticate(t, h)
	csrf := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(request(h, "GET", "/customers", nil, cookie).Body.String())[1]
	post := func(path string, v url.Values) string {
		t.Helper()
		v.Set("csrf", csrf)
		w := request(h, "POST", path, v, cookie)
		if w.Code != 303 {
			t.Fatalf("POST %s: %d %s", path, w.Code, w.Body.String())
		}
		return strings.Split(w.Header().Get("Location"), "?")[0]
	}
	cp := post("/customers", url.Values{"display_name": {"Synthetic VIC context"}, "short_code": {"VICWEB"}, "status": {"active"}})
	ep := post(cp+"/environments", url.Values{"name": {"Synthetic lab"}, "kind": {"lab"}, "status": {"active"}})
	create := func(kind string, v url.Values) string { return post(ep+"/topology/"+kind+"/new", v) }
	cluster := create("clusters", url.Values{"name": {"Synthetic VIC cluster"}, "type": {"generic"}, "lifecycle": {"active"}})
	id := func(path string) string { return path[strings.LastIndex(path, "/")+1:] }
	path := ep + "/clusters/" + id(cluster) + "/vicidial"
	for _, roles := range []string{"dialer, web", "dialer", "database"} {
		asset := create("assets", url.Values{"name": {"Synthetic " + roles}, "kind": {"server"}, "lifecycle": {"active"}})
		create("memberships", url.Values{"cluster_id": {id(cluster)}, "asset_id": {id(asset)}, "role": {roles}})
	}
	service := create("services", url.Values{"cluster_id": {id(cluster)}, "name": {"Synthetic VIC web service"}, "service_type": {"web"}, "lifecycle": {"active"}})
	instance := create("instances", url.Values{"service_id": {id(service)}, "name": {"Synthetic shared instance"}, "role": {"web"}, "instance_key": {"v1"}, "lifecycle": {"active"}})
	assetsPage := request(h, "GET", ep+"/topology/assets", nil, cookie).Body.String()
	assetPath := regexp.MustCompile(ep + `/topology/assets/([a-f0-9-]{36})`).FindStringSubmatch(assetsPage)
	if len(assetPath) != 2 {
		t.Fatal("asset fixture")
	}
	create("bindings", url.Values{"service_instance_id": {id(instance)}, "asset_id": {assetPath[1]}, "binding_role": {"primary"}})
	if w := request(h, "GET", path, nil, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "not registered") {
		t.Fatal("optional empty context", w.Code)
	}
	if request(h, "GET", path, nil).Code != 401 {
		t.Fatal("unauthenticated read")
	}
	if request(h, "POST", path, nil, cookie).Code != 403 {
		t.Fatal("CSRF required")
	}
	if request(h, "POST", path, url.Values{"csrf": {csrf}}).Code != 401 {
		t.Fatal("unauthenticated mutation")
	}
	post(path, url.Values{"revision": {"0"}, "name": {"Synthetic <script>integration</script>"}, "enabled": {"yes"}})
	w := request(h, "GET", path, nil, cookie)
	body := w.Body.String()
	for _, text := range []string{"dialer, web", "database", "Unknown · no supported automatic revision discovery", "Unknown: no retained Linux observations", "Campaign and dialer health remain Unknown", "not configured in V1", "integration enabled", "Synthetic shared instance", "Synthetic VIC web service"} {
		if !strings.Contains(body, text) {
			t.Fatalf("missing %q (%d): %s", text, w.Code, body)
		}
	}
	if strings.Contains(body, "<script>integration</script>") {
		t.Fatal("metadata XSS")
	}
	if !strings.Contains(request(h, "GET", cluster, nil, cookie).Body.String(), path) {
		t.Fatal("generic cluster navigation")
	}
	quick := "/workspace/clusters/" + id(cluster)
	post(quick, url.Values{"operation": {"link.save"}, "label": {"Synthetic official RTM"}, "url": {"https://example.invalid/vicidial/realtime.php"}, "type": {"rtm"}, "enabled": {"yes"}})
	body = request(h, "GET", path, nil, cookie).Body.String()
	if !strings.Contains(body, "https://example.invalid/vicidial/realtime.php") {
		t.Fatal("authoritative Quick Access missing")
	}
	linkMatch := regexp.MustCompile(`name="id" value="([a-f0-9-]{36})"`).FindStringSubmatch(request(h, "GET", quick, nil, cookie).Body.String())
	if len(linkMatch) != 2 {
		t.Fatal("canonical link identity")
	}
	post(quick, url.Values{"operation": {"link.save"}, "id": {linkMatch[1]}, "label": {"Synthetic official RTM"}, "url": {"https://example.invalid/vicidial/realtime.php"}, "type": {"rtm"}, "disabled": {"on"}})
	if strings.Contains(request(h, "GET", path, nil, cookie).Body.String(), "https://example.invalid/vicidial/realtime.php") {
		t.Fatal("disabled canonical link exposed")
	}
	post(quick, url.Values{"operation": {"link.save"}, "id": {linkMatch[1]}, "label": {"Synthetic official RTM"}, "url": {"https://example.invalid/vicidial/realtime.php"}, "type": {"rtm"}})
	for _, bad := range []string{"javascript:alert(1)", "https://user:password@example.invalid/"} {
		if request(h, "POST", quick, url.Values{"csrf": {csrf}, "operation": {"link.save"}, "label": {"Synthetic rejected"}, "url": {bad}, "type": {"admin"}}, cookie).Code != 422 {
			t.Fatal("unsafe URL", bad)
		}
	}
	if request(h, "POST", path, url.Values{"csrf": {csrf}, "revision": {"0"}, "name": {"Stale writer"}}, cookie).Code != 422 {
		t.Fatal("stale update accepted")
	}
	if request(h, "POST", path, url.Values{"csrf": {csrf}, "revision": {"1"}, "name": {"Synthetic invalid"}, "version": {"2.14"}}, cookie).Code != 422 {
		t.Fatal("missing revision provenance")
	}
	alien := post(cp+"/environments", url.Values{"name": {"Synthetic other environment"}, "kind": {"lab"}, "status": {"active"}})
	if request(h, "GET", strings.Replace(path, ep, alien, 1), nil, cookie).Code != 404 {
		t.Fatal("cross-environment read")
	}
	if request(h, "POST", strings.Replace(path, ep, alien, 1), url.Values{"csrf": {csrf}, "name": {"Invalid"}, "revision": {"0"}}, cookie).Code != 404 {
		t.Fatal("cross-environment mutation")
	}
	post(path, url.Values{"revision": {"1"}, "name": {"Synthetic documented installation"}, "version": {"2.14-revision-synthetic"}, "source": {"Operator synthetic fixture"}})
	body = request(h, "GET", path, nil, cookie).Body.String()
	if !strings.Contains(body, "integration disabled") || !strings.Contains(body, "2.14-revision-synthetic") || strings.Contains(body, "Existing Linux evidence") {
		t.Fatal("disable/provenance", body)
	}
	post(path, url.Values{"revision": {"2"}, "name": {"Synthetic documented installation"}, "enabled": {"yes"}})
	if !strings.Contains(request(h, "GET", path, nil, cookie).Body.String(), "dialer, web") {
		t.Fatal("canonical roles lost")
	}
	// An unrelated generic cluster remains independent and unregistered.
	generic := create("clusters", url.Values{"name": {"Synthetic Linux only"}, "type": {"generic"}, "lifecycle": {"active"}})
	if !strings.Contains(request(h, "GET", ep+"/clusters/"+id(generic)+"/vicidial", nil, cookie).Body.String(), "not registered") {
		t.Fatal("automatic integration registration")
	}
}
