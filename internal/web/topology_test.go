package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestIntegrationTopologyHTTP(t *testing.T) {
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
		return w.Header().Get("Location")
	}
	cp := strings.Split(post("/customers", url.Values{"display_name": {"Synthetic topology HTTP"}, "short_code": {"HTTPTOPO"}, "status": {"active"}}), "?")[0]
	ep := strings.Split(post(cp+"/environments", url.Values{"name": {"Synthetic lab"}, "kind": {"lab"}, "status": {"active"}}), "?")[0]
	base := ep + "/topology"
	create := func(kind string, v url.Values) string { return strings.Split(post(base+"/"+kind+"/new", v), "?")[0] }
	cluster := create("clusters", url.Values{"name": {"Synthetic <script>cluster</script>"}, "type": {"generic"}, "lifecycle": {"active"}})
	cid := cluster[strings.LastIndex(cluster, "/")+1:]
	asset := create("assets", url.Values{"name": {"Synthetic host"}, "kind": {"server"}, "lifecycle": {"active"}})
	aid := asset[strings.LastIndex(asset, "/")+1:]
	endpoint := create("endpoints", url.Values{"asset_id": {aid}, "protocol": {"ssh"}, "host": {"2001:db8::1"}, "port": {"22"}, "status": {"active"}})
	member := create("memberships", url.Values{"cluster_id": {cid}, "asset_id": {aid}, "role": {"web"}})
	service := create("services", url.Values{"cluster_id": {cid}, "name": {"Synthetic service"}, "service_type": {"web"}, "lifecycle": {"active"}})
	sid := service[strings.LastIndex(service, "/")+1:]
	instance := create("instances", url.Values{"service_id": {sid}, "name": {"Synthetic instance"}, "role": {"worker"}, "instance_key": {"web-1"}, "lifecycle": {"active"}})
	iid := instance[strings.LastIndex(instance, "/")+1:]
	binding := create("bindings", url.Values{"service_instance_id": {iid}, "asset_id": {aid}, "binding_role": {"primary"}})
	for _, p := range []string{base, base + "/clusters", cluster, asset, endpoint, member, service, instance, binding} {
		w := request(h, "GET", p, nil, cookie)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "</html>") {
			t.Fatalf("GET %s %d %s", p, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "<script>cluster</script>") {
			t.Fatal("unescaped HTML")
		}
		if request(h, "GET", p, nil).Code != 401 {
			t.Fatal("unauthorized read")
		}
		if request(h, "GET", p+"/edit", nil, cookie).Code != 200 && p != base && p != base+"/clusters" {
			t.Fatal("edit form", p)
		}
	}
	for _, kind := range []string{"clusters", "assets", "endpoints", "memberships", "services", "instances", "bindings"} {
		if request(h, "POST", base+"/"+kind+"/new", nil, cookie).Code != 403 {
			t.Fatal("missing CSRF", kind)
		}
		if request(h, "POST", base+"/"+kind+"/new", url.Values{"csrf": {csrf}}).Code != 401 {
			t.Fatal("unauthorized mutation")
		}
		if w := request(h, "POST", base+"/"+kind+"/new", url.Values{"csrf": {csrf}}, cookie); w.Code != 422 {
			t.Fatalf("invalid fields %s %d", kind, w.Code)
		}
	}
	if w := request(h, "POST", base+"/memberships/new", url.Values{"csrf": {csrf}, "cluster_id": {cid}, "asset_id": {aid}}, cookie); w.Code != 422 {
		t.Fatal("duplicate", w.Code)
	}
	// Parent path ownership must be checked before any record mutation.
	alien := strings.Split(post(cp+"/environments", url.Values{"name": {"Synthetic other lab"}, "kind": {"lab"}, "status": {"active"}}), "?")[0]
	if request(h, "GET", strings.Replace(asset, ep, alien, 1), nil, cookie).Code != 404 {
		t.Fatal("cross-environment read")
	}
	if request(h, "POST", strings.Replace(asset, ep, alien, 1)+"/edit", url.Values{"csrf": {csrf}}, cookie).Code != 404 {
		t.Fatal("cross-environment update")
	}
	post(member+"/remove", url.Values{})
	if request(h, "GET", member, nil, cookie).Code != 404 {
		t.Fatal("membership removal")
	}
	if request(h, "GET", asset, nil, cookie).Code != 200 {
		t.Fatal("removal deleted asset")
	}
	post(binding+"/remove", url.Values{})
	post(asset+"/edit", url.Values{"name": {"Synthetic renamed"}, "kind": {"server"}, "lifecycle": {"archived"}})
	if w := request(h, "POST", base+"/endpoints/new", url.Values{"csrf": {csrf}, "asset_id": {aid}, "protocol": {"ssh"}, "host": {"192.0.2.5"}, "port": {"22"}, "status": {"active"}}, cookie); w.Code != http.StatusConflict {
		t.Fatal("archived reference", w.Code)
	}
}
