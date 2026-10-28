package web

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestIntegrationWorkspaceHTTP(t *testing.T) {
	h := inventoryFixture(t)
	cookie := authenticate(t, h)
	w := request(h, "GET", "/servers/new", nil, cookie)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	csrf := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(w.Body.String())[1]
	post := func(path string, v url.Values, code int) string {
		t.Helper()
		v.Set("csrf", csrf)
		w := request(h, "POST", path, v, cookie)
		if w.Code != code {
			t.Fatalf("%s want %d got %d %s", path, code, w.Code, w.Body.String())
		}
		return strings.Split(w.Header().Get("Location"), "?")[0]
	}
	cp := post("/customers", url.Values{"display_name": {"Synthetic workspace HTTP"}, "short_code": {"SPACE"}, "status": {"active"}}, 303)
	ep := post(cp+"/environments", url.Values{"name": {"Synthetic lab"}, "kind": {"lab"}, "status": {"active"}}, 303)
	cluster := post(ep+"/topology/clusters/new", url.Values{"name": {"Synthetic cluster"}, "type": {"generic"}, "lifecycle": {"active"}}, 303)
	asset := post(ep+"/topology/assets/new", url.Values{"name": {"Synthetic machine"}, "kind": {"server"}, "lifecycle": {"active"}}, 303)
	aid := asset[strings.LastIndex(asset, "/")+1:]
	endpoint := post(ep+"/topology/endpoints/new", url.Values{"asset_id": {aid}, "host": {"ssh.example.invalid"}, "port": {"2222"}, "protocol": {"ssh"}, "status": {"active"}}, 303)
	quick := func(path, kind string) string {
		return "/workspace/" + kind + "/" + path[strings.LastIndex(path, "/")+1:]
	}
	cq := quick(cluster, "clusters")
	aq := quick(asset, "assets")
	eq := quick(endpoint, "endpoints")
	for _, path := range []string{"/workspace", cq, aq, eq} {
		if request(h, "GET", path, nil).Code != 401 {
			t.Fatal("unauthenticated read", path)
		}
		if request(h, "POST", path, nil).Code != 401 && path != "/workspace" {
			t.Fatal("unauthenticated mutation", path)
		}
		if request(h, "POST", path, nil, cookie).Code != 403 && path != "/workspace" {
			t.Fatal("missing csrf", path)
		}
	}
	post(cq, url.Values{"operation": {"pin"}}, 410)
	post(cq, url.Values{"operation": {"note.save"}, "body": {"Synthetic <script>alert(1)</script> runbook"}, "visibility": {"private"}}, 303)
	w = request(h, "GET", cq, nil, cookie)
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>alert(1)</script>") || !strings.Contains(w.Body.String(), "&lt;script&gt;") {
		t.Fatal("note escaping", w.Code)
	}
	ids := regexp.MustCompile(`name="id" value="([a-f0-9-]{36})"`).FindAllStringSubmatch(w.Body.String(), -1)
	if len(ids) != 1 {
		t.Fatal("note identity", len(ids))
	}
	nid := ids[0][1]
	post(cq, url.Values{"operation": {"note.save"}, "id": {nid}, "body": {"Synthetic updated runbook"}, "visibility": {"shared"}}, 303)
	post(aq, url.Values{"operation": {"note.save"}, "id": {nid}, "body": {"Cross-resource overwrite"}, "visibility": {"private"}}, 404)
	post(cq, url.Values{"operation": {"note.save"}, "body": {""}, "visibility": {"private"}}, 422)
	for _, u := range []string{"javascript:alert(1)", "https://user:secret@example.invalid/", "https://example.invalid/?token=secret"} {
		post(cq, url.Values{"operation": {"link.save"}, "label": {"Bad"}, "url": {u}, "type": {"rtm"}}, 422)
	}
	post(cq, url.Values{"operation": {"link.save"}, "label": {"Synthetic RTM <test>"}, "url": {"https://rtm.example.invalid/"}, "type": {"rtm"}, "pinned": {"on"}}, 303)
	w = request(h, "GET", cq, nil, cookie)
	if !strings.Contains(w.Body.String(), `rel="noopener noreferrer"`) || !strings.Contains(w.Body.String(), "Synthetic RTM &lt;test&gt;") {
		t.Fatal("external link", w.Body.String())
	}
	ids = regexp.MustCompile(`name="id" value="([a-f0-9-]{36})"`).FindAllStringSubmatch(w.Body.String(), -1)
	if len(ids) != 2 {
		t.Fatal("note and link identities", len(ids))
	}
	lid := ids[1][1]
	linkChange := url.Values{"operation": {"link.save"}, "id": {lid}, "label": {"Synthetic RTM <test>"}, "url": {"https://rtm.example.invalid/"}, "type": {"rtm"}, "disabled": {"on"}}
	post(cq, linkChange, 303)
	w = request(h, "GET", cq, nil, cookie)
	if strings.Contains(w.Body.String(), `href="https://rtm.example.invalid/"`) || !strings.Contains(w.Body.String(), "· disabled") {
		t.Fatal("disabled link remains navigable")
	}
	linkChange.Del("disabled")
	post(cq, linkChange, 303)
	w = request(h, "GET", cq, nil, cookie)
	if !strings.Contains(w.Body.String(), `href="https://rtm.example.invalid/"`) {
		t.Fatal("re-enabled link unavailable")
	}
	post(aq, url.Values{"operation": {"command.copy"}}, 410)
	post(eq, url.Values{"operation": {"command.copy"}}, 410)
	for _, q := range []string{"runbo", "ssh", "Synthetic", "' OR 1=1 --", "<script>"} {
		w = request(h, "GET", "/workspace?q="+url.QueryEscape(q), nil, cookie)
		if w.Code != 303 || w.Header().Get("Location") != "/servers?q="+url.QueryEscape(q) {
			t.Fatal("search", q, w.Code)
		}
	}
	post(cq, url.Values{"operation": {"note.remove"}, "id": {nid}}, 303)
	w = request(h, "GET", cq, nil, cookie)
	if strings.Contains(w.Body.String(), "Synthetic updated runbook") {
		t.Fatal("note removal")
	}
	if request(h, "GET", "/workspace/assets/not-a-uuid", nil, cookie).Code != 404 {
		t.Fatal("missing target")
	}
	post(cluster+"/edit", url.Values{"name": {"Synthetic cluster"}, "type": {"generic"}, "lifecycle": {"archived"}}, 303)
	post(cq, url.Values{"operation": {"pin"}}, 410)
	if request(h, "GET", "/workspace?offset=-1", nil, cookie).Code != 303 {
		t.Fatal("negative page")
	}
}
