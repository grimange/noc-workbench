package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"noc-workbench/internal/interchange"
	"regexp"
	"strings"
	"testing"
)

func TestIntegrationInterchangeHTTP(t *testing.T) {
	h := inventoryFixture(t)
	path := "/inventory/interchange"
	for _, method := range []string{"GET", "POST"} {
		if w := request(h, method, path, nil); w.Code != 401 {
			t.Fatal("authentication", w.Code)
		}
	}
	cookie := authenticate(t, h)
	page := request(h, "GET", path, nil, cookie)
	if page.Code != 200 {
		t.Fatal(page.Code)
	}
	match := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())
	if len(match) != 2 {
		t.Fatal("csrf missing")
	}
	csrf := match[1]
	if w := request(h, "POST", path, url.Values{"document": {string(interchange.Example)}, "operation": {"import"}}, cookie); w.Code != 403 {
		t.Fatal("CSRF", w.Code)
	}
	for _, kind := range []string{"sanitized", "example"} {
		w := request(h, "GET", path+"?download="+kind, nil, cookie)
		if _, err := interchange.Parse(w.Body.Bytes()); w.Code != 200 || err != nil || w.Header().Get("Content-Type") != "application/json" {
			t.Fatal("download", kind, w.Code, err)
		}
	}
	post := func(raw, operation string, code int) string {
		t.Helper()
		w := request(h, "POST", path, url.Values{"csrf": {csrf}, "document": {raw}, "operation": {operation}}, cookie)
		if w.Code != code {
			t.Fatalf("%s: %d want %d: %s", operation, w.Code, code, w.Body.String())
		}
		return w.Body.String()
	}
	post(string(interchange.Example), "preview", 200)
	w := request(h, "GET", path+"?download=sanitized", nil, cookie)
	d, _ := interchange.Parse(w.Body.Bytes())
	if len(d.Records) != 0 {
		t.Fatal("preview retained inventory")
	}
	if b := post(string(interchange.Example), "import", 200); !strings.Contains(b, "Inventory import committed") {
		t.Fatal("missing success")
	}
	post(string(interchange.Example), "import", 200)
	post(`{"format":"<script>bad</script>"}`, "preview", 422)
	post(strings.Repeat("x", interchange.MaxBytes+1), "preview", 422)
	post(string(interchange.Example), "unknown", 400)
	w = request(h, "GET", path+"?download=sanitized", nil, cookie)
	d, e := interchange.Parse(w.Body.Bytes())
	if e != nil || len(d.Records) < 40 {
		t.Fatal("import/export", e)
	}
}

func TestIntegrationInterchangeCompactBoundary(t *testing.T) {
	h := inventoryFixture(t)
	cookie := authenticate(t, h)
	path := "/inventory/interchange"
	page := request(h, "GET", path, nil, cookie)
	csrf := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())[1]
	doc := interchange.Document{Format: interchange.Format, Version: 1, Records: []interchange.Record{}}
	for i := 0; i < 400; i++ {
		doc.Records = append(doc.Records, interchange.Record{Type: "customer", ID: interchange.Pseudonym(fmt.Sprint(i)), Fields: map[string]any{"display_name": strings.Repeat("<", 110) + fmt.Sprintf("%03d", i), "short_code": fmt.Sprintf("BOUND_%03d", i), "status": "active"}})
	}
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(doc); err != nil {
		t.Fatal(err)
	}
	if _, err := interchange.Parse(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := interchange.Encode(doc); err == nil {
		t.Fatal("fixture does not exercise output expansion")
	}
	form := url.Values{"csrf": {csrf}, "operation": {"preview"}, "document": {raw.String()}}
	preview := request(h, "POST", path, form, cookie)
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), "Confirm inventory import") || strings.Contains(preview.Body.String(), strings.Repeat("<", 110)) {
		t.Fatal("missing confirmation or unescaped JSON", preview.Code)
	}
	exported := request(h, "GET", path+"?download=sanitized", nil, cookie)
	empty, err := interchange.Parse(exported.Body.Bytes())
	if err != nil || len(empty.Records) != 0 {
		t.Fatal("preview mutated inventory", err)
	}
	form.Set("operation", "import")
	result := request(h, "POST", path, form, cookie)
	if result.Code != 200 || !strings.Contains(result.Body.String(), "Import result") {
		t.Fatal("boundary import", result.Code)
	}
	exported = request(h, "GET", path+"?download=sanitized", nil, cookie)
	got, err := interchange.Parse(exported.Body.Bytes())
	if err != nil || len(got.Records) != 400 {
		t.Fatal("boundary data lost", err)
	}
}
