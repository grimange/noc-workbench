package vicidialapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type referenceFunc func(context.Context, string, int64) (Reference, error)

func (f referenceFunc) AuthorizeAPIReference(ctx context.Context, id string, rev int64) (Reference, error) {
	return f(ctx, id, rev)
}

func TestProtectedCatalogRotationAndScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	e := catalogEntry{ID: "synthetic", IntegrationID: "integration-a", Revision: 1, Enabled: true, Synthetic: true, Endpoint: "http://127.0.0.1:12345/vicidial/non_agent_api.php", ApprovedIP: "127.0.0.1", Campaign: "SYNTH01", User: "synthetic", Password: "canary-initial", ExpiresAt: time.Now().Add(time.Hour), LoggingReviewDigest: strings.Repeat("a", 64)}
	write := func() {
		b, _ := json.Marshal([]catalogEntry{e})
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	r := Reference{ID: "synthetic", IntegrationID: "integration-a", Revision: 1, Enabled: true}
	a := CatalogAuthority{Path: path, References: referenceFunc(func(context.Context, string, int64) (Reference, error) { return r, nil })}
	g, err := a.AuthorizeAPI(context.Background(), "integration-a", 1)
	if err != nil || g.Password != "canary-initial" {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprint(g), fmt.Sprintf("%+v", g), fmt.Sprintf("%#v", g)} {
		if strings.Contains(s, "canary") {
			t.Fatal("credential formatting leak")
		}
	}
	b, _ := json.Marshal(g)
	if strings.Contains(string(b), "canary") {
		t.Fatal("credential JSON leak")
	}
	e.Password = "canary-rotated"
	write()
	g, err = a.AuthorizeAPI(context.Background(), "integration-a", 1)
	if err != nil || g.Password != e.Password {
		t.Fatal("rotation not observed", err)
	}
	e.Enabled = false
	write()
	if _, err = a.AuthorizeAPI(context.Background(), "integration-a", 1); code(err) != "credential_unavailable" {
		t.Fatal(err)
	}
	e.Enabled = true
	e.Revision = 2
	write()
	if _, err = a.AuthorizeAPI(context.Background(), "integration-a", 1); code(err) != "credential_unavailable" {
		t.Fatal("stale configuration accepted", err)
	}
	e.Revision = 1
	e.IntegrationID = "integration-b"
	write()
	if _, err = a.AuthorizeAPI(context.Background(), "integration-a", 1); code(err) != "credential_unavailable" {
		t.Fatal("cross-integration credential accepted", err)
	}
	e.IntegrationID = "integration-a"
	e.ExpiresAt = time.Unix(1, 0)
	write()
	if _, err = a.AuthorizeAPI(context.Background(), "integration-a", 1); code(err) != "credential_unavailable" {
		t.Fatal("expired credential", err)
	}
	e.ExpiresAt = time.Now().Add(time.Hour)
	write()
	r.Enabled = false
	if _, err = a.AuthorizeAPI(context.Background(), "integration-a", 1); code(err) != "authorization_rejected" {
		t.Fatal("revoked application authority", err)
	}
}

func TestCatalogRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog")
	if err := os.WriteFile(path, []byte(`[]`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCatalog(path); code(err) != "credential_unavailable" {
		t.Fatal("readable secret accepted", err)
	}
	os.Chmod(path, 0600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readCatalog(link); code(err) != "credential_unavailable" {
		t.Fatal("symlink accepted", err)
	}
	for _, body := range []string{`[{"ID":"x","IntegrationID":"a","Revision":1,"Unexpected":"secret"}]`, `[] []`, strings.Repeat("x", 65537), `[{"ID":"x","IntegrationID":"a","Revision":1},{"ID":"x","IntegrationID":"b","Revision":1}]`} {
		os.WriteFile(path, []byte(body), 0600)
		if _, err := readCatalog(path); code(err) != "credential_unavailable" {
			t.Fatal("invalid catalog accepted", err)
		}
	}
	if _, err := readCatalog(dir); code(err) != "credential_unavailable" {
		t.Fatal("directory accepted", err)
	}
}
