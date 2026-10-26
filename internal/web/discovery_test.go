package web

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/testlab"
	"noc-workbench/internal/workspace"
)

type failingTrustSave struct {
	connections.Repository
	connections.DurableGuard
}

func (f failingTrustSave) SaveEnrollment(context.Context, workspace.Principal, connections.Record, int64, string) (connections.Record, error) {
	return connections.Record{}, errors.New("synthetic private database error")
}

func TestDiscoveryAuthenticationBeforeService(t *testing.T) {
	h, _ := fixture(t)
	path := "/customers/00000000-0000-4000-8000-000000000001/environments/00000000-0000-4000-8000-000000000001/assets/00000000-0000-4000-8000-000000000001/linux"
	for _, method := range []string{"GET", "POST"} {
		if w := request(h, method, path, nil); w.Code != 401 {
			t.Fatal(method, w.Code)
		}
	}
}

// Uses real PG, the actual enrollment approval service, and a disposable sshd
// under the current unprivileged account. Never uses installed inventory/keys.
func TestIntegrationLinuxDiscoveryHTTP(t *testing.T) {
	lab := testlab.Start(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	var db *postgres.Store
	var svc *connections.Service
	var discover *collection.Service
	var opts Options
	var c inventory.Customer
	var env inventory.Environment
	var asset inventory.Asset
	var ep inventory.Endpoint
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	h := inventoryFixtureWith(t, func(store *postgres.Store, o *Options) {
		db = store
		var e error
		svc, e = connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
		must(e)
		discover = collection.NewService(svc, linux.Registry())
		o.Enrollment = svc
		o.Discovery = discover
		c, e = db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic Linux discovery", ShortCode: "LINUXLAB", Status: "active"})
		must(e)
		env, e = db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Loopback lab", Kind: "lab", Status: "active"})
		must(e)
		asset, e = db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic observed host", Kind: "server", Lifecycle: "active"})
		must(e)
		ep, e = db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: asset.ID, Host: "127.0.0.1", Port: lab.Port, Protocol: "ssh", Status: "active"})
		must(e)
		opts = *o
	})
	path := fmt.Sprintf("/customers/%s/environments/%s/assets/%s/linux", c.ID, env.ID, asset.ID)
	cookie := authenticate(t, h)
	page := request(h, "GET", path, nil, cookie)
	if page.Code != 200 {
		t.Fatal(page.Code, page.Body.String())
	}
	// No enrollment and no collection merely by visiting.
	if strings.Contains(page.Body.String(), "Last requested collection</h2>") {
		t.Fatal("automatic collection")
	}
	r, e := svc.Create(ctx, actor, c.ID, env.ID, asset.ID, ep.ID, "127.0.0.1", lab.Credential.ID)
	must(e)
	act := func(action, fp, evidence string) {
		t.Helper()
		r, e = svc.Act(ctx, actor, r.EndpointID, r.ID, r.Revision, action, fp, evidence)
		must(e)
	}
	act("submit", "", "")
	act("authorize", "", "authorized")
	act("inspect", "", "")
	if r.Details.CandidateFingerprint != lab.Fingerprint {
		t.Fatal("independent fingerprint mismatch")
	}
	act("approve", lab.Fingerprint, "Synthetic lab console host key")
	// Approval alone is insufficient: discovery requires verified connectivity.
	_, e = svc.Execute(ctx, actor, r.Target(), "linux.uptime.v1")
	if e == nil {
		t.Fatal("unverified discovery executed")
	}
	act("verify", "", "")
	if r.State != "connection_verified" {
		t.Fatal(r.State, r.Details.LastCategory)
	}
	page = request(h, "GET", path, nil, cookie)
	csrfMatch := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(page.Body.String())
	if len(csrfMatch) != 2 {
		t.Fatal("missing collect form")
	}
	csrf := csrfMatch[1]
	form := func() url.Values {
		return url.Values{"csrf": {csrf}, "profile": {r.ID}, "endpoint": {r.EndpointID}, "revision": {fmt.Sprint(r.Revision)}}
	}
	noCSRF := form()
	noCSRF.Del("csrf")
	if request(h, "POST", path, noCSRF, cookie).Code != 403 {
		t.Fatal("missing CSRF allowed")
	}
	if request(h, "POST", path, form()).Code != 401 {
		t.Fatal("anonymous collection")
	}
	wrong := form()
	wrong.Set("revision", fmt.Sprint(r.Revision-1))
	if request(h, "POST", path, wrong, cookie).Code != 409 {
		t.Fatal("stale posted revision")
	}
	filesBefore, e := os.ReadDir(lab.Dir)
	must(e)
	before, e := os.ReadFile("/proc/uptime")
	must(e)
	response := request(h, "POST", path, form(), cookie)
	if response.Code != http.StatusSeeOther {
		t.Fatal(response.Code, response.Body.String())
	}
	after, e := os.ReadFile("/proc/uptime")
	must(e)
	run, ok := discover.Latest(actor, r.Target())
	if !ok || len(run.Results) != 5 {
		t.Fatal("missing normalized run")
	}
	observations := map[string]collection.Observation{}
	for _, result := range run.Results {
		if result.Outcome != "success" {
			t.Fatalf("real collector %s: %s %+v", result.CollectorID, result.Outcome, result.Diagnostics)
		}
		for _, o := range result.Observations {
			if o.AssetID != asset.ID || o.EndpointID != ep.ID || o.ProfileID != r.ID || o.ProfileVersion != r.Revision || o.Transport != "ssh" || o.Quality != "valid" || o.CollectorVersion != "1" || o.ObservedAt.IsZero() || o.ReceivedAt.Before(o.ObservedAt) {
				t.Fatal("invalid provenance", o)
			}
			observations[o.Key+o.Resource] = o
		}
	}
	low, _ := strconv.ParseFloat(strings.Fields(string(before))[0], 64)
	high, _ := strconv.ParseFloat(strings.Fields(string(after))[0], 64)
	uptime := observations["linux.uptime.seconds"].Value.Number
	if uptime < low || uptime > high {
		t.Fatalf("uptime outside independently observed interval: %f [%f,%f]", uptime, low, high)
	}
	mem, e := os.ReadFile("/proc/meminfo")
	must(e)
	match := regexp.MustCompile(`(?m)^MemTotal:\s+([0-9]+) kB$`).FindSubmatch(mem)
	if len(match) != 2 {
		t.Fatal("lab meminfo")
	}
	total, e := strconv.ParseUint(string(match[1]), 10, 64)
	must(e)
	if observations["linux.mem.total_bytes"].Value.Integer != total*1024 {
		t.Fatal("memory bytes differ from independent source")
	}
	host, e := os.Hostname()
	must(e)
	if observations["linux.hostname"].Value.Text != host {
		t.Fatal("observed hostname differs")
	}
	kernel, e := exec.Command("uname", "-r").Output()
	must(e)
	if observations["linux.kernel.release"].Value.Text != strings.TrimSpace(string(kernel)) {
		t.Fatal("kernel differs")
	}
	df, e := exec.Command("/bin/df", "-Pk", "/").Output()
	must(e)
	fields := strings.Fields(strings.Split(strings.TrimSpace(string(df)), "\n")[1])
	diskTotal, e := strconv.ParseUint(fields[1], 10, 64)
	must(e)
	if observations["linux.filesystem.total_bytes/"].Value.Integer != diskTotal*1024 {
		t.Fatal("root capacity differs from independent df")
	}
	for _, key := range []string{"linux.load.1m", "linux.load.5m", "linux.load.15m"} {
		n := observations[key].Value.Number
		if n < 0 || math.IsNaN(n) || math.IsInf(n, 0) || observations[key].Unit != "load" {
			t.Fatal("invalid load")
		}
	}
	filesAfter, e := os.ReadDir(lab.Dir)
	must(e)
	if len(filesBefore) != len(filesAfter) {
		t.Fatal("remote persistence in lab directory")
	}
	for i := range filesBefore {
		if filesBefore[i].Name() != filesAfter[i].Name() {
			t.Fatal("remote file created")
		}
	}
	page = request(h, "GET", path, nil, cookie)
	body := page.Body.String()
	for _, want := range []string{"Last requested collection</h2>", "linux.os.name", "linux.uptime.seconds", "linux.load.1m", "linux.mem.total_bytes", "linux.filesystem.total_bytes", "source SSH / linux.identity.v1", "not CPU utilization percentages"} {
		if !strings.Contains(body, want) {
			t.Fatal("missing UI", want)
		}
	}
	for _, secret := range []string{lab.Credential.IdentityFile, lab.Credential.IdentitySHA256, "BEGIN OPENSSH PRIVATE KEY"} {
		if strings.Contains(body, secret) {
			t.Fatal("sensitive UI disclosure")
		}
	}
	refreshed, _ := discover.Latest(actor, r.Target())
	if !refreshed.StartedAt.Equal(run.StartedAt) {
		t.Fatal("GET reran SSH")
	}
	// A replacement service cannot recover transient history; inventory persists.
	if _, ok := collection.NewService(svc, linux.Registry()).Latest(actor, r.Target()); ok {
		t.Fatal("unexpected durable run")
	}
	if _, e := db.GetAsset(ctx, env.ID, asset.ID); e != nil {
		t.Fatal("inventory lost")
	}

	durable := collection.NewService(svc, linux.Registry(), db)
	durableRun, e := durable.Collect(ctx, actor, r.Target())
	must(e)
	scope := collection.HistoryScope{CustomerID: c.ID, EnvironmentID: env.ID, AssetID: asset.ID}
	persisted, _, e := collection.NewService(svc, linux.Registry(), db).History(ctx, actor, scope, "")
	must(e)
	if len(persisted.Runs) != 1 || persisted.Runs[0].ID != durableRun.ID || persisted.Runs[0].State != "completed" || len(persisted.Latest) == 0 {
		t.Fatal("durable real SSH history missing")
	}
	opts.Discovery = collection.NewService(svc, linux.Registry(), db)
	durableHTTP := New(db, opts)
	durablePage := request(durableHTTP, "GET", path, nil, cookie)
	if durablePage.Code != 200 || !strings.Contains(durablePage.Body.String(), durableRun.ID) || !strings.Contains(durablePage.Body.String(), "Last successful observations") || !strings.Contains(durablePage.Body.String(), "fresh") {
		t.Fatal("durable HTTP evidence", durablePage.Code, durablePage.Body.String())
	}
	// Revocation fails at execution even before a GET updates display state.
	old := r.Target()
	data, e := os.ReadFile(lab.Catalog)
	must(e)
	must(os.WriteFile(lab.Catalog, []byte("[]"), 0600))
	_, e = svc.Execute(ctx, actor, old, "linux.uptime.v1")
	if e == nil {
		t.Fatal("revoked credential executed")
	}
	failedRun, e := durable.Collect(ctx, actor, old)
	must(e)
	persisted, _, e = durable.History(ctx, actor, scope, "")
	must(e)
	if persisted.Runs[0].ID != failedRun.ID || persisted.Runs[0].State != "failed" || len(persisted.Latest) == 0 {
		t.Fatal("failed SSH attempt erased durable evidence")
	}
	for _, o := range persisted.Latest {
		if o.RunID != durableRun.ID {
			t.Fatal("failed attempt replaced facts")
		}
	}
	must(os.WriteFile(lab.Catalog, data, 0600))
	// A real changed server key persists trust suspension. Returning the original
	// key cannot silently resume commands, even after creating a new service.
	hostKey, e := os.ReadFile(lab.Dir + "/host")
	must(e)
	wrongKey, e := os.ReadFile(lab.Dir + "/wrong")
	must(e)
	// A storage failure cannot leave the in-process UI or execution authority
	// claiming trust. Error contents must not reach the rendered diagnostics.
	svc.Repository = failingTrustSave{db, db}
	lab.ReplaceHostKey(t, wrongKey)
	response = request(durableHTTP, "POST", path, form(), cookie)
	if response.Code != 303 {
		t.Fatal(response.Code, response.Body.String())
	}
	page = request(durableHTTP, "GET", path, nil, cookie)
	if !strings.Contains(page.Body.String(), "identity_changed") || !strings.Contains(page.Body.String(), "Facts are withheld") || strings.Contains(page.Body.String(), "Collect Linux Facts</button>") || strings.Contains(page.Body.String(), "synthetic private database error") || strings.Contains(page.Body.String(), "linux.uptime.seconds</dt>") {
		t.Fatal("save failure trust/diagnostic UI", page.Body.String())
	}
	lab.ReplaceHostKey(t, hostKey)
	if _, e = svc.Execute(ctx, actor, r.Target(), "linux.uptime.v1"); e == nil {
		t.Fatal("save failure quarantine bypassed")
	}

	svc.Repository = db
	restarted, e := connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
	must(e)
	for range 2 {
		if _, e = restarted.Execute(ctx, actor, r.Target(), "linux.uptime.v1"); e == nil {
			t.Fatal("restart after failed invalidation executed")
		}
	}
	r, e = db.Enrollment(ctx, r.EndpointID, r.ID)
	must(e)
	if r.State != "identity_changed" || r.Details.ApprovedKey != "" {
		t.Fatal("restart recovery failed")
	}
	act("review", "", "")
	act("authorize", "", "authorized")
	act("inspect", "", "")
	act("approve", lab.Fingerprint, "Synthetic independent host identity after storage recovery")
	act("verify", "", "")
	old = r.Target()

	lab.ReplaceHostKey(t, wrongKey)
	response = request(h, "POST", path, form(), cookie)
	if response.Code != 303 {
		t.Fatal(response.Code, response.Body.String())
	}
	r, e = db.Enrollment(ctx, r.EndpointID, r.ID)
	must(e)
	if r.State != "identity_changed" || r.Details.ApprovedKey != "" || r.Details.VerifiedAt != nil || r.Revision != old.ProfileVersion+1 || r.Details.LastCategory != "host_key_mismatch" {
		t.Fatal("trust not suspended", r.State, r.Revision, r.Details.LastCategory)
	}
	page = request(h, "GET", path, nil, cookie)
	if !strings.Contains(page.Body.String(), "host_key_mismatch") || !strings.Contains(page.Body.String(), "previous revision are withheld") || strings.Contains(page.Body.String(), "Collect Linux Facts</button>") {
		t.Fatal("missing suspension UI", page.Body.String())
	}
	lab.ReplaceHostKey(t, hostKey)
	replacement, e := connections.New(db, db, connections.Catalog(lab.Catalog), connections.OperatorPolicy{})
	must(e)
	if _, e = replacement.Execute(ctx, actor, r.Target(), "linux.uptime.v1"); e == nil {
		t.Fatal("restored key bypassed persisted suspension")
	}
	// Explicit review, authorization and independently approved identity are needed.
	act("review", "", "")
	act("authorize", "", "authorized")
	act("inspect", "", "")
	act("approve", lab.Fingerprint, "Synthetic independent restored host identity")
	act("verify", "", "")
	if r.State != "connection_verified" {
		t.Fatal("explicit reapproval failed")
	}
	old = r.Target()

	// Live endpoint edits suspend the exact revision, including edit then revert.
	ep.Port++
	ep, e = db.SaveEndpoint(ctx, ep)
	must(e)
	_, e = svc.Execute(ctx, actor, old, "linux.uptime.v1")
	if e == nil {
		t.Fatal("changed endpoint executed")
	}
	if request(h, "POST", path, form(), cookie).Code != 409 {
		t.Fatal("stale endpoint HTTP executed")
	}
	r, e = db.Enrollment(ctx, r.EndpointID, r.ID)
	must(e)
	act("disable", "", "")
	_, e = svc.Execute(ctx, actor, r.Target(), "linux.uptime.v1")
	if e == nil {
		t.Fatal("disabled enrollment executed")
	}
	t.Log("PASS real SSH + PostgreSQL + authenticated HTTP: five collectors, independent hostname/kernel/proc/df measurements, timestamps/units/provenance, CSRF, stale revisions, revoked credentials, disabled enrollment, real changed/restored key requiring reapproval, PRG/GET without execution, temporary snapshots, no lab directory file additions")
}
