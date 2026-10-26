package postgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type historyExecutor struct{ failAll, partial, noisy, longMount bool }

func (e historyExecutor) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, id string) (sshcli.Result, error) {
	now := time.Now().UTC()
	r := sshcli.Result{StartedAt: now, EndedAt: now.Add(time.Millisecond)}
	if e.failAll {
		r.Category = sshcli.ExecutionTimeout
		return r, &sshcli.Failure{Category: r.Category}
	}
	data := map[string]string{"linux.identity.v1": "synthetic\n6.1\nx86_64\nNAME=\"Synthetic Linux\"\nVERSION_ID=1\n", "linux.uptime.v1": "123.456 12.34\n", "linux.load.v1": "0.10 1.25 2.00 1/123 99\nCPU_COUNT=4\n", "linux.memory.v1": "MemTotal: 1024 kB\nMemAvailable: 512 kB\nMemFree: 128 kB\n", "linux.filesystems.v1": "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/synthetic 1000 100 900 10% /mount with spaces\n"}
	if e.noisy && id == "linux.filesystems.v1" {
		data[id] += strings.Repeat("malformed filesystem row\n", 25)
	}
	if e.longMount && id == "linux.filesystems.v1" {
		mount := "/"
		for i := range 127 {
			mount += fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(i))))[:32]
		}
		data[id] = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/synthetic 1000 100 900 10% " + mount + "\n"
	}
	r.Stdout = []byte(data[id])
	if e.partial && id == "linux.memory.v1" {
		r.Stdout = []byte("MemTotal: malformed\n")
	}
	return r, nil
}
func collectionFixture(t *testing.T) (*Store, collection.HistoryScope, sshcli.Target) {
	t.Helper()
	ctx := context.Background()
	db, e := Open(ctx, isolatedDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Close)
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic history", ShortCode: "HISTORY", Status: "active"})
	must(e)
	env, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Synthetic lab", Kind: "lab", Status: "active"})
	must(e)
	a, e := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic host", Kind: "server", Lifecycle: "active"})
	must(e)
	ep, e := db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Host: "192.0.2.10", Protocol: "ssh", Port: 22, Status: "active"})
	must(e)
	var id string
	// Synthetic approved record is for repository tests only: no SSH is contacted.
	must(db.pool.QueryRow(ctx, `INSERT INTO connection_profile(customer_id,environment_id,asset_id,endpoint_id,state,details) VALUES($1,$2,$3,$4,'connection_verified',jsonb_build_object('Host',$5::text,'Port',22,'EndpointUpdatedAt',$6::timestamptz,'ApprovedKey','synthetic-public-key','ApprovedFingerprint','synthetic','Evidence','Synthetic repository fixture','ApprovedBy',$7::text,'AuthorizedBy',$7::text,'ApprovedAt',clock_timestamp(),'AuthorizedAt',clock_timestamp(),'VerifiedAt',clock_timestamp())) RETURNING id::text`, c.ID, env.ID, a.ID, ep.ID, ep.Host, ep.UpdatedAt, workspace.OperatorID).Scan(&id))
	return db, collection.HistoryScope{CustomerID: c.ID, EnvironmentID: env.ID, AssetID: a.ID}, sshcli.Target{AssetID: a.ID, EndpointID: ep.ID, ProfileID: id, ProfileVersion: 1}
}
func TestIntegrationCollectionHistory(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	collect := func(e historyExecutor) collection.Run {
		t.Helper()
		s := collection.NewService(e, linux.Registry(), db)
		r, e2 := s.Collect(ctx, p, target)
		must(e2)
		return r
	}
	first := collect(historyExecutor{})
	if first.ID == "" {
		t.Fatal("missing run identity")
	}
	history, e := db.CollectionHistory(ctx, p, h, "")
	must(e)
	if len(history) != 1 || history[0].State != "completed" || len(history[0].Results) != 5 || history[0].SuccessCount != 5 {
		t.Fatalf("history %+v", history)
	}
	facts, e := db.LatestEvidence(ctx, p, h)
	must(e)
	if len(facts) < 15 {
		t.Fatal("missing persisted facts", len(facts))
	}
	for _, o := range facts {
		if o.RunID != first.ID || o.ProfileVersion != target.ProfileVersion || o.Quality != "valid" {
			t.Fatal("provenance")
		}
		o.At(o.ObservedAt.Add(181 * time.Second))
		if o.Freshness != "stale" {
			t.Fatal("freshness")
		}
		o.At(o.ObservedAt.Add(time.Second))
		if o.Freshness != "fresh" {
			t.Fatal("freshness")
		}
	}
	partial := collect(historyExecutor{partial: true})
	failed := collect(historyExecutor{failAll: true})
	history, e = db.CollectionHistory(ctx, p, h, "")
	must(e)
	if len(history) != 3 || history[0].State != "failed" || history[1].State != "partial" {
		t.Fatalf("outcomes %+v", history)
	}
	facts, e = db.LatestEvidence(ctx, p, h)
	must(e)
	for _, o := range facts {
		if o.RunID == failed.ID {
			t.Fatal("failed replaced valid")
		}
		if o.Key == "linux.mem.total_bytes" && o.RunID != first.ID {
			t.Fatal("partial erased memory")
		}
		if o.Key == "linux.uptime.seconds" && o.RunID != partial.ID {
			t.Fatal("latest not newest success")
		}
	}
	// Duplicate completion and late mutation cannot overwrite an accepted run.
	if db.FinishCollection(ctx, p, first, 180) == nil {
		t.Fatal("duplicate completion")
	}
	if _, e = db.CollectionHistory(ctx, workspace.Principal{ID: "unauthorized"}, h, ""); e == nil {
		t.Fatal("unauthorized history")
	}
	alien := h
	alien.EnvironmentID = workspace.OperatorID
	empty, e := db.LatestEvidence(ctx, p, alien)
	must(e)
	if len(empty) != 0 {
		t.Fatal("foreign evidence")
	}
	// A result error after earlier inserts rolls the entire evidence transaction back.
	pending, e := db.BeginCollection(ctx, p, target)
	must(e)
	bad, e := linux.Registry().Collect(ctx, historyExecutor{}, p, target, linux.Registry().IDs())
	must(e)
	bad.ID = pending.ID
	bad.PrincipalID = p.ID
	bad.StartedAt = pending.StartedAt
	bad.Results[4].Observations[0].Unit = "invalid"
	if db.FinishCollection(ctx, p, bad, 180) == nil {
		t.Fatal("invalid unit accepted")
	}
	var count int
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM collector_result WHERE run_id=$1`, pending.ID).Scan(&count))
	if count != 0 {
		t.Fatal("partial transaction survived")
	}
	must(db.RecoverCollections(ctx))
	history, e = db.CollectionHistory(ctx, p, h, "")
	must(e)
	if history[0].State != "interrupted" || len(history[0].Results) != 0 {
		t.Fatal("interrupted invented evidence")
	}
	// SQL boundaries independently enforce ownership, types, provenance and units.
	for _, q := range []string{
		`UPDATE observation SET asset_id='00000000-0000-4000-8000-000000000001'`,
		`UPDATE observation SET subject_type='service'`,
		`UPDATE observation SET number_value='NaN'::float8 WHERE kind='number'`,
		`UPDATE observation SET integer_value=-1 WHERE kind='integer'`,
		`UPDATE observation SET integer_value=NULL WHERE kind='integer'`,
		`UPDATE observation SET number_value=NULL WHERE kind='number'`,
		`UPDATE observation SET unit='percent' WHERE collector_id='linux.memory'`,
		`UPDATE collection_run SET ended_at=NULL WHERE state='completed'`,
		`UPDATE observation SET unit='seconds' WHERE kind='integer'`,
		`INSERT INTO collector_result SELECT * FROM collector_result LIMIT 1`,
		`UPDATE collection_run SET environment_id='00000000-0000-4000-8000-000000000001'`,
	} {
		if _, e := db.pool.Exec(ctx, q); e == nil {
			t.Fatal("SQL boundary accepted", q)
		}
	}
	// Keyset pagination is bounded and excludes the current page deterministically.
	for range 22 {
		r, e := db.BeginCollection(ctx, p, target)
		must(e)
		_ = r
	}
	must(db.RecoverCollections(ctx))
	page, e := db.CollectionHistory(ctx, p, h, "")
	must(e)
	if len(page) != 20 {
		t.Fatal("unbounded page")
	}
	next, e := db.CollectionHistory(ctx, p, h, page[19].ID)
	must(e)
	if len(next) == 0 || len(next) > 20 || next[0].ID == page[19].ID {
		t.Fatal("pagination")
	}
	// Advance maintenance clock beyond both windows: latest valid series and
	// their provenance survive, old samples and empty runs expire in bounded batches.
	must(db.MaintainCollections(ctx, time.Now().Add(40*24*time.Hour), 30, 7))
	facts, e = db.LatestEvidence(ctx, p, h)
	must(e)
	if len(facts) < 15 {
		t.Fatal("retention lost latest")
	}
	history, e = db.CollectionHistory(ctx, p, h, "")
	must(e)
	if len(history) != 2 {
		t.Fatal("retention did not keep only latest provenance", len(history))
	}
}
func TestIntegrationDurableTrustGuard(t *testing.T) {
	db, _, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	token, e := db.BeginSSH(ctx, p, target)
	must(e)
	if token == "" {
		t.Fatal("missing durable guard")
	}
	if db.SSHAllowed(ctx, target, "") == nil {
		t.Fatal("unguarded authority")
	}
	must(db.SSHAllowed(ctx, target, token))
	if _, e = db.BeginSSH(ctx, p, target); e == nil {
		t.Fatal("concurrent guard")
	}
	// Failed trust write leaves the committed pre-contact marker; recovery must
	// invalidate before any restored old key could execute, even repeatedly.
	_, e = db.pool.Exec(ctx, `CREATE FUNCTION fail_trust_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private failure'; END $$; CREATE TRIGGER fail_trust BEFORE UPDATE ON connection_profile FOR EACH ROW EXECUTE FUNCTION fail_trust_test()`)
	must(e)
	if db.RecoverSSH(ctx) == nil {
		t.Fatal("failure injection not effective")
	}
	if db.SSHAllowed(ctx, target, "") == nil {
		t.Fatal("failed recovery allowed execution")
	}
	_, e = db.pool.Exec(ctx, `DROP TRIGGER fail_trust ON connection_profile`)
	must(e)
	must(db.RecoverSSH(ctx))
	must(db.RecoverSSH(ctx))
	r, e := db.Enrollment(ctx, target.EndpointID, target.ProfileID)
	must(e)
	if r.State != "identity_changed" || r.Revision != 2 || r.Details.ApprovedKey != "" || r.Details.LastCategory != "trust_recovery_required" {
		t.Fatal("restart did not revoke", r.State)
	}
	if _, e = db.BeginSSH(ctx, p, target); e == nil {
		t.Fatal("stale guard allowed")
	}
	if _, e = db.BeginSSH(ctx, p, r.Target()); e == nil {
		t.Fatal("unreviewed guard allowed")
	}
}

// Real PostgreSQL rejects a write after SSH-side work has returned. The run
// remains unfinished, no partial evidence commits, and restoration never retries SSH.
func TestIntegrationCollectionWriteFailureRecovery(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	svc := collection.NewService(historyExecutor{}, linux.Registry(), db)
	first, e := svc.Collect(ctx, p, target)
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.pool.Exec(ctx, `CREATE FUNCTION fail_observation_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private SQL failure'; END $$; CREATE TRIGGER fail_observation BEFORE INSERT ON observation FOR EACH ROW EXECUTE FUNCTION fail_observation_test()`)
	if e != nil {
		t.Fatal(e)
	}
	failed, e := svc.Collect(ctx, p, target)
	if e == nil || failed.ID == "" {
		t.Fatal("failed write reported success", e)
	}
	runs, e := db.CollectionHistory(ctx, p, h, "")
	if e != nil || runs[0].State != "running" || len(runs[0].Results) != 0 {
		t.Fatal("write rollback", e, runs)
	}
	_, e = db.pool.Exec(ctx, `DROP TRIGGER fail_observation ON observation`)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.RecoverCollections(ctx); e != nil {
		t.Fatal(e)
	}
	facts, e := db.LatestEvidence(ctx, p, h)
	if e != nil {
		t.Fatal(e)
	}
	for _, o := range facts {
		if o.RunID != first.ID {
			t.Fatal("failure replaced valid evidence")
		}
	}
	runs, e = db.CollectionHistory(ctx, p, h, "")
	if e != nil || runs[0].State != "interrupted" {
		t.Fatal("recovery invented success", e)
	}
	if _, e = svc.Collect(ctx, p, target); e != nil {
		t.Fatal("explicit collection after recovery", e)
	}
}

// Apply the exact accepted NW-009 embedded scripts, then upgrade and reopen.
func TestIntegrationNW009Upgrade(t *testing.T) {
	ctx := context.Background()
	dsn := isolatedDSN(t)
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	_, e = pool.Exec(ctx, `CREATE TABLE schema_migration(version text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP)`)
	if e != nil {
		t.Fatal(e)
	}
	names := []string{}
	// Enumerate instead of guessing historical filenames; previous scripts stay immutable.
	entries, e := migrationFiles.ReadDir("migrations")
	if e != nil {
		t.Fatal(e)
	}
	names = names[:0]
	for _, entry := range entries {
		if entry.Name() < "007" {
			names = append(names, entry.Name())
		}
	}
	if len(names) != 6 {
		t.Fatal("NW-009 baseline migration count")
	}
	for _, name := range names {
		path := "migrations/" + name
		b, e := migrationFiles.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(ctx, string(b)); e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(ctx, `INSERT INTO schema_migration(version,checksum) VALUES($1,$2)`, path, fmt.Sprintf("%x", sha256.Sum256(b))); e != nil {
			t.Fatal(e)
		}
	}
	old := &Store{pool: pool}
	c, e := old.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic upgrade", ShortCode: "UPGRADE", Status: "active"})
	if e != nil {
		t.Fatal(e)
	}
	upgraded, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer upgraded.Close()
	if e = upgraded.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = pool.QueryRow(ctx, `SELECT count(*) FROM schema_migration`).Scan(&count); e != nil || count != 7 {
		t.Fatal("upgrade history", e, count)
	}
	var name string
	if e = pool.QueryRow(ctx, `SELECT display_name FROM customer WHERE id=$1`, c.ID).Scan(&name); e != nil || name != "Synthetic upgrade" {
		t.Fatal("upgrade lost inventory", e)
	}
}

func TestIntegrationManyFilesystemDiagnosticsPreserveEvidence(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	_, e := collection.NewService(historyExecutor{noisy: true}, linux.Registry(), db).Collect(ctx, p, target)
	if e != nil {
		t.Fatal(e)
	}
	runs, e := db.CollectionHistory(ctx, p, h, "")
	if e != nil || len(runs) != 1 || runs[0].State != "partial" || runs[0].SuccessCount != 4 {
		t.Fatal("noisy df discarded successful collectors", e, runs)
	}
	facts, e := db.LatestEvidence(ctx, p, h)
	if e != nil || len(facts) < 15 {
		t.Fatal("lost valid facts", e)
	}
}

func TestIntegrationGuardRecoveryPreservesDisable(t *testing.T) {
	db, _, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	if _, e := db.BeginSSH(ctx, p, target); e != nil {
		t.Fatal(e)
	}
	if _, e := db.pool.Exec(ctx, `UPDATE connection_profile SET state='disabled',revision=revision+1 WHERE id=$1`, target.ProfileID); e != nil {
		t.Fatal(e)
	}
	if e := db.RecoverSSH(ctx); e != nil {
		t.Fatal(e)
	}
	r, e := db.Enrollment(ctx, target.EndpointID, target.ProfileID)
	if e != nil || r.State != "disabled" || r.Details.ApprovedKey != "" {
		t.Fatal("recovery changed disabled authority", e, r.State)
	}
}

func TestIntegrationLongFilesystemMount(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	svc := collection.NewService(historyExecutor{longMount: true}, linux.Registry(), db)
	for range 2 {
		if _, e := svc.Collect(ctx, p, target); e != nil {
			t.Fatal("valid long mount lost run", e)
		}
	}
	facts, e := db.LatestEvidence(ctx, p, h)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, o := range facts {
		if o.CollectorID == "linux.filesystems" {
			count++
			if len(o.Resource) < 4000 {
				t.Fatal("mount truncated")
			}
		}
	}
	if count != 5 {
		t.Fatal("long mount missing or duplicated", count)
	}
	if e = db.MaintainCollections(ctx, time.Now().Add(40*24*time.Hour), 30, 7); e != nil {
		t.Fatal(e)
	}
}
