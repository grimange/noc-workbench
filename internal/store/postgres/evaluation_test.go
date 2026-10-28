package postgres

import (
	"context"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/health"
	"noc-workbench/internal/workspace"
	"testing"
	"time"
)

func TestIntegrationEvaluationPolicyAndHistory(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	before := time.Now().UTC()
	svc := collection.NewService(historyExecutor{}, linux.Registry(), db)
	_, e := svc.Collect(ctx, actor, target)
	must(e)
	at := time.Now().UTC().Add(time.Second)
	in, e := db.EvaluationEvidence(ctx, actor, h, at)
	must(e)
	out, e := health.Evaluate(in)
	must(e)
	if len(out.Readings) < 10 || out.Collection != "completed" || out.Health != "unknown" {
		t.Fatal(out)
	}
	for _, r := range out.Readings {
		if r.Freshness != "fresh" || (r.Evidence.CollectorID == "linux.identity" && r.TTLSeconds != 86400) {
			t.Fatal(r)
		}
	}
	old, e := db.EvaluationEvidence(ctx, actor, h, before)
	must(e)
	if len(old.Evidence) != 0 {
		t.Fatal("future observations leaked")
	}
	v := health.Policy{Selector: "linux.mem.available_bytes", TTLSeconds: 60, Rule: "memory_available_low", Threshold: 600000, Enabled: true}
	v, e = db.SaveEvaluationPolicy(ctx, actor, h, v)
	must(e)
	after := time.Now().UTC().Add(time.Second)
	in, e = db.EvaluationEvidence(ctx, actor, h, after)
	must(e)
	out, e = health.Evaluate(in)
	must(e)
	found := false
	for _, r := range out.Readings {
		if r.Evidence.Key == v.Selector {
			found = true
			if r.Health != "degraded" || r.PolicyRevision != 1 || r.PolicyID != v.ID {
				t.Fatal(r)
			}
		}
	}
	if !found {
		t.Fatal("missing memory")
	}
	old, e = db.EvaluationEvidence(ctx, actor, h, v.CreatedAt.Add(-time.Microsecond))
	must(e)
	for _, p := range old.Policies {
		if p.ID == v.ID {
			t.Fatal("future policy leaked")
		}
	}
	v.TTLSeconds = 300
	v, e = db.SaveEvaluationPolicy(ctx, actor, h, v)
	must(e)
	if v.Revision != 2 {
		t.Fatal(v)
	}
	stale := v
	stale.Revision = 0
	if _, e = db.SaveEvaluationPolicy(ctx, actor, h, stale); e == nil {
		t.Fatal("lost update")
	}
	if _, e = db.EvaluationEvidence(ctx, workspace.Principal{ID: "other"}, h, after); e == nil {
		t.Fatal("unauthorized evidence")
	}
	alien := h
	alien.EnvironmentID = workspace.OperatorID
	if _, e = db.EvaluationEvidence(ctx, actor, alien, after); e == nil {
		t.Fatal("cross environment read")
	}
	if _, e = db.SaveEvaluationPolicy(ctx, actor, alien, v); e == nil {
		t.Fatal("cross environment write")
	}
	if _, e = db.pool.Exec(ctx, `INSERT INTO evaluation_policy(customer_id,environment_id,asset_id,revision,selector,version,ttl_seconds,rule,actor) VALUES($1,$2,$3,3,'linux.memory','linux-evidence.v1',180,'none',$1)`, workspace.OperatorID, h.EnvironmentID, h.AssetID); e == nil {
		t.Fatal("direct SQL scope bypass")
	}
	for _, q := range []string{`UPDATE evaluation_policy SET ttl_seconds=999 WHERE asset_id=$1`, `INSERT INTO evaluation_policy(id,revision,customer_id,environment_id,asset_id,selector,version,ttl_seconds,rule,threshold,actor) SELECT id,revision+1,customer_id,environment_id,asset_id,selector,version,0,rule,threshold,actor FROM evaluation_policy WHERE asset_id=$1`, `INSERT INTO evaluation_policy(id,revision,customer_id,environment_id,asset_id,selector,version,ttl_seconds,rule,threshold,actor) SELECT id,revision+1,customer_id,environment_id,asset_id,selector,version,180,'memory_available_low','NaN',actor FROM evaluation_policy WHERE asset_id=$1`} {
		if _, e = db.pool.Exec(ctx, q, h.AssetID); e == nil {
			t.Fatal("invalid direct SQL policy accepted")
		}
	}
	// Simulate stale time without sleeps or new collection; failure cannot refresh evidence.
	failed := collection.NewService(historyExecutor{failAll: true}, linux.Registry(), db)
	_, e = failed.Collect(ctx, actor, target)
	must(e)
	in, e = db.EvaluationEvidence(ctx, actor, h, time.Now().UTC().Add(time.Hour))
	must(e)
	out, e = health.Evaluate(in)
	must(e)
	if out.Collection != "failed" || out.LastSuccess == nil || len(out.Readings) == 0 {
		t.Fatal(out)
	}
	for _, r := range out.Readings {
		if r.Evidence.CollectorID != "linux.identity" && r.Freshness != "stale" || r.Health != "unknown" {
			t.Fatal(r)
		}
	}
	// Restart repository and migration startup preserve revision/evidence.
	reopened, e := Open(ctx, db.pool.Config().ConnString())
	must(e)
	defer reopened.Close()
	again, e := reopened.EvaluationEvidence(ctx, actor, h, in.At)
	must(e)
	if len(again.Evidence) != len(in.Evidence) {
		t.Fatal("restart lost history")
	}
}

func TestIntegrationEvaluationRollbackAndUnavailable(t *testing.T) {
	db, h, _ := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	// Deliberate failure inside the policy transaction must not create a revision.
	_, e := db.pool.Exec(ctx, `CREATE FUNCTION evaluation_test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.asset_id IS NOT NULL THEN RAISE EXCEPTION 'synthetic private database detail'; END IF; RETURN NEW; END; $$;CREATE TRIGGER evaluation_test_failure BEFORE INSERT ON evaluation_policy FOR EACH ROW EXECUTE FUNCTION evaluation_test_failure()`)
	if e != nil {
		t.Fatal(e)
	}
	v := health.Policy{Selector: "linux.memory", TTLSeconds: 180, Rule: "none", Enabled: true}
	invalid := v
	invalid.Version = "unsupported.v999"
	if _, e = db.SaveEvaluationPolicy(ctx, actor, h, invalid); e != health.ErrPolicy {
		t.Fatal("unsupported version accepted", e)
	}
	if _, e = db.SaveEvaluationPolicy(ctx, actor, h, v); e != ErrUnavailable {
		t.Fatal("write failure", e)
	}
	var count int
	if e = db.pool.QueryRow(ctx, `SELECT count(*) FROM evaluation_policy WHERE asset_id=$1`, h.AssetID).Scan(&count); e != nil || count != 0 {
		t.Fatal("partial policy committed", count, e)
	}
	_, e = db.pool.Exec(ctx, `DROP TRIGGER evaluation_test_failure ON evaluation_policy;DROP FUNCTION evaluation_test_failure()`)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.SaveEvaluationPolicy(ctx, actor, h, v); e != nil {
		t.Fatal("write recovery", e)
	}
	dsn := db.pool.Config().ConnString()
	db.Close()
	if _, e = db.EvaluationEvidence(ctx, actor, h, time.Now().UTC()); e != ErrUnavailable {
		t.Fatal("closed database read", e)
	}
	if _, e = db.SaveEvaluationPolicy(ctx, actor, h, v); e != ErrUnavailable {
		t.Fatal("closed database write", e)
	}
	restored, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	in, e := restored.EvaluationEvidence(ctx, actor, h, time.Now().UTC())
	if e != nil || len(in.Policies) != 13 {
		t.Fatal("repository recovery", in, e)
	}
}
