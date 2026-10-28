package postgres

import (
	"context"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/baseline"
	"noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/health"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"testing"
	"time"
)

type baselineExec struct{ calls int }

func (x *baselineExec) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, _ string) (sshcli.Result, error) {
	x.calls++
	at := time.Now().UTC()
	return sshcli.Result{StartedAt: at, EndedAt: at, Stdout: []byte("NW_BASELINE_1\ncpu|25\nprocess|42|asterisk|10|1024\nprocess_status|sampled_up_to_4096\npage_bytes|4096\nswap_total|1024\nswap_free|512\npressure|1\nunit|oneshot.service|loaded|active|exited\nunits_status|observed\nfiles_status|unavailable\ntimers_status|unavailable\nEND\n")}, nil
}
func TestIntegrationBaselineAutomatic(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	exec := &baselineExec{}
	svc := collection.NewService(baseline.Executor{Next: exec, Authority: db}, linux.Registry().Extend(baseline.Specs()...), db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{baseline.Collector}})
	if _, e := svc.Collect(req, p, target); e == nil || exec.calls != 0 {
		t.Fatal("legacy authority expanded")
	}
	snap, e := db.Schedules(ctx, p)
	must(e)
	if len(snap.Profiles) != 0 {
		t.Fatal("legacy scheduled")
	}
	rec, e := db.Enrollment(ctx, target.EndpointID, target.ProfileID)
	must(e)
	// Enrollment verification and baseline authority share one transaction. A
	// deliberately invalid audit action rolls all grant/schedule writes back.
	rec.Details.BaselineAuthorized = true
	tx, e := db.pool.Begin(ctx)
	must(e)
	must(authorizeBaseline(ctx, tx, p, rec))
	_, e = commitEnrollment(ctx, tx, p, rec, "invalid")
	if e == nil {
		t.Fatal("audit accepted")
	}
	tx.Rollback(ctx)
	if db.IntegrationAllowed(ctx, p, target, "baseline") == nil {
		t.Fatal("grant survived rollback")
	}
	snap, e = db.Schedules(ctx, p)
	must(e)
	if len(snap.Profiles) != 0 {
		t.Fatal("schedule survived rollback")
	}
	rec, e = db.SaveEnrollment(ctx, p, rec, rec.Revision, "baseline")
	must(e)
	target = rec.Target()
	snap, e = db.Schedules(ctx, p)
	must(e)
	if len(snap.Profiles) != 1 || snap.Profiles[0].Interval != 60 || !snap.Profiles[0].Enabled || !snap.Profiles[0].Eligible || len(snap.Profiles[0].Collectors) != 7 {
		t.Fatalf("automatic schedule %+v", snap)
	}
	must(db.IntegrationAllowed(ctx, p, target, "baseline"))
	if db.IntegrationAllowed(ctx, workspace.Principal{}, target, "baseline") == nil {
		t.Fatal("anonymous authority")
	}
	// An in-flight command lock denies admission, not presentation authority.
	token, e := db.BeginSSH(ctx, p, target)
	must(e)
	snap, e = db.Schedules(ctx, p)
	must(e)
	if snap.Profiles[0].Eligible || !snap.Profiles[0].EvidenceEligible {
		t.Fatal("execution lock changed authority", snap)
	}
	scope := workspace.Scope{Customers: []string{h.CustomerID}, Environments: []string{h.EnvironmentID}}
	inputs, records, e := db.ServerEvidence(ctx, scope, []string{h.AssetID}, time.Now().UTC())
	must(e)
	if len(inputs) != 1 || !inputs[0].Trusted || len(records) != 1 {
		t.Fatal("in-flight evidence authority lost", inputs, records)
	}
	must(db.EndSSH(ctx, target.ProfileID, token))

	run, e := svc.Collect(req, p, target)
	must(e)
	if run.SuccessCount != 1 {
		t.Fatal(run)
	}
	facts, e := db.LatestEvidence(ctx, p, h)
	must(e)
	if len(facts) != 54 {
		t.Fatal("facts", len(facts))
	}
	for _, f := range facts {
		if f.RunID != run.ID || f.CollectorVersion != "1" || f.ProfileVersion != target.ProfileVersion {
			t.Fatal("provenance")
		}
	}
	// Reopen the repository, including idempotent migration startup, rather than
	// checking only the original in-memory service instance.
	restarted, e := Open(ctx, db.pool.Config().ConnString())
	must(e)
	defer restarted.Close()
	must(restarted.Migrate(ctx))
	must(restarted.RecoverSchedules(ctx, time.Now().UTC()))
	persisted, e := restarted.LatestEvidence(ctx, p, h)
	must(e)
	if len(persisted) != len(facts) || persisted[0].RunID != run.ID {
		t.Fatal("restart lost original evidence")
	}
	snap, e = restarted.Schedules(ctx, p)
	must(e)
	if len(snap.Profiles) != 1 || !snap.Profiles[0].Eligible || snap.Profiles[0].Interval != 60 {
		t.Fatal("restart lost automatic monitoring authority")
	}
	must(db.RecoverSchedules(ctx, time.Now().UTC()))
	snap, e = db.Schedules(ctx, p)
	must(e)
	if !snap.Profiles[0].Enabled || snap.Profiles[0].Target != target {
		t.Fatal("restart lost configuration")
	}
	// Controls suspend dispatch without erasing baseline authority or history.
	must(db.SetScheduleControl(ctx, p, scheduler.Control{Kind: "asset", ID: h.AssetID, Paused: true}, time.Now().UTC()))
	snap, e = db.Schedules(ctx, p)
	must(e)
	if !snap.Profiles[0].Paused {
		t.Fatal("pause")
	}
	must(db.SetScheduleControl(ctx, p, scheduler.Control{Kind: "asset", ID: h.AssetID, Paused: false}, time.Now().UTC()))
	snap, e = db.Schedules(ctx, p)
	must(e)
	if snap.Profiles[0].Paused {
		t.Fatal("resume")
	}
	alien := target
	alien.AssetID = workspace.OperatorID
	if db.IntegrationAllowed(ctx, p, alien, "baseline") == nil {
		t.Fatal("cross asset")
	}
	// The actual quarantine state retains its diagnostic without any execution authority.
	rec.State = "identity_changed"
	rec.Details.LastCategory = "host_key_mismatch"
	rec.Details.ApprovedKey = ""
	_, e = db.SaveEnrollment(ctx, p, rec, rec.Revision, "verify")
	must(e)
	inputs, records, e = db.ServerEvidence(ctx, scope, []string{h.AssetID}, time.Now().UTC())
	must(e)
	if len(inputs) != 1 || inputs[0].Trusted || len(records) != 0 || inputs[0].AuthorizationDiagnostic != "SSH host-key trust problem" {
		t.Fatal("quarantine projection", inputs, records)
	}
	denied, hidden, e := db.ServerEvidence(ctx, workspace.Scope{}, []string{h.AssetID}, time.Now().UTC())
	must(e)
	if len(denied) != 0 || len(hidden) != 0 {
		t.Fatal("unscoped diagnostics leaked")
	}

}

func TestIntegrationBaselinePreservesApprovedCollectors(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk", true))
	// Existing choices represent already authorized, capability-verified collectors.
	_, e := db.pool.Exec(ctx, `INSERT INTO collection_schedule(customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,endpoint_revision,principal_id,collector_ids,interval_seconds,budget_seconds,enabled,authorized,next_due) SELECT customer_id,environment_id,asset_id,endpoint_id,id,revision,(details->>'EndpointUpdatedAt')::timestamptz,$2,ARRAY['asterisk.identity'],60,20,true,true,clock_timestamp() FROM connection_profile WHERE id=$1`, target.ProfileID, p.ID)
	must(e)
	r, e := db.Enrollment(ctx, target.EndpointID, target.ProfileID)
	must(e)
	r.Details.BaselineAuthorized = true
	r, e = db.SaveEnrollment(ctx, p, r, r.Revision, "baseline")
	must(e)
	must(db.IntegrationAllowed(ctx, p, r.Target(), "asterisk"))
	snap, e := db.Schedules(ctx, p)
	must(e)
	if len(snap.Profiles) != 1 || len(snap.Profiles[0].Collectors) != 8 || !snap.Profiles[0].Eligible {
		t.Fatal(snap)
	}
	// The existing ten-collector cap is deliberate: reject overflow atomically,
	// rather than silently discarding previously authorized optional collectors.
	_, e = db.pool.Exec(ctx, `UPDATE collection_schedule SET collector_ids=ARRAY['linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems','linux.services','asterisk.identity','asterisk.channels','asterisk.modules','asterisk.pjsip'] WHERE asset_id=$1`, h.AssetID)
	must(e)
	prior := r.Revision
	if _, e = db.SaveEnrollment(ctx, p, r, r.Revision, "baseline"); e == nil {
		t.Fatal("eleven collector schedule accepted")
	}
	r, e = db.Enrollment(ctx, target.EndpointID, target.ProfileID)
	must(e)
	if r.Revision != prior {
		t.Fatal("failed grant mutated enrollment")
	}
}
func TestIntegrationBaselineDashboardPolicyParity(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	r, e := db.Enrollment(ctx, target.EndpointID, target.ProfileID)
	must(e)
	r.Details.BaselineAuthorized = true
	r, e = db.SaveEnrollment(ctx, p, r, r.Revision, "baseline")
	must(e)
	target = r.Target()
	svc := collection.NewService(baseline.Executor{Next: &baselineExec{}, Authority: db}, linux.Registry().Extend(baseline.Specs()...), db)
	_, e = svc.Collect(collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{baseline.Collector}}), p, target)
	must(e)
	_, e = collection.NewService(historyExecutor{rootMount: true}, linux.Registry(), db).Collect(ctx, p, target)
	must(e)
	for _, key := range []string{"linux.baseline.status", "linux.baseline.cpu_percent", "linux.mem.available_bytes", "linux.mem.total_bytes", "linux.baseline.units", "linux.filesystem.total_bytes", "linux.filesystem.used_bytes", "linux.filesystem.available_bytes", "linux.filesystem.utilization_percent"} {
		_, e = db.SaveEvaluationPolicy(ctx, p, h, health.Policy{Selector: key, TTLSeconds: 1, Rule: "none", Enabled: true})
		must(e)
	}
	at := time.Now().UTC().Add(2 * time.Second)
	bulk, _, e := db.ServerEvidence(ctx, workspace.Scope{All: true}, []string{h.AssetID}, at)
	must(e)
	detail, e := db.EvaluationEvidence(ctx, p, h, at)
	must(e)
	b, e := health.Evaluate(bulk[0])
	must(e)
	d, e := health.Evaluate(detail)
	must(e)
	for _, key := range []string{"linux.baseline.status", "linux.baseline.cpu_percent", "linux.mem.available_bytes", "linux.mem.total_bytes", "linux.baseline.units", "linux.filesystem.total_bytes", "linux.filesystem.used_bytes", "linux.filesystem.available_bytes", "linux.filesystem.utilization_percent"} {
		found := 0
		for _, out := range []health.Evaluation{b, d} {
			for _, reading := range out.Readings {
				if reading.Evidence.Key == key {
					found++
					if reading.Freshness != "stale" {
						t.Fatal("policy mismatch", key, reading)
					}
				}
			}
		}
		expected := 2
		if key == "linux.baseline.units" {
			expected = 64
		}
		if found != expected {
			t.Fatal("missing selected evidence", key, found)
		}
	}
}
