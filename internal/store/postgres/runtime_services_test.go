package postgres

import (
	"context"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/collectors/services"
	"noc-workbench/internal/health"
	"noc-workbench/internal/integrations/asterisk"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
	"testing"
	"time"
)

type runtimeExecutor struct {
	category sshcli.Category
	state    string
	calls    int
}

func (e *runtimeExecutor) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, _ string) (sshcli.Result, error) {
	e.calls++
	at := time.Now().UTC()
	if e.category != "" {
		return sshcli.Result{StartedAt: at, EndedAt: at, Category: e.category}, &sshcli.Failure{Category: e.category}
	}
	output := "NW_RUNTIME_1\n"
	for _, id := range services.IDs {
		support := "linux"
		unit := "loaded"
		name := map[string]string{"asterisk": "asterisk.service", "database": "mariadb.service", "apache": "apache2.service"}[id]
		active := e.state
		process := "observed"
		if active == "stopped" {
			process = "not_observed"
		}
		if name == "" {
			support = "svn4034"
			unit = "unavailable"
			active = "unavailable"
			name = "unknown"
		}
		output += strings.Join([]string{id, "present", unit, active, process, support, name}, "|") + "\n"
	}
	output += "END\n"
	return sshcli.Result{StartedAt: at, EndedAt: at, Stdout: []byte(output)}, nil
}
func TestIntegrationRuntimeServices(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	exec := &runtimeExecutor{state: "running"}
	registry := linux.Registry().Extend(services.Specs()...)
	svc := collection.NewService(services.Executor{Next: exec, Authority: db}, registry, db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{services.Collector}})
	if _, e := svc.Collect(req, p, target); e == nil || exec.calls != 0 {
		t.Fatal("missing opt-in executed")
	}
	alien := h
	alien.CustomerID = workspace.OperatorID
	if db.SetIntegration(ctx, p, alien, target, "runtime_services", true) == nil {
		t.Fatal("cross-customer")
	}
	profile := scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Collectors: []string{services.Collector}, Interval: 60, Budget: 20, Enabled: true, Authorized: true}
	if _, e := db.SaveSchedule(ctx, p, profile); e == nil {
		t.Fatal("schedule bypassed opt-in")
	}
	must(db.SetIntegration(ctx, p, h, target, "runtime_services", true))
	profile, e := db.SaveSchedule(ctx, p, profile)
	must(e)
	if profile.Interval != 60 || profile.Budget != 20 {
		t.Fatal("default cadence")
	}
	run, e := svc.Collect(req, p, target)
	must(e)
	if run.SuccessCount != 1 {
		t.Fatal(run)
	}
	facts, e := db.LatestEvidence(ctx, p, h)
	must(e)
	if len(facts) != len(services.IDs) {
		t.Fatal("multi service persistence", len(facts))
	}
	for _, ev := range facts {
		s, e := services.Decode(ev)
		must(e)
		if services.Classify(s).Runtime != "Running" || ev.RunID != run.ID || ev.ProfileVersion != target.ProfileVersion {
			t.Fatal("provenance", ev)
		}
	}
	// Bounded dashboard snapshot preserves canonical observations and scope.
	at := time.Now().UTC()
	bulk, records, e := db.ServerEvidence(ctx, workspace.Scope{Customers: []string{h.CustomerID}}, []string{h.AssetID}, at)
	must(e)
	if len(bulk) != 1 || len(records) != 1 || len(bulk[0].Evidence) != 8 || bulk[0].LatestAttempt.ID != run.ID || bulk[0].LastSuccess.ID != run.ID {
		t.Fatalf("bulk provenance: %+v", bulk)
	}
	for _, scope := range []workspace.Scope{{}, {Customers: []string{workspace.OperatorID}}} {
		denied, refs, err := db.ServerEvidence(ctx, scope, []string{h.AssetID}, at)
		must(err)
		if len(denied) != 0 || len(refs) != 0 {
			t.Fatal("bulk scope escape")
		}
	}
	if _, _, err := db.ServerEvidence(ctx, workspace.Scope{All: true}, make([]string, 26), at); err == nil {
		t.Fatal("unbounded page")
	}
	first := facts[0]
	for _, category := range []sshcli.Category{sshcli.ConnectionTimeout, sshcli.ChangedKey, sshcli.AuthenticationFailed, sshcli.PermissionDenied} {
		exec.category = category
		failed, e := svc.Collect(req, p, target)
		must(e)
		if failed.State != "failed" {
			t.Fatal(failed)
		}
		retained, e := db.LatestEvidence(ctx, p, h)
		must(e)
		if retained[0].ID != first.ID || !retained[0].ObservedAt.Equal(first.ObservedAt) {
			t.Fatal("failure erased evidence")
		}
		attempt, e := db.RuntimeAttempt(ctx, p, h)
		must(e)
		bulk, _, e = db.ServerEvidence(ctx, workspace.Scope{All: true}, []string{h.AssetID}, time.Now().UTC())
		must(e)
		if bulk[0].LatestAttempt.ID != failed.ID || bulk[0].LastSuccess.ID != run.ID || !containsEvidenceID(bulk[0].Evidence, first.ID) {
			t.Fatal("bulk failure erased success")
		}
		if attempt.ID != failed.ID || attempt.Category != string(category) {
			t.Fatal("failure hidden", attempt)
		}
	}
	exec.category = ""
	exec.state = "stopped"
	stopped, e := svc.Collect(req, p, target)
	must(e)
	if stopped.State != "completed" {
		t.Fatal(stopped)
	}
	exec.state = "running"
	_, e = svc.Collect(req, p, target)
	must(e)
	// Unrelated Linux samples cannot hide the latest runtime attempt.
	before, e := db.RuntimeAttempt(ctx, p, h)
	must(e)
	_, e = collection.NewService(historyExecutor{}, linux.Registry(), db).Collect(ctx, p, target)
	must(e)
	after, e := db.RuntimeAttempt(ctx, p, h)
	must(e)
	if before.ID != after.ID {
		t.Fatal("unrelated attempt hid runtime")
	}
	in, e := db.EvaluationEvidence(ctx, p, h, time.Now().UTC())
	must(e)
	out, e := health.Evaluate(in)
	must(e)
	count := 0
	for _, r := range out.Readings {
		if r.Evidence.Key == services.Key {
			count++
			if r.Freshness != "fresh" || r.Quality != "valid" || r.Health != "unknown" {
				t.Fatal("four dimensions", r)
			}
		}
	}
	if count != len(services.IDs) {
		t.Fatal(count)
	}
	// An additional pending profile must suppress trust identically on both views.
	var pendingID string
	must(db.pool.QueryRow(ctx, `INSERT INTO connection_profile(customer_id,environment_id,asset_id,endpoint_id,state,details) SELECT customer_id,environment_id,asset_id,endpoint_id,'draft','{}'::jsonb FROM connection_profile WHERE id=$1 RETURNING id::text`, target.ProfileID).Scan(&pendingID))
	bulk, _, e = db.ServerEvidence(ctx, workspace.Scope{All: true}, []string{h.AssetID}, time.Now().UTC())
	must(e)
	detail, e := db.EvaluationEvidence(ctx, p, h, time.Now().UTC())
	must(e)
	if bulk[0].Trusted || detail.Trusted || len(bulk[0].Evidence) != 11 {
		t.Fatal("two-profile trust mismatch")
	}
	_, e = db.pool.Exec(ctx, `DELETE FROM connection_profile WHERE id=$1`, pendingID)
	must(e)
	// Exact TTL expiration uses the supplied evaluator clock, never a sleep.
	in.At = in.At.Add(181 * time.Second)
	out, e = health.Evaluate(in)
	must(e)
	for _, r := range out.Readings {
		if r.Evidence.Key == services.Key && r.Freshness != "stale" {
			t.Fatal("stale runtime")
		}
	}
	if _, e = db.pool.Exec(ctx, `UPDATE observation SET asset_id=$1 WHERE id=$2`, workspace.OperatorID, first.ID); e == nil {
		t.Fatal("foreign observation")
	}
	if _, e = db.pool.Exec(ctx, `UPDATE collection_integration SET customer_id=$1 WHERE profile_id=$2`, workspace.OperatorID, target.ProfileID); e == nil {
		t.Fatal("foreign integration")
	}
	running, e := db.BeginCollection(req, p, target)
	must(e)
	collected, e := registry.Collect(req, exec, p, target, []string{services.Collector})
	must(e)
	collected.ID = running.ID
	collected.PrincipalID = p.ID
	collected.Results[0].Observations[1].AssetID = workspace.OperatorID
	if db.FinishCollection(ctx, p, collected, 180) == nil {
		t.Fatal("invalid subject committed")
	}
	var n int
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM collector_result WHERE run_id=$1`, running.ID).Scan(&n))
	if n != 0 {
		t.Fatal("partial transaction")
	}
	must(db.RecoverCollections(ctx))
	must(db.SetIntegration(ctx, p, h, target, "runtime_services", false))
	snap, e := db.Schedules(ctx, p)
	must(e)
	if snap.Profiles[0].Eligible {
		t.Fatal("revoked schedule eligible")
	}
	calls := exec.calls
	if _, e = svc.Collect(req, p, target); e == nil || exec.calls != calls {
		t.Fatal("revoked collector")
	}
	// Disable remains possible after authority withdrawal.
	profile.Enabled = false
	profile.Authorized = false
	profile, e = db.SaveSchedule(ctx, p, profile)
	must(e)
	dsn := db.pool.Config().ConnString()
	db.Close()
	restored, e := Open(ctx, dsn)
	must(e)
	defer restored.Close()
	must(restored.Migrate(ctx))
	must(restored.Migrate(ctx))
	snap, e = restored.Schedules(ctx, p)
	must(e)
	if snap.Profiles[0].Enabled || snap.Profiles[0].Interval != 60 {
		t.Fatal("restart schedule")
	}
	facts, e = restored.LatestEvidence(ctx, p, h)
	must(e)
	if len(facts) < len(services.IDs)+15 {
		t.Fatal("restart lost history", len(facts))
	}
}

// All ten supported SSH collectors must remain visible in the latest attempt,
// including failed collectors, rather than silently truncating linux.uptime.
func TestIntegrationTenCollectorAttempt(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	for _, name := range []string{"asterisk", "runtime_services"} {
		if e := db.SetIntegration(ctx, p, h, target, name, true); e != nil {
			t.Fatal(e)
		}
	}
	registry := linux.Registry().Extend(asterisk.Specs()...).Extend(services.Specs()...)
	ids := []string{}
	for _, id := range registry.IDs() {
		if id != asterisk.RegistrationCollector && id != "asterisk.activity" {
			ids = append(ids, id)
		}
	}
	if len(ids) != 10 {
		t.Fatal(ids)
	}
	svc := collection.NewService(historyExecutor{failAll: true}, registry, db)
	run, e := svc.Collect(collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: ids}), p, target)
	if e != nil {
		t.Fatal(e)
	}
	in, e := db.EvaluationEvidence(ctx, p, h, time.Now().UTC().Add(time.Second))
	if e != nil || in.LatestAttempt == nil || in.LatestAttempt.ID != run.ID || len(in.LatestAttempt.Results) != 10 {
		t.Fatalf("truncated attempt: %+v %v", in.LatestAttempt, e)
	}
}

func containsEvidenceID(es []collection.Evidence, id string) bool {
	for _, e := range es {
		if e.ID == id {
			return true
		}
	}
	return false
}
