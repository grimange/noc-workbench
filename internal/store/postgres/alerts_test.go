package postgres

import (
	"context"
	"fmt"
	"noc-workbench/internal/alerts"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/health"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
	"sync"
	"testing"
	"time"
)

func TestIntegrationAlertLifecycleHistory(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	svc := collection.NewService(historyExecutor{}, linux.Registry(), db)
	_, e := svc.Collect(ctx, actor, target)
	must(e)
	p, e := db.SaveEvaluationPolicy(ctx, actor, h, health.Policy{Selector: "linux.mem.available_bytes", TTLSeconds: 180, Rule: "memory_available_low", Threshold: 600000, Enabled: true})
	must(e)
	rule, e := db.SaveAlertRule(ctx, actor, h, alerts.Rule{PolicyID: p.ID, Severity: "warning", DebounceSeconds: 10, Enabled: true})
	must(e)
	at := time.Now().UTC().Add(time.Second)
	must(db.EvaluateAlerts(ctx, h, at))
	v, e := db.AlertView(ctx, actor, h)
	must(e)
	if len(v.Alerts) != 1 || v.Alerts[0].State != "pending" || len(v.Events) != 1 {
		t.Fatal(v)
	}
	must(db.EvaluateAlerts(ctx, h, at.Add(9*time.Second)))
	v, e = db.AlertView(ctx, actor, h)
	must(e)
	if len(v.Events) != 1 {
		t.Fatal("debounce duplicate")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- db.EvaluateAlerts(ctx, h, at.Add(10*time.Second)) })
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		must(e)
	}
	v, e = db.AlertView(ctx, actor, h)
	must(e)
	if len(v.Alerts) != 1 || v.Alerts[0].State != "active" || len(v.Events) != 2 {
		t.Fatal(v)
	}
	must(db.AcknowledgeAlert(ctx, actor, h, v.Alerts[0].ID))
	must(db.AcknowledgeAlert(ctx, actor, h, v.Alerts[0].ID))
	v, e = db.AlertView(ctx, actor, h)
	must(e)
	if len(v.Events) != 3 || v.Alerts[0].AcknowledgedAt == nil {
		t.Fatal(v)
	}
	must(db.EvaluateAlerts(ctx, h, at.Add(181*time.Second)))
	v, e = db.AlertView(ctx, actor, h)
	must(e)
	if v.Alerts[0].State != "active" || v.Alerts[0].EvidenceState != "stale" {
		t.Fatal(v)
	}
	// An explicit revised condition with supported current evidence establishes recovery.
	p.Threshold = 0
	p, e = db.SaveEvaluationPolicy(ctx, actor, h, p)
	must(e)
	must(db.EvaluateAlerts(ctx, h, at.Add(182*time.Second)))
	v, e = db.AlertView(ctx, actor, h)
	must(e)
	if v.Alerts[0].State != "active" {
		t.Fatal("stale revision fabricated recovery")
	}
	// New collection is timestamped independently; use a later evaluation clock
	// after existing deterministic test evaluations to model recovery.
	_, e = db.pool.Exec(ctx, `UPDATE observation SET observed_at=$2,received_at=$2 WHERE asset_id=$1`, h.AssetID, at.Add(183*time.Second))
	must(e)
	must(db.EvaluateAlerts(ctx, h, at.Add(184*time.Second)))
	v, e = db.AlertView(ctx, actor, h)
	must(e)
	if v.Alerts[0].State != "resolved" || v.Alerts[0].ID != v.Events[len(v.Events)-1].Snapshot.ID {
		t.Fatal(v)
	}
	rule.Enabled = false
	_, e = db.SaveAlertRule(ctx, actor, h, rule)
	must(e)
	series, e := db.ObservationSeries(ctx, actor, h, "linux.mem.available_bytes", "", at.Add(-time.Hour), at.Add(time.Hour))
	must(e)
	if len(series.Samples) != 1 || series.Samples[0].Value != "524288" || series.Samples[0].Unit != "bytes" {
		t.Fatal(series)
	}
	alien := h
	alien.EnvironmentID = workspace.OperatorID
	if _, e = db.AlertView(ctx, actor, alien); e == nil {
		t.Fatal("cross scope view")
	}
	if _, e = db.ObservationSeries(ctx, actor, alien, "linux.load.1m", "", at.Add(-time.Hour), at); e == nil {
		t.Fatal("cross scope series")
	}
	if _, e = db.AlertView(ctx, workspace.Principal{ID: "unauthorized"}, h); e == nil {
		t.Fatal("unauthorized")
	}
	if _, e = db.SaveAlertRule(ctx, actor, alien, rule); e == nil {
		t.Fatal("cross scope rule")
	}
	otherCustomer, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic foreign alert", ShortCode: "FOREIGNALERT", Status: "active"})
	must(e)
	otherEnv, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: otherCustomer.ID, Name: "Synthetic foreign scope", Kind: "lab", Status: "active"})
	must(e)
	otherAsset, e := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: otherEnv.ID, Name: "Synthetic foreign alert host", Kind: "server", Lifecycle: "active"})
	must(e)
	// Direct SQL cannot associate a rule or event with another resource scope.
	if _, e = db.pool.Exec(ctx, `INSERT INTO alert_rule(revision,customer_id,environment_id,asset_id,policy_id,policy_revision,severity,debounce_seconds,enabled,actor) VALUES(1,$1,$2,$3,$4,$5,'warning',0,true,$6)`, otherCustomer.ID, h.EnvironmentID, h.AssetID, p.ID, p.Revision, workspace.OperatorID); e == nil {
		t.Fatal("SQL foreign customer rule")
	}
	if _, e = db.pool.Exec(ctx, `INSERT INTO alert_event(alert_id,asset_id,kind,actor,at,snapshot) VALUES($1,$2,'active',$3,now(),'{}')`, v.Alerts[0].ID, otherAsset.ID, workspace.OperatorID); e == nil {
		t.Fatal("SQL foreign asset event")
	}
	if _, e = db.pool.Exec(ctx, `UPDATE alert_rule SET enabled=false`); e == nil {
		t.Fatal("mutable revisions")
	}
	if _, e = db.SaveAlertRule(ctx, actor, h, rule); e == nil {
		t.Fatal("stale revision")
	}
}
func TestIntegrationAlertRollbackAndGaps(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	svc := collection.NewService(historyExecutor{}, linux.Registry(), db)
	_, e := svc.Collect(ctx, actor, target)
	must(e)
	p, e := db.SaveEvaluationPolicy(ctx, actor, h, health.Policy{Selector: "linux.mem.available_bytes", TTLSeconds: 180, Rule: "memory_available_low", Threshold: 600000, Enabled: true})
	must(e)
	_, e = db.SaveAlertRule(ctx, actor, h, alerts.Rule{PolicyID: p.ID, Severity: "warning", Enabled: true})
	must(e)
	_, e = db.pool.Exec(ctx, `CREATE FUNCTION fail_alert_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic event failure'; END $$; CREATE TRIGGER fail_alert_event BEFORE INSERT ON alert_event FOR EACH ROW EXECUTE FUNCTION fail_alert_event()`)
	must(e)
	if e = db.EvaluateAlerts(ctx, h, time.Now().Add(time.Second)); e == nil {
		t.Fatal("expected transaction failure")
	}
	v, e := db.AlertView(ctx, actor, h)
	must(e)
	if len(v.Alerts) != 0 || len(v.Events) != 0 {
		t.Fatal("partial commit")
	}
	_, e = db.pool.Exec(ctx, `DROP TRIGGER fail_alert_event ON alert_event`)
	must(e)
	must(db.EvaluateAlerts(ctx, h, time.Now().Add(time.Second)))
	// Reopening storage preserves the same alert identity, without replay.
	must(db.Migrate(ctx))
	v, e = db.AlertView(ctx, actor, h)
	must(e)
	if len(v.Alerts) != 1 || len(v.Events) != 1 {
		t.Fatal(v)
	}
	_, e = collection.NewService(historyExecutor{failAll: true}, linux.Registry(), db).Collect(ctx, actor, target)
	must(e)
	_, e = svc.Collect(ctx, actor, target)
	must(e)
	series, e := db.ObservationSeries(ctx, actor, h, "linux.load.1m", "", time.Now().Add(-time.Hour), time.Now().Add(time.Second))
	must(e)
	if len(series.Samples) != 2 || !series.Samples[1].Gap {
		t.Fatal("missing outage gap", series)
	}
	scopes, e := db.MonitoringScopes(ctx, actor)
	must(e)
	if len(scopes) != 1 {
		t.Fatal(scopes)
	}
}

func TestIntegrationAlertRetentionDoesNotDeleteReactivated(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e := collection.NewService(historyExecutor{}, linux.Registry(), db).Collect(ctx, actor, target)
	must(e)
	p, e := db.SaveEvaluationPolicy(ctx, actor, h, health.Policy{Selector: "linux.mem.available_bytes", TTLSeconds: 180, Rule: "memory_available_low", Threshold: 600000, Enabled: true})
	must(e)
	_, e = db.SaveAlertRule(ctx, actor, h, alerts.Rule{PolicyID: p.ID, Severity: "critical", Enabled: true})
	must(e)
	must(db.EvaluateAlerts(ctx, h, time.Now().Add(time.Second)))
	old := time.Now().Add(-91 * 24 * time.Hour)
	_, e = db.pool.Exec(ctx, `UPDATE alert_event SET at=$2 WHERE asset_id=$1`, h.AssetID, old)
	must(e)
	must(db.MaintainAlerts(ctx, time.Now()))
	v, e := db.AlertView(ctx, actor, h)
	must(e)
	if len(v.Alerts) != 1 || len(v.Events) != 0 {
		t.Fatal("active identity retention", v)
	}
	_, e = db.pool.Exec(ctx, `UPDATE alert_instance SET state='resolved',updated_at=$2 WHERE asset_id=$1`, h.AssetID, old)
	must(e)
	tx, e := db.pool.Begin(ctx)
	must(e)
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, `UPDATE alert_instance SET state='active',updated_at=clock_timestamp() WHERE asset_id=$1`, h.AssetID)
	must(e)
	// The old resolved version is visible to cleanup until this transaction commits.
	done := make(chan error, 1)
	go func() { done <- db.MaintainAlerts(ctx, time.Now()) }()
	// Prove cleanup reached a lock wait instead of relying on a sleep.
	for {
		var waiting bool
		must(db.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%DELETE FROM alert_instance%')`).Scan(&waiting))
		if waiting {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("cleanup never waited")
		}
	}
	must(tx.Commit(ctx))
	must(<-done)
	var count int
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM alert_instance WHERE asset_id=$1 AND state='active'`, h.AssetID).Scan(&count))
	if count != 1 {
		t.Fatal("cleanup deleted reactivated identity")
	}
	_, e = db.pool.Exec(ctx, `UPDATE alert_instance SET state='resolved',updated_at=$2 WHERE asset_id=$1`, h.AssetID, old)
	must(e)
	must(db.MaintainAlerts(ctx, time.Now()))
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM alert_instance WHERE asset_id=$1`, h.AssetID).Scan(&count))
	if count != 0 {
		t.Fatal("expired resolved identity not removed")
	}
}

func TestIntegrationAlertVisibilityPages(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e := collection.NewService(historyExecutor{}, linux.Registry(), db).Collect(ctx, actor, target)
	must(e)
	p, e := db.SaveEvaluationPolicy(ctx, actor, h, health.Policy{Selector: "linux.mem.available_bytes", TTLSeconds: 180, Rule: "memory_available_low", Threshold: 600000, Enabled: true})
	must(e)
	_, e = db.SaveAlertRule(ctx, actor, h, alerts.Rule{PolicyID: p.ID, Severity: "critical", Enabled: true})
	must(e)
	must(db.EvaluateAlerts(ctx, h, time.Now().UTC().Add(time.Second)))
	// Reproduce 100 newer resolved identities displacing an older active incident.
	_, e = db.pool.Exec(ctx, `INSERT INTO alert_instance(asset_id,rule_id,rule_revision,resource,state,evidence_state,snapshot,evaluated_at,updated_at)
 SELECT asset_id,rule_id,rule_revision,'synthetic-resource-'||n,'resolved','fresh',jsonb_set(jsonb_set(snapshot,'{State}','"resolved"'),'{Resource}',to_jsonb('synthetic-resource-'||n)),evaluated_at,updated_at+interval '1 second' FROM alert_instance CROSS JOIN generate_series(1,100) n WHERE asset_id=$1`, h.AssetID)
	must(e)
	v, e := db.AlertPage(ctx, actor, h, 0)
	must(e)
	if v.Total != 101 || v.Active != 1 || len(v.Alerts) != 100 || v.Alerts[0].State != "active" {
		t.Fatalf("active hidden: %+v", v)
	}
	tail, e := db.AlertPage(ctx, actor, h, 100)
	must(e)
	if len(tail.Alerts) != 1 || tail.Alerts[0].State != "resolved" {
		t.Fatal("missing page")
	}
	summary, e := db.AlertSummary(ctx, actor)
	must(e)
	if summary.Active != 1 || summary.Unacknowledged != 1 || summary.EnabledRules != 1 {
		t.Fatal(summary)
	}
	must(db.AcknowledgeAlert(ctx, actor, h, v.Alerts[0].ID))
	summary, e = db.AlertSummary(ctx, actor)
	must(e)
	if summary.Active != 1 || summary.Unacknowledged != 0 || summary.LatestEvent == 0 {
		t.Fatal(summary)
	}
	for i := range 51 {
		_, e = db.SaveAsset(ctx, inventory.Asset{EnvironmentID: h.EnvironmentID, Name: fmt.Sprintf("AAA synthetic %02d", i), Kind: "server", Lifecycle: "active"})
		must(e)
	}
	first, more, e := db.MonitoringAssetPage(ctx, actor, 0)
	must(e)
	if !more || len(first) != 50 || first[0].AssetID != h.AssetID {
		t.Fatal("active asset omitted")
	}
	next, more, e := db.MonitoringAssetPage(ctx, actor, 50)
	must(e)
	if more || len(next) != 2 {
		t.Fatalf("tail page %d %v", len(next), more)
	}
	if _, _, e = db.MonitoringAssetPage(ctx, workspace.Principal{ID: "unauthorized"}, 0); e == nil {
		t.Fatal("foreign page")
	}
	if _, e = db.AlertSummary(ctx, workspace.Principal{ID: "unauthorized"}); e == nil {
		t.Fatal("foreign summary")
	}
	if _, e = db.AlertPage(ctx, actor, h, -1); e == nil {
		t.Fatal("negative offset")
	}
}
