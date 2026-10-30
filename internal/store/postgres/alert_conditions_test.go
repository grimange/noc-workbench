package postgres

import (
	"context"
	"noc-workbench/internal/alerts"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/collectors/services"
	"noc-workbench/internal/health"
	auth "noc-workbench/internal/integrations/asteriskauth"
	"noc-workbench/internal/integrations/mariadb"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
	"testing"
	"time"
)

func TestIntegrationOperationalAlertPoliciesAndContinuity(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	s, err := db.SaveSchedule(ctx, actor, scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Collectors: []string{"linux.uptime"}, Enabled: true, Authorized: true, Interval: 60, Budget: 20})
	must(err)
	var expected bool
	must(db.pool.QueryRow(ctx, `SELECT monitoring_expected FROM collection_schedule WHERE id=$1`, s.ID).Scan(&expected))
	if !expected {
		t.Fatal("intent not recorded")
	}
	for _, key := range []string{"monitoring.continuity", "server.ssh_unreachable", "service.runtime.unavailable", "service.ami.disconnected", "service.authentication.repeated", "database.query.failed", "database.replication.failed", "database.replication.lag_seconds"} {
		rule := "condition_failed"
		threshold := float64(0)
		if key == "monitoring.continuity" {
			rule = "monitoring_interrupted"
			threshold = 180
		}
		if key == "database.replication.lag_seconds" {
			rule = "value_high"
			threshold = 30
		}
		p, err := db.SaveEvaluationPolicy(ctx, actor, h, health.Policy{Selector: key, Rule: rule, Threshold: threshold, TTLSeconds: 180, Enabled: true})
		must(err)
		_, err = db.SaveAlertRule(ctx, actor, h, alerts.Rule{PolicyID: p.ID, Severity: "warning", DebounceSeconds: 0, Enabled: true})
		must(err)
	}
	// Automatic disablement preserves intended monitoring; no collection dispatch
	// is needed to detect it. The independent evaluator uses persisted controls.
	_, err = db.pool.Exec(ctx, `UPDATE collection_schedule SET enabled=false,state='disabled' WHERE id=$1`, s.ID)
	must(err)
	at := time.Now().UTC().Add(181 * time.Second)
	must(db.EvaluateAlerts(ctx, h, at))
	v, err := db.AlertView(ctx, actor, h)
	must(err)
	if len(v.Alerts) != 1 || v.Alerts[0].State != "active" || v.Alerts[0].Reading.Evidence.Key != "monitoring.continuity" {
		t.Fatalf("continuity: %+v", v)
	}
	id := v.Alerts[0].ID
	must(db.AcknowledgeAlert(ctx, actor, h, id))
	must(db.EvaluateAlerts(ctx, h, at.Add(time.Second)))
	v, err = db.AlertView(ctx, actor, h)
	must(err)
	if len(v.Alerts) != 1 || v.Alerts[0].ID != id || v.Alerts[0].AcknowledgedAt == nil {
		t.Fatal("dedup/ack", v)
	}
	// A pause is uncertainty, never recovered evidence.
	_, err = db.pool.Exec(ctx, `UPDATE collection_schedule SET paused=true WHERE id=$1`, s.ID)
	must(err)
	must(db.EvaluateAlerts(ctx, h, at.Add(2*time.Second)))
	v, err = db.AlertView(ctx, actor, h)
	must(err)
	if v.Alerts[0].State != "active" {
		t.Fatal("pause resolved incident")
	}
	// An operator explicitly withdrawing the schedule clears expectation but does
	// not manufacture healthy evidence or erase the incident.
	s.Enabled = false
	s.Authorized = false
	s.Paused = false
	_, err = db.SaveSchedule(ctx, actor, s)
	must(err)
	must(db.pool.QueryRow(ctx, `SELECT monitoring_expected FROM collection_schedule WHERE id=$1`, s.ID).Scan(&expected))
	if expected {
		t.Fatal("explicit withdrawal kept expectation")
	}
	alien := h
	alien.CustomerID = workspace.OperatorID
	if err = db.EvaluateAlerts(ctx, alien, at.Add(3*time.Second)); err == nil {
		t.Fatal("cross customer evaluation")
	}
}
func TestReplicationFailureSemantics(t *testing.T) {
	for _, tt := range []struct {
		c    mariadb.Channel
		want string
	}{
		{mariadb.Channel{IO: "Yes", SQL: "Yes"}, "healthy"},
		{mariadb.Channel{IO: "No", SQL: "Yes"}, "degraded"},
		{mariadb.Channel{IO: "Yes", SQL: "No"}, "degraded"},
		{mariadb.Channel{IO: "Connecting", SQL: "Yes"}, "degraded"},
		{mariadb.Channel{IO: "Yes", SQL: "Yes", IOError: 123}, "degraded"},
		{mariadb.Channel{IO: "Yes", SQL: "Unknown"}, "unknown"},
	} {
		got, _ := replicationCondition(tt.c)
		if got != tt.want {
			t.Fatal(tt, got)
		}
	}
}
func TestReachabilityCorroborationFreshness(t *testing.T) {
	at := time.Now().UTC()
	p := []health.Policy{{Selector: "server.ssh_unreachable", TTLSeconds: 180, Enabled: true}}
	if !corroborationFresh(at.Add(-179*time.Second), p, at) || corroborationFresh(at.Add(-180*time.Second), p, at) || corroborationFresh(at.Add(time.Second), p, at) {
		t.Fatal("corroboration freshness")
	}
	_ = collection.Run{}
}

func TestIntegrationDatabaseOperationalAlertRecovery(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(db.SetIntegration(ctx, actor, h, target, "mariadb", true))
	_, err := db.SaveSchedule(ctx, actor, scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Collectors: []string{"mariadb.health"}, Enabled: true, Authorized: true, Interval: 60, Budget: 20})
	must(err)
	for _, key := range []string{"database.query.failed", "database.replication.failed", "database.replication.lag_seconds"} {
		rule := "condition_failed"
		threshold := float64(0)
		if key == "database.replication.lag_seconds" {
			rule = "value_high"
			threshold = 30
		}
		p, err := db.SaveEvaluationPolicy(ctx, actor, h, health.Policy{Selector: key, Rule: rule, Threshold: threshold, TTLSeconds: 180, Enabled: true})
		must(err)
		_, err = db.SaveAlertRule(ctx, actor, h, alerts.Rule{PolicyID: p.ID, Severity: "warning", Enabled: true})
		must(err)
	}
	port, lag := uint64(3306), uint64(35)
	x := &mariaDBExecutor{snapshot: mariadb.Snapshot{Protocol: 1, Status: "ready", Version: "10.11.15-MariaDB-log", Identity: "database.example.invalid", ServerID: 1, LatencyMS: 2, Metrics: map[string]uint64{"Threads_connected": 2, "Threads_running": 1, "Max_used_connections": 4, "Connections": 10, "Aborted_connects": 0, "Uptime": 100, "max_connections": 200}, ActivityStatus: "ready", Replication: "ready", Channels: []mariadb.Channel{{Name: "east", Source: "192.0.2.4", Port: &port, IO: "No", SQL: "Yes", Lag: &lag}, {Name: "west", Source: "192.0.2.5", Port: &port, IO: "Yes", SQL: "Yes"}}}}
	svc := collection.NewService(x, linux.Registry().Extend(mariadb.Specs()...), db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{mariadb.Collector}})
	collect := func() { t.Helper(); _, err := svc.Collect(req, actor, target); must(err) }
	evaluate := func() alerts.View {
		t.Helper()
		must(db.EvaluateAlerts(ctx, h, time.Now().UTC()))
		v, err := db.AlertView(ctx, actor, h)
		must(err)
		return v
	}
	collect()
	v := evaluate()
	if v.Active != 2 {
		t.Fatalf("one failed channel plus lag, healthy/NULL channel: %+v", v)
	}
	// A complete current empty replica snapshot resolves removed channel conditions,
	// but creates no zero-lag measurement or claim that this host is primary.
	x.snapshot.Channels = nil
	collect()
	v = evaluate()
	if v.Active != 0 || len(v.Alerts) != 2 {
		t.Fatalf("complete empty recovery: %+v", v)
	}
	x.snapshot = mariadb.Snapshot{Protocol: 1, Status: "authentication_denied", ActivityStatus: "unknown", Replication: "unknown"}
	collect()
	v = evaluate()
	if v.Active != 1 {
		t.Fatalf("query failure: %+v", v)
	}
	// An SSH timeout does not overwrite DB readiness with another fabricated
	// failure or resolve the active incident.
	x.failed = true
	collect()
	v = evaluate()
	if v.Active != 1 {
		t.Fatal("transport failure resolved readiness", v)
	}
}

func TestIntegrationRuntimeAndAMIAlertLifecycle(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"runtime_services", "asterisk"} {
		must(db.SetIntegration(ctx, actor, h, target, name, true))
	}
	_, err := db.SaveSchedule(ctx, actor, scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Collectors: []string{services.Collector}, Enabled: true, Authorized: true, Interval: 60, Budget: 20})
	must(err)
	for _, key := range []string{"service.runtime.unavailable", "service.ami.disconnected"} {
		p, err := db.SaveEvaluationPolicy(ctx, actor, h, health.Policy{Selector: key, Rule: "condition_failed", TTLSeconds: 180, Enabled: true})
		must(err)
		_, err = db.SaveAlertRule(ctx, actor, h, alerts.Rule{PolicyID: p.ID, Severity: "warning", Enabled: true})
		must(err)
	}
	must(db.SetAMIGrant(ctx, actor, h, target, "synthetic", strings.Repeat("a", 64), true))
	bindings, err := db.AMIBindings(ctx, actor)
	must(err)
	b := bindings[0]
	x := &runtimeExecutor{state: "stopped"}
	svc := collection.NewService(services.Executor{Next: x, Authority: db}, linux.Registry().Extend(services.Specs()...), db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{services.Collector}})
	collect := func() { t.Helper(); _, err := svc.Collect(req, actor, target); must(err) }
	evaluate := func() alerts.View {
		t.Helper()
		must(db.EvaluateAlerts(ctx, h, time.Now().UTC()))
		v, err := db.AlertView(ctx, actor, h)
		must(err)
		return v
	}
	collect()
	v := evaluate()
	if v.Active != 2 {
		t.Fatalf("stopped runtime and absent expected session: %+v", v)
	}
	for _, a := range v.Alerts {
		must(db.AcknowledgeAlert(ctx, actor, h, a.ID))
	}
	again := evaluate()
	if again.Total != 2 || again.Active != 2 {
		t.Fatal("duplicate incidents", again)
	}
	// An inactive unit with an independently observed process remains Running.
	x.state = "running"
	collect()
	id, err := db.BeginAMISession(ctx, b, time.Now().UTC())
	must(err)
	must(db.AMITransition(ctx, b, id, "connected", "", time.Now().UTC(), 0, false))
	v = evaluate()
	if v.Active != 0 || v.Total != 2 {
		t.Fatal("actual recovery", v)
	}
	must(db.AMITransition(ctx, b, id, "disconnected", "transport_disconnected", time.Now().UTC(), 0, true))
	v = evaluate()
	if v.Active != 1 {
		t.Fatal("recurrence", v)
	}
	must(db.SetScheduleControl(ctx, actor, scheduler.Control{Kind: "asset", ID: h.AssetID, Paused: true}, time.Now().UTC()))
	v = evaluate()
	if v.Active != 1 {
		t.Fatal("pause fabricated recovery", v)
	}
	reopened, err := Open(ctx, db.pool.Config().ConnString())
	must(err)
	defer reopened.Close()
	v, err = reopened.AlertView(ctx, actor, h)
	must(err)
	if v.Active != 1 {
		t.Fatal("restart lost incident")
	}
}

func TestIntegrationAuthenticationAlertWindowAndRecovery(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"asterisk", "asterisk_auth"} {
		must(db.SetIntegration(ctx, actor, h, target, name, true))
	}
	_, err := db.SaveSchedule(ctx, actor, scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Collectors: []string{auth.Collector}, Enabled: true, Authorized: true, Interval: 60, Budget: 20})
	must(err)
	p, err := db.SaveEvaluationPolicy(ctx, actor, h, health.Policy{Selector: "service.authentication.repeated", Rule: "condition_failed", TTLSeconds: 180, Enabled: true})
	must(err)
	_, err = db.SaveAlertRule(ctx, actor, h, alerts.Rule{PolicyID: p.ID, Severity: "warning", Enabled: true})
	must(err)
	now := time.Now().UTC().Truncate(time.Microsecond)
	x := &authBatchExecutor{batch: auth.Batch{Source: "security", Status: "current", Security: true, InspectedAt: now, After: auth.Cursor{Identity: "1:2", Generation: 1, Offset: 10000, Anchor: strings.Repeat("a", 64)}, Bytes: 10000}}
	for i := range 5 {
		x.batch.Events = append(x.batch.Events, auth.Event{Position: int64(i * 100), At: now.Add(-time.Minute), Type: "InvalidPassword", Account: "1001", IP: "192.0.2.1", Technology: "SIP", Severity: "authentication_failure", Reason: "InvalidPassword"})
	}
	svc := collection.NewService(x, linux.Registry().Extend(auth.Specs()...), db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{auth.Collector}})
	_, err = svc.Collect(req, actor, target)
	must(err)
	evaluate := func(at time.Time) alerts.View {
		t.Helper()
		must(db.EvaluateAlerts(ctx, h, at))
		v, err := db.AlertView(ctx, actor, h)
		must(err)
		return v
	}
	v := evaluate(time.Now().UTC())
	if v.Active != 1 || v.Alerts[0].Reading.Evidence.Value.Integer != 5 {
		t.Fatalf("repeated failure %+v", v)
	}
	id := v.Alerts[0].ID
	must(db.AcknowledgeAlert(ctx, actor, h, id))
	v = evaluate(time.Now().UTC())
	if len(v.Alerts) != 1 || v.Alerts[0].AcknowledgedAt == nil {
		t.Fatal("dedup/ack", v)
	}
	v = evaluate(now.Add(4 * time.Minute))
	if v.Active != 1 {
		t.Fatal("missing current coverage resolved", v)
	}
	// Isolated fixture advances source occurrence times out of the window, then
	// supplies a complete new source inspection; no live log or history is touched.
	_, err = db.pool.Exec(ctx, `UPDATE asterisk_auth_event SET event_at=event_at-interval '6 minutes' WHERE asset_id=$1`, h.AssetID)
	must(err)
	x.batch.Before = x.batch.After
	x.batch.After.Offset += 100
	x.batch.Bytes = 100
	x.batch.Events = nil
	x.batch.InspectedAt = now.Add(5 * time.Minute)
	_, err = svc.Collect(req, actor, target)
	must(err)
	v = evaluate(now.Add(5*time.Minute + time.Second))
	if v.Active != 0 || len(v.Alerts) != 1 {
		t.Fatal("complete window recovery", v)
	}
}

type reachabilityAlertExecutor struct{ category sshcli.Category }

func (x *reachabilityAlertExecutor) Execute(ctx context.Context, p workspace.Principal, target sshcli.Target, id string) (sshcli.Result, error) {
	if x.category != "" {
		at := time.Now().UTC()
		return sshcli.Result{StartedAt: at, EndedAt: at}, &sshcli.Failure{Category: x.category}
	}
	return (historyExecutor{}).Execute(ctx, p, target, id)
}
func TestIntegrationReachabilityAlertRecoveryAndExclusions(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := db.SaveSchedule(ctx, actor, scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Collectors: []string{"linux.uptime"}, Enabled: true, Authorized: true, Interval: 60, Budget: 20})
	must(err)
	p, err := db.SaveEvaluationPolicy(ctx, actor, h, health.Policy{Selector: "server.ssh_unreachable", Rule: "condition_failed", TTLSeconds: 180, Enabled: true})
	must(err)
	_, err = db.SaveAlertRule(ctx, actor, h, alerts.Rule{PolicyID: p.ID, Severity: "warning", Enabled: true})
	must(err)
	x := &reachabilityAlertExecutor{}
	svc := collection.NewService(x, linux.Registry(), db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{"linux.uptime"}})
	collect := func() { t.Helper(); _, err := svc.Collect(req, actor, target); must(err) }
	evaluate := func() alerts.View {
		t.Helper()
		must(db.EvaluateAlerts(ctx, h, time.Now().UTC()))
		v, err := db.AlertView(ctx, actor, h)
		must(err)
		return v
	}
	x.category = sshcli.ConnectionTimeout
	collect()
	if v := evaluate(); v.Active != 0 {
		t.Fatal("single uncorroborated failure", v)
	}
	collect()
	if v := evaluate(); v.Active != 1 {
		t.Fatal("corroborated network failure", v)
	}
	for _, category := range []sshcli.Category{sshcli.AuthenticationFailed, sshcli.ChangedKey} {
		x.category = category
		collect()
		if v := evaluate(); v.Active != 1 {
			t.Fatal("inconclusive evidence resolved", v)
		}
	}
	x.category = ""
	collect()
	if v := evaluate(); v.Active != 0 {
		t.Fatal("genuine recovery", v)
	}
}
