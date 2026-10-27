package postgres

import (
	"context"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	discovery "noc-workbench/internal/integrations/vicidialdiscovery"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type discoveryExecutor struct {
	calls int
	fail  bool
}

func (e *discoveryExecutor) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, _ string) (sshcli.Result, error) {
	e.calls++
	at := time.Now().UTC()
	if e.fail {
		return sshcli.Result{StartedAt: at, EndedAt: at, Category: sshcli.AuthenticationFailed}, &sshcli.Failure{Category: sshcli.AuthenticationFailed}
	}
	return sshcli.Result{StartedAt: at, EndedAt: at, Stdout: []byte("NW_VICIDIAL_DISCOVERY_1\nvbox=12.0.2\nsvn=4034\napp_version=2.14-968a\nidentity=matched\nweb=matched\ndialer=matched\napache=2.4.66\nasterisk=18.26.4\ndatabase=10.11.15\nconfig=present\nserver_ip=192.0.2.10\ndb_ip=192.0.2.10\nconfig_port=3306\ndb_name=asterisk\nobserved_port=3306\nregistry=available\nregistry_row=192.0.2.10|Web|-\nregistry_row=192.0.2.10|Telephony|-\nregistry_row=192.0.2.10|Database|Primary\nreplica=none\nprimary_streams=0\narchive_alias=missing\nEND\n")}, nil
}

func TestIntegrationVICIdialDiscoveryPersistence(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	executor := &discoveryExecutor{}
	registry := linux.Registry().Extend(discovery.Specs()...)
	svc := collection.NewService(discovery.Executor{Next: executor, Authority: db}, registry, db)
	request := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{discovery.Collector}})
	if _, e := svc.Collect(request, p, target); e == nil || executor.calls != 0 {
		t.Fatal("opt-in bypass")
	}
	alien := h
	alien.CustomerID = workspace.OperatorID
	if db.SetIntegration(ctx, p, alien, target, "vicidial_discovery", true) == nil {
		t.Fatal("cross-customer opt-in")
	}
	must(db.SetIntegration(ctx, p, h, target, "vicidial_discovery", true))
	run, e := svc.Collect(request, p, target)
	must(e)
	if run.SuccessCount != 1 || executor.calls != 1 {
		t.Fatal("collection failed", run)
	}
	facts, e := db.LatestEvidence(ctx, p, h)
	must(e)
	if len(facts) != 1 {
		t.Fatal("snapshot not persisted")
	}
	first := facts[0]
	if first.RunID != run.ID || first.CollectorVersion != "1" || first.CommandID != "vicidial.discovery.v1" {
		t.Fatal("provenance lost")
	}
	result := discovery.Evaluate(first, first.ReceivedAt, "fresh", true)
	if result.Roles[0].State != "Confirmed" || result.Roles[1].State != "Confirmed" || result.Deployment.ID != "Standalone" {
		t.Fatal("multi-role persistence", result)
	}
	executor.fail = true
	failed, e := svc.Collect(request, p, target)
	must(e)
	if failed.FailureCount != 1 {
		t.Fatal("missing failure history")
	}
	facts, e = db.LatestEvidence(ctx, p, h)
	must(e)
	if len(facts) != 1 || facts[0].ID != first.ID || !facts[0].ObservedAt.Equal(first.ObservedAt) {
		t.Fatal("failed discovery replaced valid evidence")
	}
	linuxSvc := collection.NewService(historyExecutor{}, linux.Registry(), db)
	_, e = linuxSvc.Collect(ctx, p, target)
	must(e)
	facts, e = db.LatestEvidence(ctx, p, h)
	must(e)
	if len(facts) < 16 {
		t.Fatal("Linux evidence not preserved")
	}
	if _, e = db.pool.Exec(ctx, `UPDATE observation SET asset_id=$1 WHERE id=$2`, workspace.OperatorID, first.ID); e == nil {
		t.Fatal("cross-asset direct SQL accepted")
	}
	if _, e = db.pool.Exec(ctx, `UPDATE collection_integration SET customer_id=$1 WHERE profile_id=$2`, workspace.OperatorID, target.ProfileID); e == nil {
		t.Fatal("cross-customer direct SQL accepted")
	}
	// Finish is atomic even when the result contains an invalid foreign subject.
	running, e := db.BeginCollection(request, p, target)
	must(e)
	executor.fail = false
	collected, e := registry.Collect(request, executor, p, target, []string{discovery.Collector})
	must(e)
	collected.ID = running.ID
	collected.PrincipalID = p.ID
	collected.Results[0].Observations[0].AssetID = workspace.OperatorID
	if db.FinishCollection(ctx, p, collected, 180) == nil {
		t.Fatal("foreign subject committed")
	}
	var count int
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM collector_result WHERE run_id=$1`, running.ID).Scan(&count))
	if count != 0 {
		t.Fatal("partial transaction persisted")
	}
	must(db.RecoverCollections(ctx))
	must(db.SetIntegration(ctx, p, h, target, "vicidial_discovery", false))
	before := executor.calls
	if _, e = svc.Collect(request, p, target); e == nil || executor.calls != before {
		t.Fatal("revoked opt-in executed")
	}
	dsn := db.pool.Config().ConnString()
	db.Close()
	restored, e := Open(ctx, dsn)
	must(e)
	defer restored.Close()
	must(restored.Migrate(ctx))
	facts, e = restored.LatestEvidence(ctx, p, h)
	must(e)
	found := false
	for _, f := range facts {
		if f.ID == first.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("restart lost discovery evidence")
	}
}
