package postgres

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	ast "noc-workbench/internal/integrations/asterisk"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"testing"
	"time"
)

type adapterFixtureExecutor struct{ denied bool }

func (e adapterFixtureExecutor) Execute(ctx context.Context, p workspace.Principal, t sshcli.Target, id string) (sshcli.Result, error) {
	if len(id) > 6 && id[:6] == "linux." {
		return (historyExecutor{}).Execute(ctx, p, t, id)
	}
	now := time.Now().UTC()
	version := "Asterisk 20.20.1 built by synthetic on Linux\n"
	data := map[string]string{"asterisk.identity.v1": version, "asterisk.channels.v1": version + "\nNW_ASTERISK_DATA\n2 active channels\n1 active call\n1 calls processed", "asterisk.modules.v1": version + "\nNW_ASTERISK_DATA\nModule Description Use Count Status Support Level\nres_pjsip.so Basic SIP resource 0 Running core\n1 modules loaded", "asterisk.pjsip.v1": version + "\nNW_ASTERISK_DATA\nNo objects found."}
	if e.denied {
		data[id] = "Unable to connect to remote asterisk (Permission denied)"
	}
	return sshcli.Result{StartedAt: now, EndedAt: now, Stdout: []byte(data[id])}, nil
}
func TestIntegrationOptionalCollectorHistory(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	ids := []string{"asterisk.identity", "asterisk.channels", "asterisk.modules", "asterisk.pjsip"}
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: ids})
	reg := linux.Registry().Extend(ast.Specs()...)
	svc := collection.NewService(ast.Executor{Next: adapterFixtureExecutor{}, Authority: db}, reg, db)
	if _, e := svc.Collect(req, p, target); e == nil {
		t.Fatal("default opt-in bypass")
	}
	if e := db.SetIntegration(ctx, workspace.Principal{}, h, target, "asterisk", true); e == nil {
		t.Fatal("anonymous enable")
	}
	alien := h
	alien.EnvironmentID = workspace.OperatorID
	if e := db.SetIntegration(ctx, p, alien, target, "asterisk", true); e == nil {
		t.Fatal("foreign enable")
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk", true))
	schedule := scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, PrincipalID: p.ID, Collectors: ids, Interval: 120, Budget: 20, Enabled: true, Authorized: true}
	if _, e := db.SaveSchedule(ctx, p, schedule); e == nil {
		t.Fatal("schedule without capability evidence")
	}
	run, e := svc.Collect(req, p, target)
	must(e)
	if run.SuccessCount != 4 {
		t.Fatalf("collect %+v", run)
	}
	schedule, e = db.SaveSchedule(ctx, p, schedule)
	must(e)
	facts, e := db.LatestEvidence(ctx, p, h)
	must(e)
	if len(facts) != 6 {
		t.Fatal("facts", len(facts))
	}
	for _, v := range facts {
		if v.RunID != run.ID || v.ProfileVersion != target.ProfileVersion || v.Unit == "" {
			t.Fatal("provenance")
		}
	}
	// An adapter-specific failure preserves both previous adapter and Linux facts.
	linuxRun, e := svc.Collect(ctx, p, target)
	must(e)
	if linuxRun.SuccessCount != 5 {
		t.Fatal("Linux defaults changed")
	}
	// A mixed nine-collector run retains every collector outcome in evaluation.
	mixed := append(reg.Defaults(), ids...)
	partialSvc := collection.NewService(adapterFixtureExecutor{denied: true}, reg, db)
	partial, e := partialSvc.Collect(collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: mixed}), p, target)
	must(e)
	if partial.SuccessCount != 5 || partial.FailureCount != 4 {
		t.Fatal("mixed result", partial)
	}
	evaluated, e := db.EvaluationEvidence(ctx, p, h, time.Now().UTC())
	must(e)
	if evaluated.LatestAttempt == nil || len(evaluated.LatestAttempt.Results) != 9 {
		t.Fatal("mixed outcomes truncated", evaluated.LatestAttempt)
	}
	failed := collection.NewService(adapterFixtureExecutor{denied: true}, reg, db)
	deniedRun, e := failed.Collect(req, p, target)
	must(e)
	if deniedRun.SuccessCount != 0 || deniedRun.FailureCount != 4 {
		t.Fatal("permission outcome")
	}
	facts, e = db.LatestEvidence(ctx, p, h)
	must(e)
	for _, v := range facts {
		if v.RunID == deniedRun.ID {
			t.Fatal("invalid replacement")
		}
	}
	// Scope and value contracts are enforced through direct SQL, too.
	if _, e = db.pool.Exec(ctx, `UPDATE collection_integration SET environment_id=$1 WHERE profile_id=$2`, workspace.OperatorID, target.ProfileID); e == nil {
		t.Fatal("cross-environment FK")
	}
	if _, e = db.pool.Exec(ctx, `UPDATE observation SET unit='bytes' WHERE run_id=$1 AND key='asterisk.channels.active'`, run.ID); e == nil {
		t.Fatal("incompatible unit")
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk", false))
	snap, e := db.Schedules(ctx, p)
	must(e)
	if len(snap.Profiles) != 1 || snap.Profiles[0].Eligible {
		t.Fatal("revoked schedule remains eligible")
	}
	if _, e = svc.Collect(req, p, target); e == nil {
		t.Fatal("revoked adapter executed")
	}
	if _, e = svc.Collect(ctx, p, target); e != nil {
		t.Fatal("adapter disable affected Linux", e)
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk", true))
	stale := target
	stale.ProfileVersion++
	if db.IntegrationAllowed(ctx, p, stale, "asterisk") == nil {
		t.Fatal("stale authority")
	}
	if e = db.RecoverCollections(ctx); e != nil {
		t.Fatal(e)
	}
}

// Admission must reuse its transaction connection, even when the shared pool
// has only one free slot. Five concurrent assets must not self-exhaust it.
func TestIntegrationOptionalAdmissionSingleFreeConnection(t *testing.T) {
	db, scope, target := collectionFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	actor := workspace.Principal{ID: workspace.OperatorID}
	if e := db.SetIntegration(ctx, actor, scope, target, "asterisk", true); e != nil {
		t.Fatal(e)
	}
	held := make([]*pgxpool.Conn, 0, 4)
	defer func() {
		for _, c := range held {
			c.Release()
		}
	}()
	for i := 0; i < 4; i++ {
		c, e := db.pool.Acquire(ctx)
		if e != nil {
			t.Fatal(e)
		}
		held = append(held, c)
	}
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{"asterisk.identity"}})
	run, e := db.BeginCollection(req, actor, target)
	if e != nil || run.ID == "" {
		t.Fatalf("single-slot admission failed: %v", e)
	}
}
