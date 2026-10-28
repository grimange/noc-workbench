package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/linux"
	ast "noc-workbench/internal/integrations/asterisk"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type registrationExecutor struct {
	failed, empty, partial, contactDenied bool
	at                                    time.Time
}

func (x *registrationExecutor) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, id string) (sshcli.Result, error) {
	output := "Asterisk 18.26.4-vici built by synthetic on Linux\n"
	if x.failed {
		output = "Unable to connect to remote asterisk (Permission denied)"
	} else if id == "asterisk.registrations.v1" {
		for _, source := range ast.RegistrationSources {
			output += "\nNW_REGISTRATIONS_" + source + "\n"
			switch {
			case source == "pjsip_contacts" && x.contactDenied:
				output += "Permission denied"
			case source == "pjsip_contacts" && !x.empty:
				output += "Contact: <Aor/ContactUri> <Hash> <Status> <RTT(ms)>\nContact: phone/sip:phone@192.0.2.2 abcdef0123 Avail 2.5\nObjects found: 1"
			case source == "pjsip_contacts" && x.empty:
				output += "No objects found."
			case source == "sip_peers" && x.partial:
				output += "Permission denied"
			default:
				output += "No such command 'unsupported'"
			}
		}
		output += "\nNW_REGISTRATIONS_END\n"
	}
	return sshcli.Result{StartedAt: x.at, EndedAt: x.at, Stdout: []byte(output)}, nil
}
func TestIntegrationRegistrationSnapshots(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	x := &registrationExecutor{at: time.Now().UTC().Add(-time.Minute)}
	svc := collection.NewService(ast.Executor{Next: x, Authority: db}, linux.Registry().Extend(ast.Specs()...), db)
	ids := []string{"asterisk.identity", ast.RegistrationCollector}
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: ids})
	if _, e := svc.Collect(req, actor, target); e == nil {
		t.Fatal("implicit authority")
	}
	must(db.SetIntegration(ctx, actor, h, target, "asterisk", true))
	run, e := svc.Collect(req, actor, target)
	must(e)
	if run.SuccessCount != 2 {
		t.Fatalf("%+v", run)
	}
	latest, e := db.LatestEvidence(ctx, actor, h)
	must(e)
	var manifest collection.Evidence
	for _, v := range latest {
		if v.Resource == "pjsip_contacts" {
			manifest = v
		}
	}
	snapshot, e := ast.DecodeRegistration(manifest, latest)
	must(e)
	if snapshot.Count != 1 || snapshot.Rows[0].Reachability != "Reachable" || manifest.RunID != run.ID || manifest.ProfileVersion != target.ProfileVersion {
		t.Fatal(snapshot, manifest)
	}
	profile := scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, PrincipalID: actor.ID, Collectors: []string{ast.RegistrationCollector}, Interval: 60, Budget: 20, Enabled: true, Authorized: true}
	profile, e = db.SaveSchedule(ctx, actor, profile)
	must(e)
	// A failed family keeps its previous valid evidence and does not discard other families.
	x.partial = true
	x.at = x.at.Add(time.Second)
	partial, e := svc.Collect(req, actor, target)
	must(e)
	if partial.FailureCount != 1 || partial.SuccessCount != 1 {
		t.Fatal(partial)
	}
	profile, e = db.SaveSchedule(ctx, actor, profile)
	must(e)
	x.failed = true
	x.at = x.at.Add(time.Second)
	failed, e := svc.Collect(req, actor, target)
	must(e)
	if failed.SuccessCount != 0 {
		t.Fatal(failed)
	}
	latest, e = db.LatestEvidence(ctx, actor, h)
	must(e)
	for _, v := range latest {
		if v.RunID == failed.ID {
			t.Fatal("failed replacement")
		}
	}
	history, e := db.RecentCollectorEvidence(ctx, actor, h, ast.RegistrationCollector, ast.RegistrationKey)
	must(e)
	if len(history) == 0 {
		t.Fatal("missing snapshot history")
	}
	// Other successful families must not crowd out the prior contact snapshot.
	x.failed = false
	x.contactDenied = true
	for range 3 {
		x.at = x.at.Add(time.Second)
		_, e = svc.Collect(req, actor, target)
		must(e)
	}
	x.contactDenied = false
	x.empty = true
	x.at = x.at.Add(time.Second)
	_, e = svc.Collect(req, actor, target)
	must(e)
	history, e = db.RecentCollectorEvidence(ctx, actor, h, ast.RegistrationCollector, ast.RegistrationKey)
	must(e)
	var counts []int
	for _, ev := range history {
		if ev.Resource == "pjsip_contacts" {
			previous, decodeErr := ast.DecodeRegistration(ev, history)
			must(decodeErr)
			counts = append(counts, previous.Count)
		}
	}
	if len(counts) != 2 || counts[0] != 0 || counts[1] != 1 {
		t.Fatalf("per-family history after partial failures: %v", counts)
	}
	foreign := h
	foreign.CustomerID = workspace.OperatorID
	if rows, e := db.RecentCollectorEvidence(ctx, actor, foreign, ast.RegistrationCollector, ast.RegistrationKey); e == nil && len(rows) > 0 {
		t.Fatal("cross customer history")
	}
	if _, e = db.RecentCollectorEvidence(ctx, workspace.Principal{}, h, ast.RegistrationCollector, ast.RegistrationKey); e == nil {
		t.Fatal("anonymous history")
	}
	// Restart opens the same schema and retains observations and scheduling.
	reopened, e := Open(ctx, db.pool.Config().ConnString())
	must(e)
	defer reopened.Close()
	persisted, e := reopened.RecentCollectorEvidence(ctx, actor, h, ast.RegistrationCollector, ast.RegistrationKey)
	must(e)
	if len(persisted) != len(history) {
		t.Fatal("restart history")
	}
	snap, e := reopened.Schedules(ctx, actor)
	must(e)
	if len(snap.Profiles) != 1 || snap.Profiles[0].Interval != 60 {
		t.Fatal("restart schedule")
	}
	// Direct SQL rejects ownership and invalid collector/resource combinations transactionally.
	tx, e := db.pool.Begin(ctx)
	must(e)
	if _, e = tx.Exec(ctx, `UPDATE observation SET asset_id=$1 WHERE run_id=$2`, workspace.OperatorID, run.ID); e == nil {
		t.Fatal("cross asset")
	}
	tx.Rollback(ctx)
	if _, e = db.pool.Exec(ctx, `UPDATE observation SET resource='arbitrary' WHERE run_id=$1 AND collector_id=$2`, run.ID, ast.RegistrationCollector); e == nil {
		t.Fatal("resource allowlist")
	}
	if _, e = db.pool.Exec(ctx, `UPDATE observation SET key='asterisk.password' WHERE run_id=$1 AND collector_id=$2`, run.ID, ast.RegistrationCollector); e == nil {
		t.Fatal("key allowlist")
	}
	for _, v := range persisted {
		if strings.Contains(v.Value.Text, "Permission denied") {
			t.Fatal("raw diagnostic retained")
		}
	}
	must(db.SetIntegration(ctx, actor, h, target, "asterisk", false))
	if _, e = svc.Collect(req, actor, target); e == nil {
		t.Fatal("revoked authority")
	}
}
