package postgres

import (
	"context"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/linux"
	ast "noc-workbench/internal/integrations/asterisk"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"testing"
	"time"
)

func TestIntegrationStandardMonitoringGrants(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	if db.StandardMonitoringAllowed(ctx, p, target) == nil {
		t.Fatal("legacy expanded")
	}
	alien := h
	alien.CustomerID = workspace.OperatorID
	if db.SetStandardMonitoring(ctx, p, alien, target, true) == nil || db.SetStandardMonitoring(ctx, workspace.Principal{}, h, target, true) == nil {
		t.Fatal("scope bypass")
	}
	stale := target
	stale.ProfileVersion++
	if db.SetStandardMonitoring(ctx, p, h, stale, true) == nil {
		t.Fatal("stale enrollment")
	}
	// Force the final audit insert to fail and prove grants/schedule roll back.
	_, e := db.pool.Exec(ctx, `ALTER TABLE connection_audit ADD CONSTRAINT synthetic_reject_standard CHECK(operation<>'standard')`)
	must(e)
	if db.SetStandardMonitoring(ctx, p, h, target, true) == nil {
		t.Fatal("audit failure ignored")
	}
	var n int
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM collection_integration`).Scan(&n))
	if n != 0 {
		t.Fatal("grant rollback", n)
	}
	must(db.pool.QueryRow(ctx, `SELECT count(*) FROM collection_schedule`).Scan(&n))
	if n != 0 {
		t.Fatal("schedule rollback")
	}
	_, e = db.pool.Exec(ctx, `ALTER TABLE connection_audit DROP CONSTRAINT synthetic_reject_standard`)
	must(e)
	must(db.SetStandardMonitoring(ctx, p, h, target, false))
	must(db.StandardMonitoringAllowed(ctx, p, target))
	if db.IntegrationAllowed(ctx, p, target, "asterisk_helper") == nil {
		t.Fatal("implicit helper")
	}
	_, e = db.pool.Exec(ctx, `UPDATE collection_schedule SET paused=true,next_due='2030-01-01'`)
	must(e)
	var before, after string
	snapshot := `SELECT jsonb_build_object('schedule',(SELECT row_to_json(s) FROM collection_schedule s),'grants',(SELECT jsonb_agg(row_to_json(i) ORDER BY integration) FROM collection_integration i WHERE integration<>'asterisk_helper'))::text`
	must(db.pool.QueryRow(ctx, snapshot).Scan(&before))
	must(db.SetStandardMonitoring(ctx, p, h, target, true))
	must(db.SetStandardMonitoring(ctx, p, h, target, true))
	must(db.pool.QueryRow(ctx, snapshot).Scan(&after))
	if before != after {
		t.Fatal("valid grants or schedule reset")
	}
	must(db.IntegrationAllowed(ctx, p, target, "asterisk_helper"))
	must(db.SetStandardMonitoring(ctx, p, h, target, false))
	if db.IntegrationAllowed(ctx, p, target, "asterisk_helper") == nil {
		t.Fatal("helper revocation")
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk", false))
	if db.StandardMonitoringAllowed(ctx, p, target) == nil {
		t.Fatal("revocation ignored")
	}
	rec, e := db.Enrollment(ctx, target.EndpointID, target.ProfileID)
	must(e)
	if rec.Revision != target.ProfileVersion {
		t.Fatal("authority changed SSH revision")
	}
}

type helperEvidenceExecutor struct{ mismatch bool }

func (x helperEvidenceExecutor) Execute(ctx context.Context, p workspace.Principal, t sshcli.Target, id string) (sshcli.Result, error) {
	r, e := (&registrationExecutor{at: time.Now().UTC()}).Execute(ctx, p, t, id)
	r.CommandID = "asterisk.identity.helper.v1"
	if x.mismatch {
		r.CommandID = "asterisk.registrations.helper.v1"
	}
	return r, e
}
func TestIntegrationHelperProvenance(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	if e := db.SetStandardMonitoring(ctx, p, h, target, true); e != nil {
		t.Fatal(e)
	}
	svc := collection.NewService(helperEvidenceExecutor{}, linux.Registry().Extend(ast.Specs()...), db)
	run, e := svc.Collect(collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{"asterisk.identity"}}), p, target)
	if e != nil || run.SuccessCount != 1 {
		t.Fatal(run, e)
	}
	var command string
	if e = db.pool.QueryRow(ctx, `SELECT command_id FROM observation WHERE run_id=$1`, run.ID).Scan(&command); e != nil || command != "asterisk.identity.helper.v1" {
		t.Fatal(command, e)
	}
	for _, table := range []string{"observation", "collector_result"} {
		if _, e = db.pool.Exec(ctx, `UPDATE `+table+` SET command_id='asterisk.registrations.helper.v1' WHERE run_id=$1`, run.ID); e == nil {
			t.Fatal("SQL accepted wrong helper pair", table)
		}
	}
	reopened, e := Open(ctx, db.pool.Config().ConnString())
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if e = reopened.IntegrationAllowed(ctx, p, target, "asterisk_helper"); e != nil {
		t.Fatal("restart grant", e)
	}
	_ = h
}
