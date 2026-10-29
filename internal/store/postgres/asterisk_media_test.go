package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/linux"
	ast "noc-workbench/internal/integrations/asterisk"
	activity "noc-workbench/internal/integrations/asteriskactivity"
	ami "noc-workbench/internal/integrations/asteriskami"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

func TestIntegrationMediaHistoryAuthorityRuntimeAndReplay(t *testing.T) {
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
	must(db.SetIntegration(ctx, p, h, target, "asterisk_activity", true))
	_, e := db.SaveSchedule(ctx, p, scheduler.Profile{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, AssetID: h.AssetID, Target: target, Interval: 60, Budget: 20, Collectors: []string{"linux.uptime"}, Enabled: true, Authorized: true})
	must(e)
	must(db.SetAMIGrant(ctx, p, h, target, "synthetic", strings.Repeat("a", 64), true))
	bindings, e := db.AMIBindings(ctx, p)
	must(e)
	b := bindings[0]
	now := time.Now().UTC().Truncate(time.Microsecond)
	id, e := db.BeginAMISession(ctx, b, now.Add(-time.Second))
	must(e)
	must(db.AMITransition(ctx, b, id, "connected", "", now.Add(-time.Second), 0, false))
	f := ami.Frame{"event": {"RTCPReceived"}, "uniqueid": {"1.1"}, "linkedid": {"context-only"}, "ssrc": {"0x12345678"}, "pt": {"201(RR)"}, "reportcount": {"1"}, "report0sourcessrc": {"0xabcdef01"}, "report0lsr": {"42"}, "report0fractionlost": {"0"}, "report0cumulativelost": {"0"}, "report0iajitter": {"80"}, "rtt": {"0.125"}, "calleridnum": {"discard-secret"}}
	event, ok := ami.Normalize(f, now)
	if !ok {
		t.Fatal("normalization")
	}
	event.Sequence = 1
	if db.PersistAMIEvent(ctx, b, id, event, 0) == nil {
		t.Fatal("media without explicit grant")
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk_media", true))
	bindings, e = db.AMIBindings(ctx, p)
	must(e)
	b = bindings[0]
	if !b.Media {
		t.Fatal("subscription")
	}
	x := &activityExecutor{snap: activity.Snapshot{Runtime: strings.Repeat("a", 64), Channels: []activity.Channel{{ID: "1.1", Name: "SIP/phone-00000001", State: "Up"}}}, at: now.Add(-time.Millisecond)}
	svc := collection.NewService(x, linux.Registry().Extend(ast.Specs()...), db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{activity.Collector}})
	run, e := svc.Collect(req, p, target)
	must(e)
	if run.SuccessCount != 1 {
		t.Fatal(run)
	}
	must(db.PersistAMIEvent(ctx, b, id, event, 0))
	event.ReceivedAt = now.Add(time.Hour)
	must(db.PersistAMIEvent(ctx, b, id, event, 0))
	history, allowed, e := db.MediaHistory(ctx, p, h, target)
	must(e)
	if !allowed || len(history) != 1 || !history[0].At.Equal(now) || history[0].Runtime != strings.Repeat("a", 64) || history[0].Channel != "SIP/phone-00000001" || *history[0].Report.RTTMilliseconds != 125 {
		t.Fatalf("history %+v", history)
	}
	alien := h
	alien.CustomerID = workspace.OperatorID
	if _, _, e = db.MediaHistory(ctx, p, alien, target); e == nil {
		t.Fatal("customer boundary")
	}
	if _, e = db.pool.Exec(ctx, `UPDATE asterisk_ami_event SET customer_id=$1 WHERE session_id=$2`, workspace.OperatorID, id); e == nil {
		t.Fatal("SQL tenant boundary")
	}
	if _, e = db.pool.Exec(ctx, `UPDATE asterisk_ami_event SET media=jsonb_set(media,'{Blocks,0,CallerID}', '"secret"') WHERE session_id=$1`, id); e == nil {
		t.Fatal("SQL sensitive block field")
	}
	// Snapshot removal must retain immutable historical channel association.
	x.snap.Channels = nil
	x.at = now.Add(time.Second)
	_, e = svc.Collect(req, p, target)
	must(e)
	reopened, e := Open(ctx, db.pool.Config().ConnString())
	must(e)
	defer reopened.Close()
	history, _, e = reopened.MediaHistory(ctx, p, h, target)
	must(e)
	if len(history) != 1 || history[0].Channel != "SIP/phone-00000001" {
		t.Fatal("history lost after channel end/reopen")
	}
	// The legacy activity authorization path cannot report an effective media subscription.
	must(db.SetIntegration(ctx, p, h, target, "asterisk_activity", false))
	bindings, e = db.AMIBindings(ctx, p)
	must(e)
	if bindings[0].Media {
		t.Fatal("system-only session advertised media")
	}
	_, allowed, e = db.MediaHistory(ctx, p, h, target)
	must(e)
	if allowed {
		t.Fatal("media effective authority ignores activity revocation")
	}
	event.Sequence = 2
	event.ReceivedAt = now.Add(2 * time.Second)
	if db.PersistAMIEvent(ctx, b, id, event, 0) == nil {
		t.Fatal("queued media accepted after revocation")
	}
	must(db.SetIntegration(ctx, p, h, target, "asterisk_activity", true))
	// Atomic failure: no journal or timestamp changes when persistence fails.
	_, e = db.pool.Exec(ctx, `CREATE FUNCTION reject_media_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$; CREATE TRIGGER reject_media BEFORE INSERT ON asterisk_ami_event FOR EACH ROW EXECUTE FUNCTION reject_media_fixture()`)
	must(e)
	if db.PersistAMIEvent(ctx, b, id, event, 0) == nil {
		t.Fatal("database failure ignored")
	}
	_, e = db.pool.Exec(ctx, `DROP TRIGGER reject_media ON asterisk_ami_event`)
	must(e)
	history, _, e = db.MediaHistory(ctx, p, h, target)
	must(e)
	if len(history) != 1 || !history[0].At.Equal(now) {
		t.Fatal("partial commit")
	}
	must(db.RecoverAMI(ctx))
	if db.PersistAMIEvent(ctx, b, id, event, 0) == nil {
		t.Fatal("ended session ingestion")
	}
	history, _, e = db.MediaHistory(ctx, p, h, target)
	must(e)
	if len(history) != 1 {
		t.Fatal("restart erased media")
	}

	_, e = db.pool.Exec(ctx, `UPDATE connection_profile SET revision=revision+1 WHERE id=$1`, target.ProfileID)
	must(e)
	target.ProfileVersion++
	history, _, e = db.MediaHistory(ctx, p, h, target)
	must(e)
	if len(history) != 1 || history[0].ProfileRevision != target.ProfileVersion-1 {
		t.Fatal("revision change erased historical evidence", history)
	}
}

func TestIntegrationMediaStandardScheduleExpansion(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	if e := db.SetStandardMonitoringWithActivity(ctx, p, h, target, true, true, true, true); e != nil {
		t.Fatal(e)
	}
	// Stage A's already verified registration collector is retained on the real schedule.
	if _, e := db.pool.Exec(ctx, `UPDATE collection_schedule SET collector_ids=array_append(collector_ids,'asterisk.registrations') WHERE asset_id=$1`, h.AssetID); e != nil {
		t.Fatal(e)
	}
	snap, e := db.Schedules(ctx, p)
	if e != nil || len(snap.Profiles) != 1 || len(snap.Profiles[0].Collectors) != 10 {
		t.Fatalf("Stage D baseline %+v %v", snap, e)
	}
	if e = db.SetStandardMonitoringWithMedia(ctx, p, h, target, true, true, true, true, true); e != nil {
		t.Fatal(e)
	}
	snap, e = db.Schedules(ctx, p)
	if e != nil || len(snap.Profiles) != 1 || len(snap.Profiles[0].Collectors) != 11 {
		t.Fatalf("Stage E expansion %+v %v", snap, e)
	}
	if e = scheduler.Validate(snap.Profiles[0]); e != nil {
		t.Fatal(e)
	}
	if e = db.SetStandardMonitoringWithMedia(ctx, p, h, target, true, true, true, true, true); e != nil {
		t.Fatal(e)
	}
	again, e := db.Schedules(ctx, p)
	if e != nil || len(again.Profiles[0].Collectors) != 11 {
		t.Fatal("duplicate expansion", e)
	}
}

type mediaCLIExecutor struct {
	at   time.Time
	body []byte
	fail bool
}

func (x *mediaCLIExecutor) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, id string) (sshcli.Result, error) {
	r := sshcli.Result{CommandID: "asterisk.media.helper.v1", StartedAt: x.at, EndedAt: x.at.Add(time.Millisecond), Stdout: x.body}
	if x.fail {
		return r, &sshcli.Failure{Category: sshcli.ExecutionTimeout}
	}
	return r, nil
}
func TestIntegrationMediaCLIHistoryFreshnessAndFailedLatest(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	for _, name := range []string{"asterisk", "asterisk_activity", "asterisk_media", "asterisk_helper"} {
		if e := db.SetIntegration(ctx, p, h, target, name, true); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	x := &mediaCLIExecutor{at: now, body: []byte("Asterisk 18.26.4-vici\nNW_MEDIA_sip\nPeer             Call ID      Duration Recv: Pack Lost (%) Jitter Send: Pack Lost (%) Jitter\n192.0.2.1 private-id 00:00:05 50 0 ( 0.00%) 0.000 60 1 ( 1.50%) 0.000\n1 active SIP channels\nNW_MEDIA_pjsip\nNo objects found.\nNW_MEDIA_END\n")}
	svc := collection.NewService(x, linux.Registry().Extend(ast.Specs()...), db)
	req := collection.WithRequest(ctx, collection.Request{Source: "operator", Collectors: []string{"asterisk.media"}})
	run, e := svc.Collect(req, p, target)
	if e != nil || run.SuccessCount != 1 {
		t.Fatal(run, e)
	}
	v, e := db.MediaCLIView(ctx, p, h, target, now.Add(time.Second))
	if e != nil || !v.Current || len(v.Sources) != 2 || len(v.Sources[1].Rows) != 1 {
		t.Fatalf("populated %+v %v", v, e)
	}
	// Source ordering is lexicographic; pjsip precedes sip.
	v, e = db.MediaCLIView(ctx, p, h, target, now.Add(181*time.Second))
	if e != nil || v.Current {
		t.Fatal("stale", e)
	}
	x.at = now.Add(time.Second)
	x.body = []byte("Asterisk 18.26.4-vici\nNW_MEDIA_sip\nPeer             Call ID      Duration Recv: Pack Lost (%) Jitter Send: Pack Lost (%) Jitter\n0 active SIP channels\nNW_MEDIA_pjsip\nNo objects found.\nNW_MEDIA_END\n")
	run, e = svc.Collect(req, p, target)
	if e != nil || run.SuccessCount != 1 {
		t.Fatal(run, e)
	}
	v, e = db.MediaCLIView(ctx, p, h, target, now.Add(2*time.Second))
	if e != nil || !v.Current || len(v.Sources) != 2 || len(v.Sources[1].Rows) != 0 {
		t.Fatal("empty", v, e)
	}
	x.at = now.Add(2 * time.Second)
	x.fail = true
	_, e = svc.Collect(req, p, target)
	if e != nil {
		t.Fatal(e)
	}
	v, e = db.MediaCLIView(ctx, p, h, target, now.Add(3*time.Second))
	if e != nil || v.Current || len(v.Sources) != 0 {
		t.Fatal("failed latest borrowed success", v, e)
	}
}
