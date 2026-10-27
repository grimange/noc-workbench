package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"noc-workbench/internal/integrations/vicidial"
	api "noc-workbench/internal/integrations/vicidialapi"

	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/workspace"
)

const apiVersionBody = "VERSION: 2.14-210|BUILD: 260925-1400|DATE: 2026-10-27 08:00:00|EPOCH: 1793088000|DST: 0|TZ: 0|TZNOW: 0|\n"
const apiCampaignBody = "campaign_id|campaign_name|active|user_group|dial_method|dial_level|lead_order|dial_statuses|dial_timeout|dial_prefix|manual_dial_prefix|three_way_dial_prefix\nSYNTH01|Synthetic|Y|SYNTH|MANUAL|1|DOWN|NEW|60|9||\n"
const apiAgentsBody = "user|campaign_id|session_id|status|lead_id|callerid|calls_today|full_name|user_group|user_level\nsynthetic01|SYNTH01|1001|INCALL|123|private-discard-me|0|Private synthetic name|SYNTH|1\n"

func sourceFixture(t *testing.T) (*Store, string, collection.Source) {
	t.Helper()
	s, dsn, h, _ := vicidialFixture(t)
	p := workspace.Principal{ID: workspace.OperatorID}
	if _, e := s.SaveVICIdialIntegration(context.Background(), p, h, vicidial.Integration{Name: "Synthetic API context", Enabled: true}); e != nil {
		t.Fatal(e)
	}
	v, e := s.SaveSourceConfiguration(context.Background(), p, collection.Source{CustomerID: h.CustomerID, EnvironmentID: h.EnvironmentID, ClusterID: h.ClusterID, CredentialReference: "synthetic_api", Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	return s, dsn, v
}
func sourceAPI(t *testing.T, s *Store, v collection.Source, handler http.HandlerFunc) (*api.Service, *collection.Service, *atomic.Int32) {
	service, admission, calls, _ := sourceAPICatalog(t, s, v, handler)
	return service, admission, calls
}
func sourceAPICatalog(t *testing.T, s *Store, v collection.Source, handler http.HandlerFunc) (*api.Service, *collection.Service, *atomic.Int32, string) {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.Path != "/vicidial/non_agent_api.php" {
			t.Error("unsafe request")
		}
		_ = r.ParseForm()
		if r.Form.Get("source") != "noc-workbench" || r.Form.Get("user") != "synthetic_user" {
			t.Error("request binding")
		}
		if handler != nil {
			handler(w, r)
			return
		}
		switch r.Form.Get("function") {
		case "version":
			_, _ = w.Write([]byte(apiVersionBody))
		case "campaigns_list":
			_, _ = w.Write([]byte(apiCampaignBody))
		case "logged_in_agents":
			_, _ = w.Write([]byte(apiAgentsBody))
		default:
			t.Error("unapproved function")
		}
	}))
	t.Cleanup(server.Close)
	catalog := filepath.Join(t.TempDir(), "catalog.json")
	data, _ := json.Marshal([]map[string]any{{"ID": v.CredentialReference, "IntegrationID": v.ID, "Revision": v.Revision, "Enabled": true, "Endpoint": server.URL + "/vicidial/non_agent_api.php", "ApprovedIP": "127.0.0.1", "Campaign": "SYNTH01", "User": "synthetic_user", "Password": "synthetic-secret-only", "Synthetic": true, "ExpiresAt": time.Now().UTC().Add(time.Hour), "LoggingReviewDigest": strings.Repeat("a", 64), "ContractVersion": api.DocumentedVersion, "ContractBuild": api.DocumentedBuild}})
	if e := os.WriteFile(catalog, data, 0600); e != nil {
		t.Fatal(e)
	}
	admission := collection.NewService(nil, nil)
	return api.NewService(s, admission, catalog), admission, calls, catalog
}
func TestIntegrationSourceAPIHistoryEvaluationAndRestart(t *testing.T) {
	s, dsn, v := sourceFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	service, _, calls := sourceAPI(t, s, v, nil)
	run, e := service.Collect(ctx, p, v.ID, v.Revision)
	if e != nil || run.State != "completed" || run.SuccessCount != 3 || calls.Load() != 3 {
		t.Fatalf("run %s/%s %v calls%d", run.State, run.Category, e, calls.Load())
	}
	at := time.Now().UTC()
	h, e := s.SourceHistory(ctx, p, v, at)
	if e != nil || len(h.Latest) != 7 || len(h.Runs) != 1 || len(h.Runs[0].Results) != 3 {
		t.Fatalf("history %+v %v", h, e)
	}
	for _, o := range h.Latest {
		if o.SourceID != v.ID || o.SourceRevision != 1 || o.AssetID != "" || o.Transport != "http_fixture" || strings.Contains(o.Value.Text, "Private") {
			t.Fatal("invalid provenance or minimization", o)
		}
	}
	in, e := s.SourceEvaluation(ctx, p, v, at)
	if e != nil {
		t.Fatal(e)
	}
	ev, e := health.Evaluate(in)
	if e != nil || ev.Health != "unknown" || len(ev.Readings) != 7 {
		t.Fatal("canonical evaluation", ev, e)
	}
	// No implicit clock: exact expiry is stale; static identity remains fresh.
	dynamic := h.Latest[0].ObservedAt
	for _, o := range h.Latest {
		if o.Key == "vicidial.agents.visible_logged_in_count" {
			dynamic = o.ObservedAt
		}
	}
	in.At = dynamic.Add(180 * time.Second)
	ev, e = health.Evaluate(in)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range ev.Readings {
		if r.Evidence.Key == "vicidial.agents.visible_logged_in_count" && r.Freshness != "stale" {
			t.Fatal("TTL boundary", r)
		}
		if r.Evidence.Key == "vicidial.api.version" && r.Freshness != "fresh" {
			t.Fatal("static TTL", r)
		}
	}
	series, e := s.SourceSeries(ctx, p, v, "vicidial.agents.visible_logged_in_count", at.Add(-time.Hour), at)
	if e != nil || len(series.Samples) != 1 || series.Samples[0].Value != "1" {
		t.Fatal("chart", series, e)
	}
	if calls.Load() != 3 {
		t.Fatal("passive retrieval contacted API")
	}
	reopened, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	again, e := reopened.SourceHistory(ctx, p, v, at)
	if e != nil || len(again.Latest) != 7 {
		t.Fatal("restart", e)
	}
	// A new configuration cannot present a prior campaign's counts as current.
	v, e = s.SaveSourceConfiguration(ctx, p, v)
	if e != nil {
		t.Fatal(e)
	}
	h, e = s.SourceHistory(ctx, p, v, time.Now().UTC())
	if e != nil || len(h.Latest) != 0 || len(h.Runs) != 1 {
		t.Fatal("revision evidence isolation", h, e)
	}
	series, e = s.SourceSeries(ctx, p, v, "vicidial.agents.visible_logged_in_count", at.Add(-time.Hour), time.Now().UTC())
	if e != nil || len(series.Samples) != 0 {
		t.Fatal("revision chart isolation", e)
	}
	if _, e = service.Collect(ctx, p, v.ID, 1); e == nil || calls.Load() != 3 {
		t.Fatal("stale source contacted API")
	}
}
func TestIntegrationSourceFailurePreservesEvidenceAndNoHTTPOnBeginFailure(t *testing.T) {
	s, _, v := sourceFixture(t)
	ctx := context.Background()
	p := workspace.Principal{ID: workspace.OperatorID}
	mode := atomic.Bool{}
	service, _, calls := sourceAPI(t, s, v, func(w http.ResponseWriter, r *http.Request) {
		if mode.Load() {
			_, _ = w.Write([]byte("ERROR: Invalid Username/Password: synthetic|"))
			return
		}
		switch r.Form.Get("function") {
		case "version":
			_, _ = w.Write([]byte(apiVersionBody))
		case "campaigns_list":
			_, _ = w.Write([]byte(apiCampaignBody))
		case "logged_in_agents":
			_, _ = w.Write([]byte("ERROR: logged_in_agents NO LOGGED IN AGENTS: synthetic|"))
		}
	})
	run, e := service.Collect(ctx, p, v.ID, 1)
	if e != nil || run.State != "partial" || run.Results[2].TransportOutcome != "success" || run.Results[2].Diagnostics[0].Code != "insufficient_scope" {
		t.Fatal("application/transport separation", run, e)
	}
	before, e := s.SourceHistory(ctx, p, v, time.Now().UTC())
	if e != nil || len(before.Latest) != 4 {
		t.Fatal(e)
	}
	mode.Store(true)
	// A fresh service avoids coupling this assertion to rate-limit elapsed time.
	failure, _, _ := sourceAPI(t, s, v, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ERROR: Invalid Username/Password: synthetic|"))
	})
	failed, e := failure.Collect(ctx, p, v.ID, 1)
	if e != nil || failed.State != "failed" || scheduler.Retryable(failed) {
		t.Fatal("auth outcome", failed, e)
	}
	after, e := s.SourceHistory(ctx, p, v, time.Now().UTC())
	if e != nil || len(after.Latest) != 4 || !after.Latest[0].ObservedAt.Equal(before.Latest[0].ObservedAt) || len(after.Runs[0].Results) != 3 {
		t.Fatal("failed attempt erased evidence", e)
	}
	n := calls.Load()
	if _, e = s.pool.Exec(ctx, `CREATE FUNCTION reject_source_attempt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic durable-write failure'; END $$; CREATE TRIGGER reject_source_attempt BEFORE INSERT ON collection_run FOR EACH ROW EXECUTE FUNCTION reject_source_attempt()`); e != nil {
		t.Fatal(e)
	}
	if _, e = service.Collect(ctx, p, v.ID, 1); e == nil || calls.Load() != n {
		t.Fatal("HTTP without durable attempt")
	}
	if _, e = s.pool.Exec(ctx, `DROP TRIGGER reject_source_attempt ON collection_run`); e != nil {
		t.Fatal(e)
	}
	v.Enabled = false
	v, e = s.SaveSourceConfiguration(ctx, p, v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = service.Collect(ctx, p, v.ID, v.Revision); e == nil || calls.Load() != n {
		t.Fatal("disabled source execution")
	}
}
func TestIntegrationSourceScheduleScopeStopAndRecovery(t *testing.T) {
	s, _, v := sourceFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	service, admission, calls := sourceAPI(t, s, v, nil)
	profile := scheduler.Profile{CustomerID: v.CustomerID, EnvironmentID: v.EnvironmentID, ClusterID: v.ClusterID, CollectionSource: v, Collectors: api.CollectorIDs(), Interval: 60, Budget: 20, Enabled: true, Authorized: true}
	profile, e := s.SaveSchedule(ctx, actor, profile)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE collection_schedule SET next_due=clock_timestamp()-interval '1 second' WHERE id=$1`, profile.ID); e != nil {
		t.Fatal(e)
	}
	scheduled := collection.WithRequest(ctx, collection.Request{Source: "scheduled", ScheduleID: profile.ID, Revision: profile.Revision, Collectors: api.CollectorIDs(), Budget: 20 * time.Second})
	run, e := service.CollectSource(scheduled, actor, profile)
	if e != nil || run.Source != "scheduled" || run.ScheduleID != profile.ID || run.State != "completed" {
		t.Fatal("scheduled attempt", run, e)
	}
	if e = s.CompleteSchedule(ctx, profile, run, nil, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	snap, e := s.Schedules(ctx, actor)
	if e != nil || len(snap.Profiles) != 1 || snap.Profiles[0].State != "completed" {
		t.Fatal("source status", snap, e)
	}
	n := calls.Load()
	if e = s.SetScheduleControl(ctx, actor, scheduler.Control{Kind: "global", Action: "stop"}, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	admission.EmergencyStop(true)
	if _, e = service.Collect(ctx, actor, v.ID, 1); e == nil || calls.Load() != n {
		t.Fatal("stop bypass")
	}
	if e = s.SetScheduleControl(ctx, actor, scheduler.Control{Kind: "global", Action: "release"}, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	admission.EmergencyStop(false)
	v, e = s.SaveSourceConfiguration(ctx, actor, v)
	if e != nil {
		t.Fatal(e)
	}
	snap, e = s.Schedules(ctx, actor)
	if e != nil || snap.Profiles[0].Enabled || snap.Profiles[0].Authorized {
		t.Fatal("revision retained scheduling authority", e)
	}
	if _, e = service.CollectSource(scheduled, actor, profile); e == nil || calls.Load() != n {
		t.Fatal("queued stale authority")
	}
	forged := v
	forged.EnvironmentID = "00000000-0000-0000-0000-000000000001"
	if _, e = s.SaveSourceConfiguration(ctx, actor, forged); e == nil {
		t.Fatal("cross environment")
	}
	if _, e = s.SourceHistory(ctx, workspace.Principal{}, v, time.Now().UTC()); !errors.Is(e, workspace.ErrDenied) {
		t.Fatal("anonymous history", e)
	}
	if _, e = s.pool.Exec(ctx, `INSERT INTO collection_source(id,revision,customer_id,environment_id,cluster_id,adapter_id,credential_reference,enabled,actor) VALUES(gen_random_uuid(),1,$1,$2,$3,'vicidial.api','test',true,$4)`, v.CustomerID, forged.EnvironmentID, v.ClusterID, actor.ID); e == nil {
		t.Fatal("SQL owner escape")
	}
	// Interrupted source attempts are finalized without replay, using NW010 recovery.
	current, e := s.CollectionSource(ctx, actor, v.ID, v.Revision)
	if e != nil {
		t.Fatal(e)
	}
	interrupted, e := s.BeginSourceCollection(ctx, actor, current, api.CollectorIDs())
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RecoverCollections(ctx); e != nil {
		t.Fatal(e)
	}
	var state string
	if e = s.pool.QueryRow(ctx, `SELECT state FROM collection_run WHERE id=$1`, interrupted.ID).Scan(&state); e != nil || state != "interrupted" || calls.Load() != n {
		t.Fatal("recovery replay", state, e)
	}
	if _, e = s.SourceConfiguration(ctx, actor, collection.Source{CustomerID: v.CustomerID, EnvironmentID: v.EnvironmentID, ClusterID: "00000000-0000-0000-0000-000000000001"}); e == nil {
		t.Fatal("missing source")
	}
}

func TestIntegrationSourceInFlightStopAndCatalogRotation(t *testing.T) {
	for _, mode := range []string{"stop", "rotation"} {
		t.Run(mode, func(t *testing.T) {
			s, _, v := sourceFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			service, admission, calls, catalog := sourceAPICatalog(t, s, v, func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				select {
				case <-release:
					_, _ = w.Write([]byte(apiVersionBody))
				case <-r.Context().Done():
				}
			})
			defer close(release)
			type outcome struct {
				run collection.Run
				err error
			}
			done := make(chan outcome, 1)
			go func() {
				r, e := service.Collect(context.Background(), workspace.Principal{ID: workspace.OperatorID}, v.ID, v.Revision)
				done <- outcome{r, e}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("request barrier")
			}
			if mode == "stop" {
				admission.EmergencyStop(true)
			} else {
				data, e := os.ReadFile(catalog)
				if e != nil {
					t.Fatal(e)
				}
				data = []byte(strings.Replace(string(data), "synthetic-secret-only", "rotated-synthetic-secret", 1))
				if e = os.WriteFile(catalog, data, 0600); e != nil {
					t.Fatal(e)
				}
				// Release a valid response only after the grant is revoked/rotated.
				release <- struct{}{}
			}
			select {
			case got := <-done:
				if got.err != nil || got.run.State == "completed" || calls.Load() != 1 {
					t.Fatalf("unsafe outcome %s %v calls%d", got.run.State, got.err, calls.Load())
				}
				for _, r := range got.run.Results {
					if len(r.Observations) != 0 {
						t.Fatal("invalidated response retained")
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancel/rotation did not terminate")
			}
			if n, q := admission.Capacity(); n != 0 || q != 0 {
				t.Fatalf("capacity leak %d/%d", n, q)
			}
			h, e := s.SourceHistory(context.Background(), workspace.Principal{ID: workspace.OperatorID}, v, time.Now().UTC())
			if e != nil || len(h.Latest) != 0 {
				t.Fatal("invalid evidence persisted", e)
			}
		})
	}
}

func TestIntegrationSourceConcurrentRevisionAndScheduleSave(t *testing.T) {
	s, _, v := sourceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := workspace.Principal{ID: workspace.OperatorID}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SELECT id FROM cluster WHERE id=$1 FOR UPDATE`, v.ClusterID); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, e := s.SaveSchedule(ctx, p, scheduler.Profile{CustomerID: v.CustomerID, EnvironmentID: v.EnvironmentID, ClusterID: v.ClusterID, CollectionSource: v, Collectors: api.CollectorIDs(), Interval: 120, Budget: 20, Enabled: true, Authorized: true})
		done <- e
	}()
	// Synchronize on PostgreSQL's lock wait, rather than guessing thread timing.
	for {
		var waiting bool
		e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE 'SELECT id FROM cluster WHERE id=%FOR UPDATE%')`).Scan(&waiting)
		if e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("lock barrier", ctx.Err())
		}
	}
	if _, e = tx.Exec(ctx, `INSERT INTO collection_source(id,revision,customer_id,environment_id,cluster_id,adapter_id,credential_reference,enabled,actor) SELECT id,revision+1,customer_id,environment_id,cluster_id,adapter_id,credential_reference,enabled,actor FROM collection_source WHERE id=$1 AND revision=$2`, v.ID, v.Revision); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e == nil {
		t.Fatal("schedule accepted obsolete source revision after lock wait")
	}
	var count int
	if e = s.pool.QueryRow(ctx, `SELECT count(*) FROM collection_schedule WHERE source_id=$1 AND enabled`, v.ID).Scan(&count); e != nil || count != 0 {
		t.Fatal("obsolete schedule persisted", count, e)
	}
}
