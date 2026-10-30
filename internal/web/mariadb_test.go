package web

import (
	"noc-workbench/internal/collectors/services"
	"noc-workbench/internal/health"
	"noc-workbench/internal/integrations/mariadb"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"testing"
	"time"
)

func TestMariaDBCurrentEvidenceAndIndependentProcessState(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := func() (mariadb.History, health.Input, runtimeData) {
		h := mariadb.History{Samples: []mariadb.Sample{{Snapshot: mariadb.Snapshot{Protocol: 1, Status: "ready", Version: "10.11.15-MariaDB-log", Identity: "database.example.invalid", ActivityStatus: "ready", Replication: "ready", Metrics: map[string]uint64{"Threads_connected": 3}}, At: now, Received: now, ProfileID: "profile", EndpointID: "endpoint", ProfileVersion: 1, TTL: 180}}, Attempt: mariadb.Attempt{At: now, Outcome: "success"}}
		in := health.Input{At: now.Add(time.Second), Active: true, Trusted: true, Authority: map[string]int64{"profile": 1}}
		rt := runtimeData{Enabled: true, Profile: scheduler.Profile{Collectors: []string{mariadb.Collector}, Target: sshcli.Target{ProfileID: "profile", ProfileVersion: 1, EndpointID: "endpoint"}}, Rows: []runtimeRow{{Reading: services.Reading{Signal: services.Signal{ID: "database"}}, State: "Running"}}}
		return h, in, rt
	}
	h, in, rt := base()
	v := mariaDBView(h, in, rt, true)
	if !v.Current || v.Role != "Unknown" || v.Replication != "No local replica channels configured" || v.Process != "Running" {
		t.Fatalf("current %+v", v)
	}
	if v.Metrics[0].Value != "3" || v.Metrics[1].Value != "Unavailable" {
		t.Fatal("missing metric fabricated")
	}
	h.Samples[0].Snapshot.ActivityStatus = "permission_denied"
	h.Attempt.Outcome = "partial"
	h.Attempt.Codes = []string{"activity_permission_denied", "missing_metrics"}
	partial := mariaDBView(h, in, rt, true)
	if !partial.Current || partial.Readiness != "Ready — authenticated connection and SELECT 1 succeeded" || partial.Sample.Snapshot.ActivityStatus != "permission_denied" {
		t.Fatalf("activity failure erased readiness %+v", partial)
	}
	h, in, rt = base()
	cases := map[string]func(*mariadb.History, *health.Input, *runtimeData){
		"expired":        func(_ *mariadb.History, i *health.Input, _ *runtimeData) { i.At = now.Add(180 * time.Second) },
		"future":         func(_ *mariadb.History, i *health.Input, _ *runtimeData) { i.At = now.Add(-time.Second) },
		"receive_future": func(h *mariadb.History, _ *health.Input, _ *runtimeData) { h.Samples[0].Received = now.Add(time.Hour) },
		"new_failed_attempt": func(h *mariadb.History, _ *health.Input, _ *runtimeData) {
			h.Attempt = mariadb.Attempt{At: now.Add(time.Second), Outcome: "failed", Codes: []string{"authentication_denied"}}
		},
		"new_profile":      func(_ *mariadb.History, i *health.Input, _ *runtimeData) { i.Authority["profile"] = 2 },
		"untrusted":        func(_ *mariadb.History, i *health.Input, _ *runtimeData) { i.Trusted = false },
		"inactive":         func(_ *mariadb.History, i *health.Input, _ *runtimeData) { i.Active = false },
		"paused":           func(_ *mariadb.History, _ *health.Input, r *runtimeData) { r.Paused = true },
		"disabled":         func(_ *mariadb.History, _ *health.Input, r *runtimeData) { r.Enabled = false },
		"removed":          func(_ *mariadb.History, _ *health.Input, r *runtimeData) { r.Profile.Collectors = nil },
		"endpoint_changed": func(_ *mariadb.History, _ *health.Input, r *runtimeData) { r.Profile.Target.EndpointID = "other" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h, i, r := base()
			mutate(&h, &i, &r)
			got := mariaDBView(h, i, r, true)
			if got.Current || got.State == "Current" || got.Role != "Unknown" {
				t.Fatalf("uncertain evidence current %+v", got)
			}
			if got.Sample == nil || got.Metrics[0].Value != "3" {
				t.Fatal("history lost")
			}
		})
	}
	h, in, rt = base()
	if mariaDBView(h, in, rt, false).Current {
		t.Fatal("revoked scope current")
	}
	// A running OS process must not establish database query readiness.
	h = mariadb.History{Attempt: mariadb.Attempt{At: now, Outcome: "failed", Codes: []string{"connection_unavailable"}}}
	v = mariaDBView(h, in, rt, true)
	if v.Current || v.Readiness != "connection_unavailable" || v.Process != "Running" {
		t.Fatalf("conflated signals %+v", v)
	}
}
