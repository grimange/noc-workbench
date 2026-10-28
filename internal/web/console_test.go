package web

import (
	"encoding/json"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/services"
	"noc-workbench/internal/health"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"testing"
	"time"
)

func TestConsoleRuntimeSemantics(t *testing.T) {
	at := time.Date(2026, 10, 28, 0, 39, 12, 123456789, time.UTC)
	sig := services.Signal{ID: "asterisk", Binary: "present", Unit: "loaded", Active: "stopped", Process: "observed", Support: "linux", UnitName: "asterisk.service"}
	encoded, _ := json.Marshal(sig)
	ev := collection.Evidence{ID: "original-observation"}
	ev.ProfileID = "profile"
	ev.ProfileVersion = 3
	ev.Key = services.Key
	ev.Resource = sig.ID
	ev.CollectorID = services.Collector
	ev.CollectorVersion = services.Version
	ev.Value = collection.Text(string(encoded))
	ev.ObservedAt = at

	input := health.Input{At: at, Active: true, Trusted: true, Authority: map[string]int64{"profile": 3}}
	for _, tc := range []struct {
		name                              string
		enabled                           bool
		freshness, quality, outcome, want string
	}{
		{"running process inactive unit", true, "fresh", "valid", "success", "Process running"},
		{"disabled preserves history", false, "fresh", "valid", "success", "Unknown"},
		{"stale preserves history", true, "stale", "valid", "success", "Stale"},
		{"failed retains recent valid reading", true, "fresh", "valid", "transport_error", "Process running"},
		{"invalid evidence", true, "fresh", "invalid", "success", "Unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &collection.Run{State: "completed", Results: []collection.Result{{CollectorID: services.Collector, Outcome: tc.outcome}}}
			d := runtimeData{Enabled: tc.enabled, Status: "Monitoring disabled", Profile: scheduler.Profile{Target: sshcli.Target{ProfileID: "profile", ProfileVersion: 3}}, Attempt: run}
			got := runtimeReadings(d, input, health.Evaluation{Readings: []health.Reading{{Evidence: ev, Freshness: tc.freshness, Quality: tc.quality}}})
			if len(got.Rows) != 1 || got.Rows[0].State != tc.want || got.Rows[0].Reading.Runtime != "Running" || got.Rows[0].Unit != "asterisk.service · stopped" || got.Outcome != tc.outcome || !got.LastObservation.Equal(at) || got.Rows[0].Evidence.ID != ev.ID {
				t.Fatalf("lost semantics/provenance: %+v", got)
			}
		})
	}
	d := runtimeReadings(runtimeData{Enabled: true, Attempt: &collection.Run{State: "failed", Results: []collection.Result{{CollectorID: services.Collector, Outcome: "transport_error"}}}}, input, health.Evaluation{})
	if d.Outcome != "transport_error" || d.Summary != "Collection transport_error" {
		t.Fatal("failure with no observations", d)
	}
	if localTime(at) != "Oct 28, 2026, 8:39:12 AM PHT" || utcTime(at) != "2026-10-28T00:39:12.123456789Z" {
		t.Fatal("timestamp conversion", localTime(at), utcTime(at))
	}
}

func TestConsoleStoppedUnsupportedAndRevokedAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, process, unit, active, support, want string
		trusted                                    bool
	}{
		{"stopped", "not_observed", "loaded", "stopped", "linux", "Stopped", true},
		{"running unit only", "not_observed", "loaded", "running", "linux", "Running", true},
		{"unsupported", "unavailable", "unavailable", "unavailable", "unsupported", "Unsupported", true},
		{"no unit authority", "not_observed", "unavailable", "unavailable", "linux", "Unknown", true},
		{"revoked trust", "observed", "loaded", "running", "linux", "Unknown", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := services.Signal{ID: "asterisk", Binary: "present", Unit: tc.unit, Active: tc.active, Process: tc.process, Support: tc.support, UnitName: "asterisk.service"}
			encoded, _ := json.Marshal(sig)
			ev := collection.Evidence{}
			ev.Key = services.Key
			ev.Resource = sig.ID
			ev.CollectorID = services.Collector
			ev.CollectorVersion = services.Version
			ev.Value = collection.Text(string(encoded))
			ev.ProfileID = "p"
			ev.ProfileVersion = 2
			input := health.Input{Active: true, Trusted: tc.trusted, Authority: map[string]int64{"p": 2}}
			d := runtimeData{Enabled: true, Profile: scheduler.Profile{Target: sshcli.Target{ProfileID: "p", ProfileVersion: 2}}}
			got := runtimeReadings(d, input, health.Evaluation{Readings: []health.Reading{{Evidence: ev, Freshness: "fresh", Quality: "valid"}}})
			if len(got.Rows) != 1 || got.Rows[0].State != tc.want {
				t.Fatalf("%+v", got)
			}
		})
	}
}
