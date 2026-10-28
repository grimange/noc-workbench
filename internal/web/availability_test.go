package web

import (
	"noc-workbench/internal/collection"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"testing"
	"time"
)

func TestAvailabilityEvidence(t *testing.T) {
	at := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	target := sshcli.Target{AssetID: "asset", ProfileID: "profile", ProfileVersion: 2}
	run := func(code string, age time.Duration) collection.Run {
		return collection.Run{Target: target, StartedAt: at.Add(-age - time.Second), EndedAt: at.Add(-age), Results: []collection.Result{{TransportOutcome: code}}}
	}
	base := runtimeData{Enabled: true, Authorized: true, ConnectivityTTL: 180, Profile: scheduler.Profile{Target: target, Interval: 60}}
	tests := []struct {
		name             string
		codes            []string
		state, reason    string
		disabled, paused bool
		age              time.Duration
	}{
		{name: "success", codes: []string{"success"}, state: "Reachable"},
		{name: "two failures", codes: []string{"connection_timeout", "connection_refused"}, state: "SSH unreachable"},
		{name: "one failure", codes: []string{"connection_timeout"}, state: "Unknown"},
		{name: "transient", codes: []string{"connection_timeout", "success"}, state: "Reachable"},
		{name: "authentication", codes: []string{"authentication_failed", "connection_timeout"}, state: "Unknown", reason: "SSH authentication / authorization problem"},
		{name: "key", codes: []string{"host_key_mismatch", "connection_timeout"}, state: "Unknown", reason: "SSH host-key trust problem"},
		{name: "execution timeout", codes: []string{"execution_timeout", "execution_timeout"}, state: "Unknown"},
		{name: "disabled", codes: []string{"success"}, state: "Unknown", disabled: true},
		{name: "paused", codes: []string{"success"}, state: "Paused", paused: true},
		{name: "expired", codes: []string{"success"}, state: "Unknown", age: 4 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := base
			d.Enabled = !tt.disabled
			d.Paused = tt.paused
			for i, c := range tt.codes {
				d.Attempts = append(d.Attempts, run(c, tt.age+time.Duration(i+1)*time.Second))
			}
			state, _, reason, _, checked := availability(d, at)
			if len(d.Attempts) > 0 && !checked.Equal(d.Attempts[0].EndedAt) {
				t.Fatal("last completed check lost", checked)
			}
			if state != tt.state || tt.reason != "" && reason != tt.reason {
				t.Fatal(state, reason)
			}
		})
	}
	d := base
	d.Attempts = []collection.Run{run("success", time.Second)}
	d.Attempts[0].Target.ProfileVersion = 1
	if state, _, _, _, _ := availability(d, at); state != "Unknown" {
		t.Fatal("stale authorization", state)
	}
	d.Attempts[0] = run("success", time.Second)
	d.Authorized = false
	if state, _, _, _, _ := availability(d, at); state != "Unknown" {
		t.Fatal("revoked authority", state)
	}
}
func TestFleetAttentionFiltering(t *testing.T) {
	rows := []consoleServer{{View: consolePresentation{Availability: "Unknown"}}, {View: consolePresentation{Availability: "Reachable"}}, {View: consolePresentation{Availability: "SSH unreachable", Attention: 4}}, {View: consolePresentation{Availability: "Unknown", Attention: 3}}}
	selected, c, _ := fleetPage(rows, "", "attention", 0)
	if len(selected) != 4 || selected[0].View.Availability != "SSH unreachable" || c.Reachable != 1 || c.Unreachable != 1 || c.Unknown != 2 {
		t.Fatal(selected, c)
	}
	selected, _, _ = fleetPage(rows, "attention", "name", 0)
	if len(selected) != 2 {
		t.Fatal(selected)
	}
	selected, _, _ = fleetPage(rows, "reachable", "name", 0)
	if len(selected) != 1 {
		t.Fatal(selected)
	}
}

func TestAvailabilityBlockedAndInFlight(t *testing.T) {
	at := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	target := sshcli.Target{AssetID: "asset", ProfileID: "profile", ProfileVersion: 2}
	good := collection.Run{Target: target, StartedAt: at.Add(-time.Minute), EndedAt: at.Add(-59 * time.Second), Results: []collection.Result{{TransportOutcome: "success"}}}
	d := runtimeData{Enabled: true, Authorized: true, ConnectivityTTL: 180, Profile: scheduler.Profile{Target: target}, Attempts: []collection.Run{{Target: target, StartedAt: at.Add(-time.Second)}, good}}
	state, _, _, _, checked := availability(d, at)
	if state != "Reachable" || !checked.Equal(good.EndedAt) {
		t.Fatal("in-progress erased completed evidence", state, checked)
	}
	d.Enabled = false
	d.Authorized = false
	d.AuthorizationDiagnostic = "SSH host-key trust problem"
	state, _, reason, priority, _ := availability(d, at)
	if state != "Unknown" || reason != d.AuthorizationDiagnostic || priority != 3 {
		t.Fatal("quarantine lost diagnostic", state, reason, priority)
	}
	d.AuthorizationDiagnostic = "SSH authentication / authorization problem"
	_, _, reason, priority, _ = availability(d, at)
	if reason != d.AuthorizationDiagnostic || priority != 3 {
		t.Fatal(reason, priority)
	}
	d.Enabled = true
	d.Authorized = true
	d.AuthorizationDiagnostic = ""
	d.Attempts = []collection.Run{good}
	for _, ttl := range []int{0, 60} {
		d.ConnectivityTTL = ttl
		if state, _, _, _, _ := availability(d, at); state != "Unknown" {
			t.Fatal("policy TTL", ttl, state)
		}
	}
	d.ConnectivityTTL = 180
	d.Attempts[0].EndedAt = at.Add(time.Second)
	if state, _, _, _, _ := availability(d, at); state != "Unknown" {
		t.Fatal("future evidence", state)
	}
}
func TestConnectivityOrderIndependent(t *testing.T) {
	if got := connectivity(collection.Run{Category: "parse_error", Results: []collection.Result{{TransportOutcome: "success"}}}); got != "success" {
		t.Fatal("parser failure erased SSH success", got)
	}
	for _, tt := range []struct {
		codes []string
		want  string
	}{
		{[]string{"connection_timeout", "permission_denied"}, "permission_denied"},
		{[]string{"permission_denied", "host_key_mismatch"}, "host_key_mismatch"},
		{[]string{"success", "connection_refused"}, "inconclusive"},
		{[]string{"execution_timeout", "dns_failure"}, "inconclusive"},
		{[]string{"connection_refused", "dns_failure"}, "connection_timeout"},
	} {
		for i := 0; i < 2; i++ {
			r := collection.Run{Results: []collection.Result{{TransportOutcome: tt.codes[i]}, {TransportOutcome: tt.codes[1-i]}}}
			if got := connectivity(r); got != tt.want {
				t.Fatal(tt.codes, got)
			}
		}
	}
	r := collection.Run{Category: "host_key_mismatch", Results: []collection.Result{{TransportOutcome: "permission_denied"}}}
	if connectivity(r) != "host_key_mismatch" {
		t.Fatal("lost first collector trust category")
	}
}

func TestLastCheckedNeverUsesSuccessfulObservationFallback(t *testing.T) {
	at := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	d := runtimeData{LastObservation: at.Add(-time.Minute)}
	v := presentation(resourceData{}, d, at)
	if !v.Checked.IsZero() || v.Age != "No completed check" {
		t.Fatal(v.Checked, v.Age)
	}
	d.Profile.Target.AssetID = "asset"
	d.AuthorizationDiagnostic = "SSH host-key trust problem"
	d.Attempts = []collection.Run{{Target: d.Profile.Target, StartedAt: at.Add(-time.Hour), EndedAt: at.Add(-time.Hour + time.Second)}}
	v = presentation(resourceData{}, d, at)
	if !v.Checked.Equal(d.Attempts[0].EndedAt) || v.Availability != "Unknown" {
		t.Fatal(v)
	}
}
