package health

import (
	"noc-workbench/internal/collection"
	"testing"
	"time"
)

func TestContinuityIntentAndProgress(t *testing.T) {
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	p := Policy{Threshold: 180, CreatedAt: at.Add(-time.Hour)}
	base := ScheduleProgress{Exists: true, Expected: true, Authorized: true, Enabled: true, Interval: 60, Budget: 40, CompletedAt: at.Add(-180 * time.Second)}
	tests := []struct {
		name   string
		mutate func(*ScheduleProgress)
		want   string
	}{
		{"three missed opportunities", func(s *ScheduleProgress) {}, "degraded"},
		{"ordinary delay", func(s *ScheduleProgress) { s.CompletedAt = at.Add(-179 * time.Second) }, "healthy"},
		{"unexpected disabled", func(s *ScheduleProgress) { s.Enabled = false }, "degraded"},
		{"intentional disabled", func(s *ScheduleProgress) { s.Enabled = false; s.Expected = false }, "unknown"},
		{"pause", func(s *ScheduleProgress) { s.Paused = true }, "unknown"},
		{"stop", func(s *ScheduleProgress) { s.Stopped = true }, "unknown"},
		{"revoked", func(s *ScheduleProgress) { s.Authorized = false }, "unknown"},
		{"guard", func(s *ScheduleProgress) { s.Guard = true }, "degraded"},
		{"local failure", func(s *ScheduleProgress) { s.Category = "guard_storage_failed" }, "degraded"},
		{"dispatch alone", func(s *ScheduleProgress) { s.LastDispatch = at }, "degraded"},
		{"recovered", func(s *ScheduleProgress) { s.CompletedAt = at }, "healthy"},
		{"long valid budget", func(s *ScheduleProgress) { s.Budget = 200 }, "healthy"},
		{"future", func(s *ScheduleProgress) { s.CompletedAt = at.Add(time.Second) }, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := base
			tt.mutate(&s)
			got, _ := Continuity(s, p, at)
			if got != tt.want {
				t.Fatalf("%s want %s", got, tt.want)
			}
		})
	}
}
func TestOperationalReadingsFreshnessAndLag(t *testing.T) {
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, key := range []string{"monitoring.continuity", "server.ssh_unreachable", "service.runtime.unavailable", "service.ami.disconnected", "service.authentication.repeated", "database.query.failed", "database.replication.failed", "database.replication.lag_seconds"} {
		p := Policy{ID: "policy", Revision: 1, Version: Version, Selector: key, TTLSeconds: 180, Enabled: true, CreatedAt: at.Add(-time.Hour), Rule: "condition_failed"}
		if key == "monitoring.continuity" {
			p.Rule = "monitoring_interrupted"
			p.Threshold = 180
		}
		if key == "database.replication.lag_seconds" {
			p.Rule = "value_high"
			p.Threshold = 30
		}
		if err := p.Validate(); err != nil {
			t.Fatal(key, err)
		}
		n := uint64(30)
		c := Condition{State: "degraded", Value: &n, Evidence: collection.Evidence{Observation: collection.Observation{Key: key, Quality: "valid", ObservedAt: at, ReceivedAt: at}}}
		r := OperationalReadings([]Condition{c}, []Policy{p}, at)[0]
		if r.Health != "degraded" || r.Freshness != "fresh" {
			t.Fatal(r)
		}
		r = OperationalReadings([]Condition{c}, []Policy{p}, at.Add(180*time.Second))[0]
		if r.Health != "unknown" || r.Freshness != "stale" || !r.Evidence.ObservedAt.Equal(at) {
			t.Fatal(r)
		}
		c.State = "unknown"
		c.Value = nil
		if r = OperationalReadings([]Condition{c}, []Policy{p}, at)[0]; r.Health != "unknown" {
			t.Fatal("missing is not recovery", r)
		}
	}
}
func TestConnectivityExcludesNonNetworkFailures(t *testing.T) {
	for _, code := range []string{"authentication_failed", "permission_denied", "host_key_mismatch", "credential_unavailable", "guard_conflict", "guard_storage_failed", "cancelled", "parser_failure"} {
		r := collection.Run{Results: []collection.Result{{TransportOutcome: code}}}
		if NetworkFailure(Connectivity(r)) {
			t.Fatal(code)
		}
	}
	for _, code := range []string{"connection_timeout", "connection_refused", "dns_failure"} {
		if !NetworkFailure(Connectivity(collection.Run{Results: []collection.Result{{TransportOutcome: code}}})) {
			t.Fatal(code)
		}
	}
	if NetworkFailure(Connectivity(collection.Run{Results: []collection.Result{{TransportOutcome: "success"}, {TransportOutcome: "connection_timeout"}}})) {
		t.Fatal("mixed transport outcomes are inconclusive")
	}
}
func TestPersistentFilesystemSelection(t *testing.T) {
	at := time.Now().UTC()
	for _, tt := range []struct {
		device, mount string
		want          bool
	}{{"tmpfs", "/run/credentials/service", false}, {"tmpfs", "/unfamiliar", false}, {"proc", "/proc", false}, {"cgroup2", "/sys/fs/cgroup", false}, {"/dev/synthetic", "/unfamiliar", true}, {"server:/volume", "/data", true}, {"overlay", "/", true}, {"/dev/synthetic", "/run/persistent", true}, {"/dev/synthetic", "/run/credentials/service", false}} {
		e := collection.Evidence{RunID: "run", Observation: collection.Observation{Key: "linux.filesystem.utilization_percent", Resource: tt.mount, ObservedAt: at, Quality: "valid"}}
		i := e
		i.Key = "linux.filesystem.identifier"
		i.Value = collection.Text(tt.device)
		if got := PersistentFilesystem(e, []collection.Evidence{i}); got != tt.want {
			t.Fatal(tt, got)
		}
		i.RunID = "old"
		if PersistentFilesystem(e, []collection.Evidence{i}) {
			t.Fatal("cross snapshot identifier")
		}
	}
}
