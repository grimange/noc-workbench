package web

import (
	"noc-workbench/internal/collectors/baseline"
	"strings"
	"testing"
	"time"
)

func TestConsolePresentationEvidenceStates(t *testing.T) {
	at := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	d := runtimeData{Enabled: true, Outcome: "success", LastObservation: at.Add(-2 * time.Minute)}
	r := resourceData{Current: true, UnitsAvailable: true, Status: map[string]string{"units_status": "observed"}, Units: []baseline.Unit{{Active: "failed"}, {Active: "active", Sub: "exited"}}}
	v := presentation(r, d, at)
	if v.Availability != "Observed" || v.Issues != "1 failed units" || v.Age != "2 min ago" {
		t.Fatal(v)
	}
	r.UnitsAvailable = false
	if got := presentation(r, d, at); got.Issues != "Unknown" {
		t.Fatal(got)
	}
	for _, outcome := range []string{"transport_error", "permission_denied", "host_key_mismatch", "cancelled"} {
		d.Outcome = outcome
		if got := presentation(r, d, at); !strings.Contains(got.Availability, outcome) || strings.Contains(got.Availability, "unreachable") {
			t.Fatal(got)
		}
	}
	d.Outcome = "success"
	r.Current = false
	r.State = "Stale"
	if got := presentation(r, d, at); got.Availability != "Stale evidence" {
		t.Fatal(got)
	}
	d.Enabled = false
	if got := presentation(r, d, at); got.Availability != "Monitoring inactive" {
		t.Fatal(got)
	}
}
func TestConsoleGaugesRequireCurrentMeasurements(t *testing.T) {
	for _, state := range []string{"Stale", "Historical — monitoring paused", "Unknown", "Current"} {
		d := resourceData{Metrics: []resourceMetric{{Name: "CPU utilization (sampled counters)", Value: "25.0%", State: state}}, Filesystems: []filesystemRow{{Mount: "/dev/shm", Percent: "90%", State: "Current"}, {Mount: "/", Percent: "10%", Available: "900 KiB", State: state}}}
		resourceGauges(&d)
		if len(d.Gauges) != 3 || d.Gauges[0].Valid != (state == "Current") || d.Gauges[2].Valid != (state == "Current") || d.Gauges[1].Valid {
			t.Fatal(d)
		}
		if len(d.PrimaryFilesystems) != 1 || d.PrimaryFilesystems[0].Mount != "/" {
			t.Fatal(d)
		}
	}
	for _, bad := range []string{"NaN%", "101%", "-1%", "invalid"} {
		d := resourceData{Metrics: []resourceMetric{{Name: "CPU utilization (sampled counters)", Value: bad, State: "Current"}}}
		resourceGauges(&d)
		if d.Gauges[0].Valid {
			t.Fatal(d)
		}
	}
}
