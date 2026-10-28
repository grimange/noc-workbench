package web

import (
	"noc-workbench/internal/collectors/baseline"
	"testing"
	"time"
)

func TestConsolePresentationEvidenceStates(t *testing.T) {
	at := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	d := runtimeData{Enabled: true, LastObservation: at.Add(-2 * time.Minute)}
	r := resourceData{Current: true, UnitsAvailable: true, Status: map[string]string{"units_status": "observed"}, Units: []baseline.Unit{{Active: "failed"}}}
	v := presentation(r, d, at)
	if v.Availability != "Unknown" || v.Issues != "1 failed units" || v.Attention != 2 {
		t.Fatal(v)
	}
	r.UnitsAvailable = false
	if presentation(r, d, at).Issues != "Unknown" {
		t.Fatal("unsupported unit evidence")
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

func TestPersistentAndTransientStorage(t *testing.T) {
	for _, source := range []string{"tmpfs", "devtmpfs", "proc", "sysfs"} {
		if !transientFilesystem(source) {
			t.Fatal(source)
		}
	}
	for _, mount := range []string{"/data", "/var/lib/database", "/tmp"} {
		d := resourceData{Filesystems: []filesystemRow{{Mount: mount, Percent: "25%", State: "Current"}}}
		resourceGauges(&d)
		if !d.Gauges[2].Valid {
			t.Fatal("persistent mount hidden", mount)
		}
	}
	d := resourceData{Filesystems: []filesystemRow{{Mount: "/scratch", Technical: true, Percent: "25%", State: "Current"}}}
	resourceGauges(&d)
	if d.Gauges[2].Valid {
		t.Fatal("transient source presented as primary persistent storage")
	}
	d = resourceData{Metrics: []resourceMetric{{Name: "Load · 1 minute", Value: "1.25", State: "Current"}}}
	resourceGauges(&d)
	if d.Gauges[0].Valid || d.Gauges[0].Value != "Unknown" {
		t.Fatal("load fabricated CPU utilization")
	}
}
