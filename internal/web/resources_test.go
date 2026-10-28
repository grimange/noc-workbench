package web

import (
	"fmt"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/baseline"
	"noc-workbench/internal/health"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"strings"
	"testing"
	"time"
)

func TestResourceCurrentHistoricalAndUnavailable(t *testing.T) {
	at := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	input := health.Input{At: at, Active: true, Trusted: true, Authority: map[string]int64{"p": 1}}
	d := runtimeData{Enabled: true, Profile: scheduler.Profile{Target: sshcli.Target{ProfileID: "p", ProfileVersion: 1}}}
	makeReading := func(key, run string, v collection.Value) health.Reading {
		ev := collection.Evidence{}
		ev.Key = baseline.Prefix + key
		ev.RunID = run
		ev.ProfileID = "p"
		ev.ProfileVersion = 1
		ev.CollectorID = baseline.Collector
		ev.ObservedAt = at
		ev.Value = v
		ev.Unit = "percent"
		return health.Reading{Evidence: ev, Quality: "valid", Freshness: "fresh"}
	}
	cpu := makeReading("cpu_percent", "old", collection.Number(25))
	pressure := makeReading("pressure_some_percent", "old", collection.Number(1))
	status := makeReading("status", "old", collection.Text(`{"units_status":"observed"}`))
	out := health.Evaluation{Readings: []health.Reading{cpu, pressure, status}}
	if got := resources(input, out, d); got.CPUText != "25.0%" {
		t.Fatal(got)
	}
	// New successful sample lacks CPU/pressure. Old values retain their timestamps
	// and cannot remain current even before their original freshness TTL expires.
	out.Readings[2].Evidence.RunID = "new"
	out.Readings[2].Evidence.ObservedAt = at.Add(time.Minute)
	out.Readings[2].Evidence.Value = collection.Text(`{"cpu":"unavailable","pressure":"unavailable"}`)
	got := resources(input, out, d)
	if got.CPUText != "Unknown" || !strings.HasPrefix(got.Metrics[0].State, "Historical") || !got.Metrics[0].At.Equal(at) {
		t.Fatal(got)
	}
	d.Enabled = false
	if got = resources(input, out, d); got.Current || got.CPUText != "Unknown" {
		t.Fatal(got)
	}
	d.Enabled = true
	out.Readings[0].Freshness = "stale"
	out.Readings[2].Freshness = "stale"
	if got = resources(input, out, d); got.Current || got.CPUText != "Unknown" {
		t.Fatal(got)
	}
	out.Readings[0].Freshness = "fresh"
	out.Readings[2] = status
	input.LatestAttempt = &collection.Run{StartedAt: at.Add(time.Minute), Results: []collection.Result{{CollectorID: baseline.Collector, Outcome: "transport_error"}}}
	if got = resources(input, out, d); got.Current || got.CPUText != "Unknown" || !strings.Contains(got.Metrics[0].State, "transport_error") {
		t.Fatal(got)
	}
}

func TestResourceChunkFreshnessIndependentOfStatus(t *testing.T) {
	at := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	in := health.Input{At: at, Active: true, Trusted: true, Authority: map[string]int64{"p": 1}}
	d := runtimeData{Enabled: true, Outcome: "success", Profile: scheduler.Profile{Target: sshcli.Target{ProfileID: "p", ProfileVersion: 1}}}
	makeReading := func(key, resource, value string) health.Reading {
		ev := collection.Evidence{}
		ev.Key = baseline.Prefix + key
		ev.Resource = resource
		ev.RunID = "run"
		ev.ProfileID = "p"
		ev.ProfileVersion = 1
		ev.CollectorID = baseline.Collector
		ev.ObservedAt = at
		ev.Value = collection.Text(value)
		return health.Reading{Evidence: ev, Quality: "valid", Freshness: "fresh"}
	}
	out := health.Evaluation{Readings: []health.Reading{makeReading("status", "", `{"units_status":"observed"}`)}}
	for i := 0; i < 32; i++ {
		v := "[]"
		if i == 0 {
			v = `[{"Name":"synthetic.service","Active":"failed"}]`
		}
		out.Readings = append(out.Readings, makeReading("units", fmt.Sprintf("%02d", i), v))
	}
	got := resources(in, out, d)
	if !got.Current || !got.UnitsAvailable || presentation(got, d, at).Issues != "1 failed units" {
		t.Fatal(got)
	}
	out.Readings[1].Freshness = "stale"
	got = resources(in, out, d)
	if !got.Current || got.UnitsAvailable || got.UnitsState == "Current" || presentation(got, d, at).Issues != "Unknown" || len(got.Units) != 1 {
		t.Fatal(got)
	}
	// Retain historical unit facts; one expired or unauthorized chunk cannot create
	// a fresh summary even while the independent status observation remains fresh.
	out.Readings[1].Freshness = "fresh"
	out.Readings[1].Evidence.ProfileVersion = 2
	got = resources(in, out, d)
	if got.UnitsAvailable || got.UnitsState == "Current" {
		t.Fatal(got)
	}
	out.Readings = out.Readings[:len(out.Readings)-1]
	if got = resources(in, out, d); got.UnitsAvailable || got.UnitsState != "Unknown — incomplete snapshot" {
		t.Fatal(got)
	}
}
