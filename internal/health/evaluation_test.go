package health

import (
	"math"
	"noc-workbench/internal/collection"
	"reflect"
	"testing"
	"time"
)

func fixture() Input {
	at := time.Date(2026, 1, 1, 9, 2, 0, 0, time.UTC)
	return Input{Scope: collection.HistoryScope{AssetID: "asset"}, At: at, Active: true, Trusted: true,
		Policies: []Policy{{ID: "policy", Revision: 1, Version: Version, Selector: "linux.memory", TTLSeconds: 180, Rule: "none", Enabled: true, CreatedAt: at.Add(-time.Hour)}},
		Evidence: []collection.Evidence{{Observation: collection.Observation{AssetID: "asset", Key: "linux.mem.available_bytes", CollectorID: "linux.memory", Quality: "valid", Unit: "bytes", Value: collection.Integer(500), ObservedAt: at.Add(-120 * time.Second), ReceivedAt: at.Add(-119 * time.Second)}, ID: "observation", RunID: "run"}}}
}
func TestFourDimensions(t *testing.T) {
	tests := []struct {
		name                   string
		edit                   func(*Input)
		fresh, quality, health string
	}{
		{"fresh", func(*Input) {}, "fresh", "valid", "unknown"},
		{"expiry equality", func(i *Input) { i.At = i.At.Add(time.Minute) }, "stale", "valid", "unknown"},
		{"beyond expiry", func(i *Input) { i.At = i.At.Add(time.Minute + time.Nanosecond) }, "stale", "valid", "unknown"},
		{"invalid", func(i *Input) { i.Evidence[0].Quality = "invalid" }, "unknown", "invalid", "unknown"},
		{"partial", func(i *Input) { i.Evidence[0].Quality = "partial" }, "unknown", "partial", "unknown"},
		{"unsupported", func(i *Input) { i.Evidence[0].Quality = "unsupported" }, "unknown", "unsupported", "unknown"},
		{"future observed", func(i *Input) { i.Evidence[0].ObservedAt = i.At.Add(time.Second) }, "unknown", "invalid", "unknown"},
		{"future received", func(i *Input) { i.Evidence[0].ReceivedAt = i.At.Add(time.Second) }, "unknown", "invalid", "unknown"},
		{"missing timestamp", func(i *Input) { i.Evidence[0].ObservedAt = time.Time{} }, "unknown", "invalid", "unknown"},
		{"clock ordering", func(i *Input) { i.Evidence[0].ReceivedAt = i.Evidence[0].ObservedAt.Add(-time.Second) }, "unknown", "invalid", "unknown"},
		{"unit mismatch", func(i *Input) { i.Evidence[0].Unit = "percent" }, "unknown", "invalid", "unknown"},
		{"disabled asset", func(i *Input) { i.Active = false }, "fresh", "valid", "unknown"},
		{"untrusted", func(i *Input) { i.Trusted = false }, "fresh", "valid", "unknown"},
		{"missing policy", func(i *Input) { i.Policies = nil }, "unknown", "valid", "unknown"},
		{"disabled policy", func(i *Input) { i.Policies[0].Enabled = false }, "unknown", "valid", "unknown"},
		{"degraded equality", func(i *Input) {
			i.Policies[0].Selector = "linux.mem.available_bytes"
			i.Policies[0].Rule = "memory_available_low"
			i.Policies[0].Threshold = 500
		}, "fresh", "valid", "degraded"},
		{"healthy resource", func(i *Input) {
			i.Policies[0].Selector = "linux.mem.available_bytes"
			i.Policies[0].Rule = "memory_available_low"
			i.Policies[0].Threshold = 499
		}, "fresh", "valid", "healthy"},
		{"stale rule", func(i *Input) {
			i.Policies[0].Selector = "linux.mem.available_bytes"
			i.Policies[0].Rule = "memory_available_low"
			i.Policies[0].Threshold = 500
			i.At = i.At.Add(time.Hour)
		}, "stale", "valid", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := fixture()
			tt.edit(&i)
			out, e := Evaluate(i)
			if e != nil {
				t.Fatal(e)
			}
			r := out.Readings[0]
			if r.Freshness != tt.fresh || r.Quality != tt.quality || r.Health != tt.health || out.Health != "unknown" {
				t.Fatalf("%+v", out)
			}
			again, e := Evaluate(i)
			if e != nil || !reflect.DeepEqual(again, out) {
				t.Fatal("nondeterministic")
			}
		})
	}
}
func TestFailuresDoNotRefreshEvidenceOrImplyHealth(t *testing.T) {
	for _, state := range []string{"failed", "interrupted", "cancelled", "partial", "completed", "running"} {
		for _, category := range []string{"authentication_failed", "host_key_mismatch", "connection_timeout", ""} {
			i := fixture()
			i.At = i.At.Add(time.Hour)
			i.LatestAttempt = &collection.Run{ID: "latest", State: state, Category: category, StartedAt: i.At.Add(-time.Minute), EndedAt: i.At.Add(-time.Second)}
			out, e := Evaluate(i)
			if e != nil || out.Health != "unknown" || out.Readings[0].Freshness != "stale" || out.Readings[0].Evidence.ObservedAt != i.Evidence[0].ObservedAt {
				t.Fatal(out, e)
			}
		}
	}
	i := fixture()
	i.Evidence = nil
	out, e := Evaluate(i)
	if e != nil || len(out.Readings) != 0 || out.Health != "unknown" {
		t.Fatal(out, e)
	}
}
func TestPolicyValidationPrecedenceAndCadence(t *testing.T) {
	i := fixture()
	i.IntervalSeconds = 86400
	p := i.Policies[0]
	p.Selector = "linux.mem.available_bytes"
	p.ID = "override"
	p.TTLSeconds = 60
	i.Policies = append(i.Policies, p)
	out, e := Evaluate(i)
	if e != nil || out.Readings[0].PolicyID != "override" || out.Readings[0].Freshness != "stale" || !out.Readings[0].CadenceConflict {
		t.Fatal(out, e)
	}
	for _, edit := range []func(*Policy){func(p *Policy) { p.Version = "v999" }, func(p *Policy) { p.TTLSeconds = 0 }, func(p *Policy) { p.Threshold = math.NaN() }, func(p *Policy) { p.Rule = "service_down" }, func(p *Policy) { p.Rule = "filesystem_used_high" }, func(p *Policy) { p.Selector = "linux.load.1m"; p.Rule = "memory_available_low" }} {
		v := p
		edit(&v)
		if v.Validate() == nil {
			t.Fatal("invalid policy accepted", v)
		}
	}
	i.Policies = append(i.Policies, p)
	if _, e := Evaluate(i); e == nil {
		t.Fatal("ambiguous policies")
	}
	i = fixture()
	i.Evidence = append(i.Evidence, i.Evidence[0])
	if _, e := Evaluate(i); e == nil {
		t.Fatal("duplicate series")
	}
	i = fixture()
	i.Policies[0].Selector = "linux.identity"
	i.Policies[0].TTLSeconds = 86400
	i.Evidence[0].CollectorID = "linux.identity"
	i.Evidence[0].Key = "linux.os.name"
	i.Evidence[0].Unit = "text"
	i.Evidence[0].Value = collection.Text("Synthetic Linux")
	i.At = i.At.Add(time.Hour)
	out, e = Evaluate(i)
	if e != nil || out.Readings[0].Freshness != "fresh" {
		t.Fatal(out, e)
	}
}

func TestQualityIndependentOfPolicyAndProvenance(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		for _, bad := range []func(*collection.Evidence){func(e *collection.Evidence) { e.Unit = "percent" }, func(e *collection.Evidence) { e.ObservedAt = time.Time{} }, func(e *collection.Evidence) { e.CollectorID = "linux.identity" }} {
			i := fixture()
			bad(&i.Evidence[0])
			if disabled {
				i.Policies[0].Enabled = false
			} else {
				i.Policies = nil
			}
			out, e := Evaluate(i)
			if e != nil || out.Readings[0].Quality != "invalid" || out.Readings[0].Freshness != "unknown" {
				t.Fatal(out, e)
			}
		}
	}
}
func TestFilesystemThresholdAndFutureCompletion(t *testing.T) {
	i := fixture()
	i.Evidence[0].Key = "linux.filesystem.utilization_percent"
	i.Evidence[0].CollectorID = "linux.filesystems"
	i.Evidence[0].Resource = "/synthetic mount"
	i.Evidence[0].Unit = "percent"
	i.Evidence[0].Value = collection.Integer(80)
	i.Policies[0].Selector = i.Evidence[0].Key
	i.Policies[0].Rule = "filesystem_used_high"
	i.Policies[0].Threshold = 80
	out, e := Evaluate(i)
	if e != nil || out.Readings[0].Health != "degraded" {
		t.Fatal(out, e)
	}
	i.Evidence[0].Value = collection.Integer(79)
	out, e = Evaluate(i)
	if e != nil || out.Readings[0].Health != "healthy" {
		t.Fatal(out, e)
	}
	i.LatestAttempt = &collection.Run{StartedAt: i.At.Add(-time.Second), EndedAt: i.At.Add(time.Second), State: "completed", SuccessCount: 5}
	out, e = Evaluate(i)
	if e != nil || out.Collection != "running" || out.LatestAttempt.SuccessCount != 0 {
		t.Fatal(out, e)
	}
	i.Evidence = make([]collection.Evidence, 2049)
	if _, e = Evaluate(i); e == nil {
		t.Fatal("unbounded input")
	}
}

func TestEvidenceAuthorityRevision(t *testing.T) {
	for _, revision := range []int64{0, 1, 2} {
		i := fixture()
		i.Evidence[0].ProfileID = "profile"
		i.Evidence[0].ProfileVersion = 1
		i.Authority = map[string]int64{}
		if revision != 0 {
			i.Authority["profile"] = revision
		}
		i.Policies[0].Selector = i.Evidence[0].Key
		i.Policies[0].Rule = "memory_available_low"
		i.Policies[0].Threshold = 499
		out, e := Evaluate(i)
		if e != nil {
			t.Fatal(e)
		}
		want := "unknown"
		if revision == 1 {
			want = "healthy"
		}
		if out.Readings[0].Health != want {
			t.Fatal(out)
		}
	}
}
