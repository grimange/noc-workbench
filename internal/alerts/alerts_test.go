package alerts

import (
	"noc-workbench/internal/health"
	"reflect"
	"testing"
	"time"
)

func TestDeterministicLifecycle(t *testing.T) {
	at := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	rule := Rule{ID: "r", PolicyID: "p", Revision: 1, Severity: "warning", DebounceSeconds: 60, Enabled: true}
	r := health.Reading{PolicyID: "p", PolicyRevision: 1, Quality: "valid", Freshness: "fresh", Health: "degraded"}
	prev := Instance{}
	steps := []struct {
		delta                          int
		fresh, condition, state, event string
	}{
		{0, "fresh", "degraded", "pending", "pending"}, {59, "fresh", "degraded", "pending", ""}, {60, "fresh", "degraded", "active", "active"}, {61, "fresh", "degraded", "active", ""}, {180, "stale", "unknown", "active", "evidence_changed"}, {190, "unknown", "unknown", "active", "evidence_changed"}, {200, "fresh", "healthy", "resolved", "resolved"},
	}
	for _, step := range steps {
		r.Freshness = step.fresh
		r.Health = step.condition
		now := at.Add(time.Duration(step.delta) * time.Second)
		next, event, e := Reduce(prev, rule, r, now)
		if e != nil || next.State != step.state || event != step.event {
			t.Fatalf("%+v => %+v %s %v", step, next, event, e)
		}
		again, event2, _ := Reduce(prev, rule, r, now)
		if !reflect.DeepEqual(next, again) || event != event2 {
			t.Fatal("nondeterministic")
		}
		prev = next
	}
}
func TestRevisionUncertaintyAndAcknowledgment(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rule := Rule{ID: "r", PolicyID: "p", Revision: 1, Severity: "critical", DebounceSeconds: 10, Enabled: true}
	r := health.Reading{PolicyID: "p", PolicyRevision: 1, Quality: "valid", Freshness: "fresh", Health: "degraded"}
	a, _, _ := Reduce(Instance{}, rule, r, at)
	r.PolicyRevision++
	a, _, _ = Reduce(a, rule, r, at.Add(10*time.Second))
	if a.State != "pending" || !a.PendingAt.Equal(at.Add(10*time.Second)) {
		t.Fatal(a)
	}
	a, _, _ = Reduce(a, rule, r, at.Add(20*time.Second))
	a.AcknowledgedAt = &at
	a.AcknowledgedBy = "operator"
	rule.Enabled = false
	a, _, _ = Reduce(a, rule, r, at.Add(21*time.Second))
	if a.State != "active" || a.EvidenceState != "disabled" || a.AcknowledgedAt == nil {
		t.Fatal(a)
	}
	rule.Enabled = true
	r.PolicyID = "foreign"
	r.Health = "healthy"
	a, _, _ = Reduce(a, rule, r, at.Add(22*time.Second))
	if a.State != "active" {
		t.Fatal("foreign policy resolved")
	}
	r.PolicyID = "p"
	r.Quality = "invalid"
	a, _, _ = Reduce(a, rule, r, at.Add(23*time.Second))
	if a.State != "active" {
		t.Fatal("invalid evidence resolved")
	}
}
func TestRuleValidation(t *testing.T) {
	for _, r := range []Rule{{Revision: 0, Severity: "info"}, {Revision: 1, Severity: "down"}, {Revision: 1, Severity: "info", DebounceSeconds: -1}, {Revision: 1, Severity: "info", DebounceSeconds: 86401}} {
		if r.Validate() == nil {
			t.Fatal(r)
		}
	}
}
func TestDebounceResetsAcrossExpiredSamplingGap(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rule := Rule{ID: "r", PolicyID: "p", Revision: 1, Severity: "warning", Enabled: true, DebounceSeconds: 10}
	r := health.Reading{PolicyID: "p", PolicyRevision: 1, Quality: "valid", Freshness: "fresh", Health: "degraded", ExpiresAt: at.Add(5 * time.Second)}
	r.Evidence.ObservedAt = at
	prev, _, _ := Reduce(Instance{}, rule, r, at)
	r.Evidence.ObservedAt = at.Add(9 * time.Second)
	r.ExpiresAt = at.Add(20 * time.Second)
	next, _, _ := Reduce(prev, rule, r, at.Add(10*time.Second))
	if next.State != "pending" || !next.PendingAt.Equal(at.Add(10*time.Second)) {
		t.Fatal("stale sampling gap counted as sustained condition", next)
	}
}
