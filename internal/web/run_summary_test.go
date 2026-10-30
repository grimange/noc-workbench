package web

import (
	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"strings"
	"testing"
	"time"
)

func TestAggregateRunSummaryIndependentOfServiceResult(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		state           string
		success, failed int
		age             time.Duration
		enabled         bool
		want            string
	}{
		{"completed", 12, 0, 0, true, "Success — 12 successful, 0 failed"},
		{"partial", 6, 6, 0, true, "Partial — 6 successful, 6 failed"},
		{"failed", 0, 12, 0, true, "Failed — 0 successful, 12 failed"},
		{"cancelled", 1, 0, 0, true, "Cancelled"},
		{"completed", 12, 0, 3 * time.Minute, true, "Historical: Success"},
		{"completed", 12, 0, 0, false, "Historical: Success"},
		{"running", 0, 0, 0, true, "Unknown"},
	} {
		r := &collection.Run{State: tc.state, SuccessCount: tc.success, FailureCount: tc.failed, EndedAt: at.Add(-tc.age), Results: []collection.Result{{CollectorID: "linux.services", Outcome: "success"}}}
		got := runtimeReadings(runtimeData{Enabled: tc.enabled, Attempt: r}, health.Input{At: at}, health.Evaluation{})
		if !strings.HasPrefix(got.RunSummary, tc.want) {
			t.Fatalf("%+v: %s", tc, got.RunSummary)
		}
	}
}
