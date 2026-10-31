package web

import (
	"bytes"
	"fmt"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	auth "noc-workbench/internal/integrations/asteriskauth"
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
		{"completed", 12, 0, 0, true, "Success — 12 successful"},
		{"partial", 6, 6, 0, true, "Partial — 6 successful, 0 partial, 6 failed"},
		{"failed", 0, 12, 0, true, "Failed — 0 successful, 0 partial, 12 failed"},
		{"cancelled", 1, 0, 0, true, "Cancelled"},
		{"completed", 12, 0, 3 * time.Minute, true, "Historical: Success"},
		{"completed", 12, 0, 0, false, "Historical: Success"},
		{"running", 0, 0, 0, true, "Unknown"},
	} {
		r := &collection.Run{State: tc.state, SuccessCount: tc.success, FailureCount: tc.failed, EndedAt: at.Add(-tc.age)}
		for i := 0; i < tc.success+tc.failed; i++ {
			outcome := "success"
			if i >= tc.success {
				outcome = "failed"
			}
			r.Results = append(r.Results, collection.Result{CollectorID: fmt.Sprint(i), Outcome: outcome})
		}
		got := runtimeReadings(runtimeData{Enabled: tc.enabled, Attempt: r}, health.Input{At: at}, health.Evaluation{})
		if !strings.HasPrefix(got.RunSummary, tc.want) {
			t.Fatalf("%+v: %s", tc, got.RunSummary)
		}
	}
}

func TestPartialCoverageSummary(t *testing.T) {
	at := time.Now().UTC()
	r := &collection.Run{State: "partial", SuccessCount: 11, FailureCount: 1, EndedAt: at}
	for i := 0; i < 11; i++ {
		r.Results = append(r.Results, collection.Result{CollectorID: fmt.Sprint(i), Outcome: "success"})
	}
	r.Results = append(r.Results, collection.Result{CollectorID: "asterisk.auth", Outcome: "partial", Diagnostics: []collection.Diagnostic{{Code: "coverage_gap"}}})
	got := runtimeReadings(runtimeData{Enabled: true, Attempt: r}, health.Input{At: at}, health.Evaluation{})
	if got.RunSummary != "Partial — 11 successful, 1 partial, 0 failed" {
		t.Fatal(got.RunSummary)
	}
	if r.State != "partial" || r.FailureCount != 1 {
		t.Fatal("canonical state changed")
	}
}

func TestCurrentHistoricalCoverageExplanation(t *testing.T) {
	const explanation = "Current authentication-log collection succeeded; earlier historical log coverage remains incomplete."
	for _, tc := range []struct{ current, gap bool }{{true, true}, {true, false}, {false, true}} {
		d := pageData{Server: serverData{Asterisk: asteriskRegistrationData{Auth: auth.View{Current: tc.current, Gap: tc.gap}}}}
		var b bytes.Buffer
		if err := pages.ExecuteTemplate(&b, "asterisk-registrations", d); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.String(), explanation) != (tc.current && tc.gap) {
			t.Fatalf("incorrect coverage explanation for %+v", tc)
		}
	}
}
