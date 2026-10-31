package collection

import (
	"reflect"
	"testing"
)

func TestCanonicalCountSummary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		outcomes []string
		want     string
	}{
		{"success", []string{"success", "success"}, "2 successful"},
		{"historical partial", []string{"success", "partial"}, "1 successful, 1 partial, 0 failed"},
		{"failed", []string{"success", "failed"}, "1 successful, 0 partial, 1 failed"},
		{"mixed", []string{"success", "partial", "failed"}, "1 successful, 1 partial, 1 failed"},
		{"all failed", []string{"failed", "failed"}, "0 successful, 0 partial, 2 failed"},
		{"cancelled and skipped", []string{"cancelled", "skipped"}, "0 successful, 0 partial, 0 failed, 1 cancelled, 1 skipped"},
		{"unknown", []string{"unsupported"}, "0 successful, 0 partial, 0 failed, 1 unknown"},
		{"missing", nil, "Collector counts unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Run{State: "partial", Category: "coverage_gap"}
			for i, o := range tc.outcomes {
				r.Results = append(r.Results, Result{CollectorID: string(rune('a' + i)), Outcome: o, Diagnostics: []Diagnostic{{Code: "coverage_gap"}}})
				if o == "success" {
					r.SuccessCount++
				} else {
					r.FailureCount++
				}
			}
			before := r
			if got := r.CountSummary(); got != tc.want {
				t.Fatalf("%q != %q", got, tc.want)
			}
			if !reflect.DeepEqual(r, before) {
				t.Fatal("presentation mutated canonical evidence")
			}
		})
	}
	r := Run{SuccessCount: 11, FailureCount: 1, Results: []Result{{CollectorID: "linux.services", Outcome: "success"}}}
	if r.CountSummary() != "Collector counts unavailable" {
		t.Fatal("invented counts for incomplete projection")
	}
}
