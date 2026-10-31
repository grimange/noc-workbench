package collection

import (
	"fmt"
	"strings"
)

// ResultCounts is a presentation of canonical collector outcomes. FailureCount
// on Run is a legacy non-success aggregate and is not a failed-collector count.
type ResultCounts struct {
	Successful, Partial, Failed, Cancelled, Skipped, Unknown int
	Available                                                bool
}

func (r Run) ResultCounts() ResultCounts {
	results := r.Results
	if r.SummaryResults != nil {
		results = r.SummaryResults
	}
	c := ResultCounts{Available: len(results) > 0 && len(results) == r.SuccessCount+r.FailureCount}
	seen := map[string]bool{}
	for _, result := range results {
		if result.CollectorID == "" || seen[result.CollectorID] {
			c.Available = false
		}
		seen[result.CollectorID] = true
		switch result.Outcome {
		case "success":
			c.Successful++
		case "partial":
			c.Partial++
		case "failed":
			c.Failed++
		case "cancelled":
			c.Cancelled++
		case "skipped":
			c.Skipped++
		default:
			c.Unknown++
		}
	}
	return c
}

func (r Run) CountSummary() string {
	c := r.ResultCounts()
	if !c.Available {
		return "Collector counts unavailable"
	}
	if c.Partial+c.Failed+c.Cancelled+c.Skipped+c.Unknown == 0 {
		return fmt.Sprintf("%d successful", c.Successful)
	}
	parts := []string{fmt.Sprintf("%d successful", c.Successful), fmt.Sprintf("%d partial", c.Partial), fmt.Sprintf("%d failed", c.Failed)}
	for _, extra := range []struct {
		n     int
		label string
	}{{c.Cancelled, "cancelled"}, {c.Skipped, "skipped"}, {c.Unknown, "unknown"}} {
		if extra.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", extra.n, extra.label))
		}
	}
	return strings.Join(parts, ", ")
}
