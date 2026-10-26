package collection

import (
	"testing"
	"time"
)

func TestFreshnessBoundary(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := Evidence{Observation: Observation{ObservedAt: now}, TTLSeconds: 180}
	for _, tc := range []struct {
		offset time.Duration
		want   string
	}{{-time.Second, "stale"}, {0, "fresh"}, {179 * time.Second, "fresh"}, {180 * time.Second, "stale"}} {
		e.At(now.Add(tc.offset))
		if e.Freshness != tc.want || e.AgeSeconds < 0 {
			t.Fatal(tc, e)
		}
	}
}
