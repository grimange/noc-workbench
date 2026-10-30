package health

import "time"

// ScheduleProgress is a read-only snapshot of scheduling intent and progress.
// Grace is max(three configured opportunities, configured grace, budget+interval).
type ScheduleProgress struct {
	Exists, Expected, Authorized, Enabled, Paused, Stopped, Guard bool
	Interval, Budget                                              int
	Category                                                      string
	LastDispatch, CompletedAt, NextDue                            time.Time
}

func Continuity(s ScheduleProgress, policy Policy, at time.Time) (state, reason string) {
	if !s.Exists || !s.Expected {
		return "unknown", "Monitoring not expected"
	}
	if s.Paused || s.Stopped {
		return "unknown", "Monitoring intentionally suspended"
	}
	if !s.Authorized {
		return "unknown", "Monitoring authorization revoked"
	}
	grace := time.Duration(policy.Threshold) * time.Second
	if d := time.Duration(3*s.Interval) * time.Second; d > grace {
		grace = d
	}
	if d := time.Duration(s.Interval+s.Budget) * time.Second; d > grace {
		grace = d
	}
	anchor := s.CompletedAt
	if anchor.IsZero() {
		anchor = policy.CreatedAt
	}
	// Starting attempts alone cannot conceal a collector that never completes.
	if anchor.After(at) {
		return "unknown", "Inconsistent scheduling timestamp"
	}
	if at.Sub(anchor) < grace {
		return "healthy", "Monitoring within configured progress grace"
	}
	if !s.Enabled {
		return "degraded", "Expected monitoring interrupted: schedule disabled unexpectedly"
	}
	if s.Guard {
		return "degraded", "Expected monitoring interrupted: execution guard blocks progress"
	}
	if s.Category != "" {
		return "degraded", "Expected monitoring interrupted: " + s.Category
	}
	return "degraded", "Expected monitoring interrupted: no completed attempt within progress grace"
}
