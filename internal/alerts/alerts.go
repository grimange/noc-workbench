// Package alerts reduces canonical evaluated evidence into durable alert decisions.
// It has no transport dependency and never reads a clock.
package alerts

import (
	"context"
	"errors"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"noc-workbench/internal/workspace"
	"time"
)

var ErrRule = errors.New("invalid alert rule or revision")

const Version = "evidence-alert.v1"

type Rule struct {
	ID, PolicyID, Severity, Actor string
	Revision                      int64
	DebounceSeconds               int
	Enabled                       bool
	CreatedAt                     time.Time
}

func (r Rule) Validate() error {
	if r.Revision < 1 || r.DebounceSeconds < 0 || r.DebounceSeconds > 86400 {
		return ErrRule
	}
	switch r.Severity {
	case "info", "warning", "critical":
	default:
		return ErrRule
	}
	return nil
}

type Instance struct {
	ID, RuleID, Resource, State, EvidenceState, Severity string
	RuleRevision, PolicyRevision                         int64
	PendingAt, DetectedAt, UpdatedAt, EvaluatedAt        time.Time
	AcknowledgedAt                                       *time.Time
	AcknowledgedBy                                       string
	Reading                                              health.Reading
}
type Event struct {
	ID          int64
	Kind, Actor string
	At          time.Time
	Snapshot    Instance
}
type Summary struct {
	LatestEvent                                   int64
	Active, Pending, Unacknowledged, EnabledRules int
}
type View struct {
	Total, Active, Pending int

	Rules  []Rule
	Alerts []Instance
	Events []Event
}
type Sample struct {
	ID, RunID, Key, Resource, Unit, Value, Collector, Transport string
	At                                                          time.Time
	TTLSeconds                                                  int
	Gap                                                         bool
}
type Series struct {
	Samples       []Sample
	From, To      time.Time
	Key, Resource string
}
type Repository interface {
	AlertPage(context.Context, workspace.Principal, collection.HistoryScope, int) (View, error)
	MonitoringAssetPage(context.Context, workspace.Principal, int) ([]collection.HistoryScope, bool, error)
	AlertSummary(context.Context, workspace.Principal) (Summary, error)

	SaveAlertRule(context.Context, workspace.Principal, collection.HistoryScope, Rule) (Rule, error)
	AlertView(context.Context, workspace.Principal, collection.HistoryScope) (View, error)
	AcknowledgeAlert(context.Context, workspace.Principal, collection.HistoryScope, string) error
	ObservationSeries(context.Context, workspace.Principal, collection.HistoryScope, string, string, time.Time, time.Time) (Series, error)
	MaintainAlerts(context.Context, time.Time) error
	MonitoringAssets(context.Context, workspace.Principal) ([]collection.HistoryScope, error)
	MonitoringScopes(context.Context, workspace.Principal) ([]collection.HistoryScope, error)
	EvaluateAlerts(context.Context, collection.HistoryScope, time.Time) error
}

// Reduce preserves active conditions on expiry/disable. Only fresh, valid,
// policy-matched canonical healthy evidence can establish recovery. A revision
// resets pending debounce; active identity and acknowledgment remain intact.
func Reduce(previous Instance, rule Rule, reading health.Reading, at time.Time) (Instance, string, error) {
	if rule.Validate() != nil || at.IsZero() || at.Before(previous.EvaluatedAt) {
		return previous, "", ErrRule
	}
	next := previous
	next.Severity = rule.Severity
	next.RuleID = rule.ID
	next.RuleRevision = rule.Revision
	next.PolicyRevision = reading.PolicyRevision
	next.Resource = reading.Evidence.Resource
	next.EvaluatedAt = at.UTC()
	next.Reading = reading
	next.EvidenceState = "unknown"
	eligible := rule.Enabled && reading.PolicyID == rule.PolicyID && reading.Quality == "valid" && reading.Freshness == "fresh" && (reading.Health == "healthy" || reading.Health == "degraded")
	if !rule.Enabled {
		next.EvidenceState = "disabled"
	} else if reading.Freshness == "stale" {
		next.EvidenceState = "stale"
	}
	kind := ""
	if eligible {
		next.EvidenceState = "fresh"
		if reading.Health == "degraded" {
			if previous.State != "active" {
				if previous.State != "pending" || previous.RuleRevision != rule.Revision || previous.PolicyRevision != reading.PolicyRevision || previous.EvidenceState != "fresh" || (!previous.Reading.ExpiresAt.IsZero() && reading.Evidence.ObservedAt.After(previous.Reading.ExpiresAt)) {
					next.PendingAt = at.UTC()
					next.DetectedAt = at.UTC()
					next.AcknowledgedAt = nil
					next.AcknowledgedBy = ""
				}
				next.State = "pending"
				if at.Sub(next.PendingAt) >= time.Duration(rule.DebounceSeconds)*time.Second {
					next.State = "active"
				}
			}
		} else {
			if previous.State == "active" || previous.State == "pending" {
				next.State = "resolved"
			}
			next.PendingAt = time.Time{}
		}
	} else if next.State == "pending" {
		next.PendingAt = time.Time{}
	}
	if next.State == "" {
		return previous, "", nil
	}
	switch {
	case previous.State != next.State:
		kind = next.State
	case previous.EvidenceState != next.EvidenceState:
		kind = "evidence_changed"
	case previous.RuleRevision != next.RuleRevision || previous.PolicyRevision != next.PolicyRevision:
		kind = "revision_changed"
	}
	if kind != "" {
		next.UpdatedAt = at.UTC()
	}
	return next, kind, nil
}

// Run uses a single bounded loop, independent of SSH scheduling. PostgreSQL
// selects at most twenty oldest evaluation cursors per pass. Errors never
// synthesize transitions; a later pass reconciles committed authoritative state.
func Run(ctx context.Context, repo Repository) {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		_ = repo.MaintainAlerts(c, time.Now().UTC())
		scopes, e := repo.MonitoringScopes(c, workspace.Principal{ID: workspace.OperatorID})
		cancel()
		if e != nil {
			continue
		}
		for _, h := range scopes {
			if ctx.Err() != nil {
				return
			}
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			_ = repo.EvaluateAlerts(c, h, time.Now().UTC())
			cancel()
		}
	}
}
