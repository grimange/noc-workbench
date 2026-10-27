package collection

import (
	"context"
	"errors"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"time"
)

var ErrPersistence = errors.New("Collection evidence could not be committed. No success is recorded; review history after database recovery.")

type HistoryScope struct{ CustomerID, EnvironmentID, AssetID, SourceID string }
type Evidence struct {
	Observation
	ID, RunID, Freshness string
	TTLSeconds           int
	AgeSeconds           int64
}

func (e *Evidence) At(now time.Time) {
	e.AgeSeconds = int64(now.Sub(e.ObservedAt).Seconds())
	if e.AgeSeconds < 0 {
		e.AgeSeconds = 0
	}
	e.Freshness = "stale"
	if !now.Before(e.ObservedAt) && now.Before(e.ObservedAt.Add(time.Duration(e.TTLSeconds)*time.Second)) {
		e.Freshness = "fresh"
	}
}

type HistoryRepository interface {
	BeginCollection(context.Context, workspace.Principal, sshcli.Target) (Run, error)
	FinishCollection(context.Context, workspace.Principal, Run, int) error
	CollectionHistory(context.Context, workspace.Principal, HistoryScope, string) ([]Run, error)
	LatestEvidence(context.Context, workspace.Principal, HistoryScope) ([]Evidence, error)
}

type History struct {
	Runs      []Run
	Latest    []Evidence
	Next      string
	Truncated bool
}

func (s *Service) History(ctx context.Context, p workspace.Principal, h HistoryScope, before string) (History, bool, error) {
	if s.repository == nil {
		return History{}, false, nil
	}
	runs, e := s.repository.CollectionHistory(ctx, p, h, before)
	if e != nil {
		return History{}, true, e
	}
	latest, e := s.repository.LatestEvidence(ctx, p, h)
	if e != nil {
		return History{}, true, e
	}
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock()
	}
	for i := range latest {
		latest[i].At(now)
	}
	out := History{Runs: runs, Latest: latest}
	if len(latest) > 2048 {
		out.Latest = latest[:2048]
		out.Truncated = true
	}
	if len(runs) == 20 {
		out.Next = runs[len(runs)-1].ID
	}
	return out, true, nil
}
func (r Run) DurationSeconds() float64 {
	if r.EndedAt.IsZero() {
		return 0
	}
	return r.EndedAt.Sub(r.StartedAt).Seconds()
}

// Summarize derives collection outcome without evaluating operational health.
func (r *Run) Summarize() {
	r.State, r.Category, r.SuccessCount, r.FailureCount = "completed", "", 0, 0
	observations := 0
	for _, c := range r.Results {
		observations += len(c.Observations)
		if c.Outcome == "success" {
			r.SuccessCount++
		} else {
			r.FailureCount++
		}
		if len(c.Diagnostics) > 0 && r.Category == "" {
			r.Category = c.Diagnostics[0].Code
		}
	}
	if r.FailureCount > 0 {
		r.State = "partial"
		if observations == 0 {
			r.State = "failed"
		}
		if r.Category == "cancelled" {
			r.State = "cancelled"
		}
	}
}
