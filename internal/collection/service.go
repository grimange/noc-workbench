package collection

import (
	"context"
	"errors"
	"sync"
	"time"

	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

var ErrBusy = errors.New("Linux discovery is already running or at capacity; retry shortly")

// Service retains only 16 last-request snapshots for 30 minutes in process.
// It is not durable collection history. Opening a page never starts collection.
type Service struct {
	registry *Registry
	executor Executor
	mu       sync.Mutex
	busy     map[string]bool
	latest   map[string]cached
}
type cached struct {
	actor string
	run   Run
}

func NewService(e Executor, r *Registry) *Service {
	return &Service{executor: e, registry: r, busy: map[string]bool{}, latest: map[string]cached{}}
}
func (s *Service) Collect(ctx context.Context, p workspace.Principal, t sshcli.Target) (Run, error) {
	s.mu.Lock()
	if s.busy[t.AssetID] || len(s.busy) >= 5 {
		s.mu.Unlock()
		return Run{}, ErrBusy
	}
	s.busy[t.AssetID] = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.busy, t.AssetID); s.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	run, err := s.registry.Collect(ctx, s.executor, p, t, s.registry.IDs())
	if err != nil {
		return run, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Evict expired snapshots first, then oldest. All returned values are copies.
	now := time.Now()
	for id, c := range s.latest {
		if now.Sub(c.run.EndedAt) > 30*time.Minute {
			delete(s.latest, id)
		}
	}
	if len(s.latest) >= 16 {
		oldest := ""
		var at time.Time
		for id, c := range s.latest {
			if oldest == "" || c.run.EndedAt.Before(at) {
				oldest = id
				at = c.run.EndedAt
			}
		}
		delete(s.latest, oldest)
	}
	s.latest[t.AssetID] = cached{p.ID, clone(run)}
	return run, nil
}
func (s *Service) Latest(p workspace.Principal, t sshcli.Target) (Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.latest[t.AssetID]
	if !ok || c.actor != p.ID || c.run.Target != t || time.Since(c.run.EndedAt) > 30*time.Minute {
		return Run{}, false
	}
	return clone(c.run), true
}

// SuspendedDiagnostics retains a failed request's diagnostics across the revision
// bump caused by host identity invalidation. It never exposes superseded facts.
func (s *Service) SuspendedDiagnostics(p workspace.Principal, t sshcli.Target) (Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.latest[t.AssetID]
	if !ok || c.actor != p.ID || c.run.Target.AssetID != t.AssetID || c.run.Target.EndpointID != t.EndpointID || c.run.Target.ProfileID != t.ProfileID || time.Since(c.run.EndedAt) > 30*time.Minute {
		return Run{}, false
	}
	run := clone(c.run)
	for i := range run.Results {
		run.Results[i].Observations = nil
	}
	return run, true
}
func clone(r Run) Run {
	r.Results = append([]Result(nil), r.Results...)
	for i := range r.Results {
		r.Results[i].Observations = append([]Observation(nil), r.Results[i].Observations...)
		r.Results[i].Diagnostics = append([]Diagnostic(nil), r.Results[i].Diagnostics...)
	}
	return r
}
