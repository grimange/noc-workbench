package collection

import (
	"context"
	"errors"
	"sync"
	"time"

	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

// ScheduledSSHBudget bounds the entire sequential attempt, including admission.
// Expanded optional profiles need room for independent SSH handshakes; each
// command retains its own smaller transport deadline and output/concurrency caps.
func ScheduledSSHBudget(collectors int) time.Duration {
	if collectors > 8 && collectors <= 12 {
		return 40 * time.Second
	}
	return 20 * time.Second
}

var ErrBusy = errors.New("Collection is already running or at capacity; retry shortly")

// Service executes explicit bounded requests and commits evidence to its repository.
// A repository-free service supports isolated parser/transport tests only.
// Opening a page never starts collection.
type Service struct {
	repository          HistoryRepository
	TTLSeconds          int
	RunDays, SampleDays int
	Clock               func() time.Time
	registry            *Registry
	executor            Executor
	mu                  sync.Mutex
	admission           admission
	latest              map[string]cached
}
type cached struct {
	actor string
	run   Run
}

func NewService(e Executor, r *Registry, repositories ...HistoryRepository) *Service {
	s := &Service{executor: e, registry: r, TTLSeconds: 180, RunDays: 30, SampleDays: 7, latest: map[string]cached{}}
	if len(repositories) > 0 {
		s.repository = repositories[0]
	}
	return s
}
func (s *Service) Collect(ctx context.Context, p workspace.Principal, t sshcli.Target) (Run, error) {
	req := Requested(ctx)
	ids := req.Collectors
	if len(ids) == 0 {
		ids = s.registry.Defaults()
	}
	// Validate before admission or durable history: unknown/duplicate IDs execute nothing.
	seen := map[string]bool{}
	approved := map[string]bool{}
	for _, id := range s.registry.IDs() {
		approved[id] = true
	}
	for _, id := range ids {
		if !approved[id] || seen[id] {
			return Run{}, ErrUnknown
		}
		seen[id] = true
	}
	budget := 10 * time.Second
	if req.Source == "scheduled" {
		budget = req.Budget
		if budget < time.Second || budget > ScheduledSSHBudget(len(ids)) {
			return Run{}, ErrUnknown
		}
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	scope := AdmissionScope{}
	if repo, ok := s.repository.(interface {
		CollectionAdmissionScope(context.Context, workspace.Principal, sshcli.Target) (AdmissionScope, error)
	}); ok {
		var e error
		scope, e = repo.CollectionAdmissionScope(ctx, p, t)
		if e != nil {
			if ctx.Err() != nil {
				return Run{}, ctx.Err()
			}
			return Run{}, errors.Join(ErrPersistence, e)
		}
	}
	var release func()
	var err error
	ctx, release, err = s.admission.acquire(ctx, t.AssetID, req.Source == "scheduled", scope)
	if err != nil {
		return Run{}, err
	}
	defer release()
	var durable Run
	if s.repository != nil {
		if m, ok := s.repository.(interface {
			MaintainCollections(context.Context, time.Time, int, int) error
		}); ok {
			if e := m.MaintainCollections(ctx, time.Now().UTC(), s.RunDays, s.SampleDays); e != nil {
				if ctx.Err() != nil {
					return Run{}, ctx.Err()
				}
				return Run{}, errors.Join(ErrPersistence, e)
			}
		}
		var err error
		durable, err = s.repository.BeginCollection(ctx, p, t)
		if err != nil {
			if ctx.Err() != nil {
				return Run{}, ctx.Err()
			}
			return Run{}, errors.Join(ErrPersistence, err)
		}
	}
	run, err := s.registry.Collect(ctx, s.executor, p, t, ids)
	if err != nil {
		return run, err
	}
	if s.repository != nil {
		run.ID = durable.ID
		run.Source = durable.Source
		run.ScheduleID = durable.ScheduleID
		run.ScheduleRevision = durable.ScheduleRevision
		run.PrincipalID = p.ID
		run.StartedAt = durable.StartedAt
		run.EndpointRevision = durable.EndpointRevision
		saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer saveCancel()
		if e := s.repository.FinishCollection(saveCtx, p, run, s.TTLSeconds); e != nil {
			return run, errors.Join(ErrPersistence, e)
		}
		return run, nil
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
