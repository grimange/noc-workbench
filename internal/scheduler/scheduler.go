// Package scheduler owns due-time decisions only. SSH authority, execution and
// evidence remain in the accepted collection and connection services.
package scheduler

import (
	"context"
	"errors"
	"hash/fnv"
	"sort"
	"sync"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

const QueueLimit = 32
const ProfileLimit = 1000

var ErrInvalid = errors.New("Invalid or changed schedule configuration; review verified enrollment and explicit scheduling authorization.")

type Profile struct {
	// EvidenceEligible excludes only the transient execution lock; admission still uses Eligible.
	EvidenceEligible                                               bool
	CollectionSource                                               collection.Source
	Clusters                                                       []string
	ID, CustomerID, EnvironmentID, AssetID, ClusterID, PrincipalID string
	Target                                                         sshcli.Target
	Revision                                                       int64
	Collectors                                                     []string
	Interval, Budget, RetryCount                                   int
	Enabled, Authorized, Paused, Eligible                          bool
	State, Category                                                string
	NextDue, LastDispatch, AdmittedAt, CompletedAt                 time.Time
	LagSeconds                                                     float64
	Skipped                                                        int64
}
type Control struct {
	Action          string
	Kind, ID        string
	Paused, Stopped bool
}
type Snapshot struct {
	Profiles        []Profile
	Controls        []Control
	Paused, Stopped bool
}
type Repository interface {
	Schedules(context.Context, workspace.Principal) (Snapshot, error)
	SaveSchedule(context.Context, workspace.Principal, Profile) (Profile, error)
	SetScheduleControl(context.Context, workspace.Principal, Control, time.Time) error
	RecoverSchedules(context.Context, time.Time) error
	ScheduleDecision(context.Context, Profile, string, time.Time) error
	CompleteSchedule(context.Context, Profile, collection.Run, error, time.Time) error
}
type Runner interface {
	Collect(context.Context, workspace.Principal, sshcli.Target) (collection.Run, error)
	EmergencyStop(bool)
	Capacity() (int, int)
}

func Validate(p Profile) error {
	if p.Interval < 60 || p.Interval > 86400 || p.Budget < 1 || p.Budget > 20 || len(p.Collectors) < 1 || len(p.Collectors) > 10 {
		return ErrInvalid
	}
	known := map[string]bool{"linux.baseline": true, "linux.services": true, "linux.identity": true, "linux.uptime": true, "linux.load": true, "linux.memory": true, "linux.filesystems": true, "asterisk.identity": true, "asterisk.channels": true, "asterisk.modules": true, "asterisk.pjsip": true}
	if p.CollectionSource.ID != "" {
		known = map[string]bool{"vicidial.api.version": true, "vicidial.api.campaigns": true, "vicidial.api.agents": true}
		if len(p.Collectors) != 3 {
			return ErrInvalid
		}
	}
	for _, id := range p.Collectors {
		if !known[id] {
			return ErrInvalid
		}
		delete(known, id)
	}
	if p.Enabled && !p.Authorized {
		return ErrInvalid
	}
	return nil
}

// Jitter is reproducible, positive and bounded. Positive jitter preserves the
// configured minimum interval. Salt distinguishes each cadence and retry.
func Jitter(id string, salt int64, bound time.Duration) time.Duration {
	if bound <= 0 {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	v := h.Sum64() ^ uint64(salt)*0x9e3779b97f4a7c15
	return time.Duration(v % uint64(bound+1))
}
func Next(p Profile, now time.Time) time.Time {
	return now.UTC().Add(time.Duration(p.Interval)*time.Second + Jitter(p.ID, now.Unix()/int64(p.Interval), time.Duration(p.Interval)*time.Second/10))
}
func Initial(p Profile, now time.Time) time.Time {
	return now.UTC().Add(time.Second + Jitter(p.ID, p.Revision, time.Duration(p.Interval-1)*time.Second))
}
func Retryable(r collection.Run) bool {
	if r.State != "failed" || len(r.Results) == 0 {
		return false
	}
	attempted := false
	for _, c := range r.Results {
		switch c.TransportOutcome {
		case "not_attempted":
			if r.CollectionSource.ID == "" || len(c.Diagnostics) != 1 || c.Diagnostics[0].Code != "dependency_unavailable" {
				return false
			}
			continue
		case "connection_refused", "connection_timeout", "dns_failure", "network_unreachable":
		case "transport_failed", "timeout", "request_timeout", "temporarily_unavailable":
			if r.CollectionSource.ID == "" {
				return false
			}
		default:
			return false
		}
		attempted = true
	}
	return attempted
}

type Status struct {
	Snapshot
	Queued, Running, Waiting int
	Error                    string
}
type activeJob struct {
	cancel  context.CancelFunc
	profile Profile
}
type Service struct {
	repo         Repository
	runner       Runner
	mu           sync.Mutex
	step         sync.Mutex
	queue        []Profile
	active       map[string]activeJob
	lastCustomer string
	lastCluster  map[string]string
	snapshot     Snapshot
	failure      string
	wg           sync.WaitGroup
}

func New(r Repository, x Runner) *Service {
	return &Service{repo: r, runner: x, active: map[string]activeJob{}, lastCluster: map[string]string{}}
}
func (s *Service) Save(ctx context.Context, p workspace.Principal, c Profile) (Profile, error) {
	if e := Validate(c); e != nil {
		return Profile{}, e
	}
	return s.repo.SaveSchedule(ctx, p, c)
}
func (s *Service) Control(ctx context.Context, p workspace.Principal, c Control) error {
	if e := s.repo.SetScheduleControl(ctx, p, c, time.Now().UTC()); e != nil {
		return e
	}
	if c.Kind == "global" && (c.Action == "stop" || c.Action == "release") {
		s.runner.EmergencyStop(c.Action == "stop")
	}
	return nil
}
func (s *Service) Status(ctx context.Context, p workspace.Principal) (Status, error) {
	snap, e := s.repo.Schedules(ctx, p)
	if e != nil {
		return Status{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, w := s.runner.Capacity()
	return Status{Snapshot: snap, Queued: len(s.queue), Running: a, Waiting: w, Error: s.failure}, nil
}

// Run has one timer and at most five execution goroutines. Step is also exposed
// for fake-clock tests; all time-based decisions use its supplied UTC time.
func (s *Service) Run(ctx context.Context) error {
	if e := s.repo.RecoverSchedules(ctx, time.Now().UTC()); e != nil {
		return e
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() {
		s.runner.EmergencyStop(true)
		s.mu.Lock()
		for _, job := range s.active {
			job.cancel()
		}
		s.mu.Unlock()
		s.wg.Wait()
	}()
	for {
		if e := s.Step(ctx, time.Now().UTC()); e != nil && ctx.Err() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (s *Service) Step(ctx context.Context, now time.Time) error {
	s.step.Lock()
	defer s.step.Unlock()
	snap, e := s.repo.Schedules(ctx, workspace.Principal{ID: workspace.OperatorID})
	s.mu.Lock()
	if e != nil {
		s.queue = nil
		s.failure = "database_unavailable"
		s.mu.Unlock()
		s.runner.EmergencyStop(true)
		return e
	}
	s.snapshot = snap
	s.failure = ""
	s.runner.EmergencyStop(snap.Stopped)
	eligible := map[string]Profile{}
	if !snap.Paused && !snap.Stopped {
		for _, p := range snap.Profiles {
			if p.Enabled && p.Authorized && p.Eligible && !p.Paused {
				eligible[p.ID] = p
			}
		}
	}
	// Reconstruct the finite pending queue from current authority each tick.
	// No stale in-memory job survives a configuration revision or pause.
	old := map[string]bool{}
	for _, p := range s.queue {
		old[p.ID] = true
	}
	s.queue = nil
	due := []Profile{}
	for _, p := range eligible {
		if s.active[resourceKey(p)].cancel == nil && !now.Before(p.NextDue) {
			due = append(due, p)
		}
	}
	for len(due) > 0 && len(s.queue) < QueueLimit {
		i := s.choose(due)
		p := due[i]
		due = append(due[:i], due[i+1:]...)
		s.queue = append(s.queue, p)
	}
	queue := append([]Profile(nil), s.queue...)
	s.mu.Unlock()
	for _, p := range due {
		_ = s.repo.ScheduleDecision(ctx, p, "delayed", now)
	}
	for _, p := range queue {
		if !old[p.ID] {
			if s.repo.ScheduleDecision(ctx, p, "queued", now) != nil {
				return ErrInvalid
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.queue) > 0 && len(s.active) < 5 {
		ix := -1
		for i, p := range s.queue {
			if s.scopeAvailable(p) {
				ix = i
				break
			}
		}
		if ix < 0 {
			break
		}
		p := s.queue[ix]
		s.queue = append(s.queue[:ix], s.queue[ix+1:]...)
		jobCtx, cancel := context.WithCancel(ctx)
		s.active[resourceKey(p)] = activeJob{cancel: cancel, profile: p}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer cancel()
			req := collection.Request{Source: "scheduled", ScheduleID: p.ID, Revision: p.Revision, Collectors: append([]string(nil), p.Collectors...), Budget: time.Duration(p.Budget) * time.Second, CustomerID: p.CustomerID, ClusterID: p.ClusterID}
			var run collection.Run
			var err error
			execution := collection.WithRequest(jobCtx, req)
			if p.CollectionSource.ID != "" {
				x, ok := s.runner.(interface {
					CollectSource(context.Context, workspace.Principal, Profile) (collection.Run, error)
				})
				if ok {
					run, err = x.CollectSource(execution, workspace.Principal{ID: p.PrincipalID}, p)
				} else {
					err = ErrInvalid
				}
			} else {
				run, err = s.runner.Collect(execution, workspace.Principal{ID: p.PrincipalID}, p.Target)
			}
			save, done := context.WithTimeout(context.WithoutCancel(jobCtx), 2*time.Second)
			finishErr := s.repo.CompleteSchedule(save, p, run, err, time.Now().UTC())
			done()
			s.mu.Lock()
			delete(s.active, resourceKey(p))
			if finishErr != nil {
				s.failure = "schedule_write_failed"
			}
			s.mu.Unlock()
		}()
	}
	return nil
}

// Hierarchical rotating scopes: customer first, then cluster, then oldest due.
// Each dispatch advances the cursor, including across bounded-queue refills.
func (s *Service) choose(due []Profile) int {
	customers := []string{}
	seen := map[string]bool{}
	for _, p := range due {
		if !seen[p.CustomerID] {
			customers = append(customers, p.CustomerID)
			seen[p.CustomerID] = true
		}
	}
	sort.Strings(customers)
	customer := customers[0]
	for _, id := range customers {
		if id > s.lastCustomer {
			customer = id
			break
		}
	}
	clusters := []string{}
	seen = map[string]bool{}
	for _, p := range due {
		if p.CustomerID == customer && !seen[p.ClusterID] {
			clusters = append(clusters, p.ClusterID)
			seen[p.ClusterID] = true
		}
	}
	sort.Strings(clusters)
	cluster := clusters[0]
	for _, id := range clusters {
		if id > s.lastCluster[customer] {
			cluster = id
			break
		}
	}
	best := -1
	for i, p := range due {
		if p.CustomerID == customer && p.ClusterID == cluster && (best < 0 || p.NextDue.Before(due[best].NextDue) || p.NextDue.Equal(due[best].NextDue) && p.ID < due[best].ID) {
			best = i
		}
	}
	s.lastCustomer = customer
	s.lastCluster[customer] = cluster
	return best
}

// Fixed initial scope budgets keep one large customer or shared cluster from
// occupying all five slots. All memberships count, including secondary ones.
func (s *Service) scopeAvailable(p Profile) bool {
	customer := 0
	clusters := map[string]int{}
	for _, j := range s.active {
		if j.profile.CustomerID == p.CustomerID {
			customer++
		}
		for _, c := range j.profile.Clusters {
			clusters[c]++
		}
	}
	if customer >= 3 {
		return false
	}
	for _, c := range p.Clusters {
		if clusters[c] >= 2 {
			return false
		}
	}
	return true
}

func resourceKey(p Profile) string {
	if p.CollectionSource.ID != "" {
		return "source:" + p.CollectionSource.ID
	}
	return p.AssetID
}
