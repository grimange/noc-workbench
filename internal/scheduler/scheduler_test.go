package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type fakeRepo struct {
	mu        sync.Mutex
	snap      Snapshot
	fail      bool
	decisions map[string]string
}

func (f *fakeRepo) Schedules(context.Context, workspace.Principal) (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return Snapshot{}, errors.New("offline")
	}
	out := f.snap
	out.Profiles = append([]Profile(nil), out.Profiles...)
	return out, nil
}
func (f *fakeRepo) SaveSchedule(_ context.Context, _ workspace.Principal, p Profile) (Profile, error) {
	return p, Validate(p)
}
func (f *fakeRepo) SetScheduleControl(_ context.Context, _ workspace.Principal, c Control, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap.Paused = c.Paused
	f.snap.Stopped = c.Stopped
	return nil
}
func (f *fakeRepo) RecoverSchedules(context.Context, time.Time) error { return nil }
func (f *fakeRepo) ScheduleDecision(_ context.Context, p Profile, state string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.decisions == nil {
		f.decisions = map[string]string{}
	}
	f.decisions[p.ID] = state
	return nil
}
func (f *fakeRepo) CompleteSchedule(_ context.Context, p Profile, _ collection.Run, _ error, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.snap.Profiles {
		if f.snap.Profiles[i].ID == p.ID {
			f.snap.Profiles[i].NextDue = p.NextDue.Add(time.Hour)
		}
	}
	return nil
}

type barrierRunner struct {
	mu          sync.Mutex
	started     chan collection.Request
	release     chan struct{}
	active, max int
	stopped     bool
	assets      map[string]bool
	t           *testing.T
}

func (b *barrierRunner) Collect(ctx context.Context, _ workspace.Principal, target sshcli.Target) (collection.Run, error) {
	b.mu.Lock()
	if b.assets == nil {
		b.assets = map[string]bool{}
	}
	if b.assets[target.AssetID] {
		b.t.Error("overlapping asset")
	}
	b.assets[target.AssetID] = true
	b.active++
	if b.active > b.max {
		b.max = b.active
	}
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.active--; delete(b.assets, target.AssetID); b.mu.Unlock() }()
	b.started <- collection.Requested(ctx)
	select {
	case <-ctx.Done():
		return collection.Run{}, ctx.Err()
	case <-b.release:
		return collection.Run{State: "completed"}, nil
	}
}
func (b *barrierRunner) EmergencyStop(v bool) { b.mu.Lock(); b.stopped = v; b.mu.Unlock() }
func (b *barrierRunner) Capacity() (int, int) { b.mu.Lock(); defer b.mu.Unlock(); return b.active, 0 }
func profiles(n int, now time.Time) []Profile {
	out := []Profile{}
	for i := range n {
		p := Profile{ID: fmt.Sprint(i), AssetID: fmt.Sprint(i), CustomerID: "A", ClusterID: "large", PrincipalID: workspace.OperatorID, Enabled: true, Authorized: true, Eligible: true, Interval: 60, Budget: 20, Collectors: []string{"linux.uptime"}, NextDue: now.Add(-time.Second)}
		p.Target.AssetID = p.AssetID
		if i%5 == 0 {
			p.CustomerID = "B"
		}
		if i%4 == 0 {
			p.ClusterID = "small"
		}
		p.Clusters = []string{p.CustomerID + "/" + p.ClusterID}
		out = append(out, p)
	}
	return out
}
func TestFleetBoundsAndFairness(t *testing.T) {
	for _, n := range []int{1, 20, 100} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			f := &fakeRepo{snap: Snapshot{Profiles: profiles(n, now)}}
			b := &barrierRunner{t: t, started: make(chan collection.Request, 5), release: make(chan struct{}, 5)}
			s := New(f, b)
			seen := map[string]bool{}
			first := []collection.Request{}
			waves := 0
			for len(seen) < n {
				if e := s.Step(context.Background(), now); e != nil {
					t.Fatal(e)
				}
				waves++
				s.mu.Lock()
				count := len(s.active)
				s.mu.Unlock()
				if count == 0 {
					t.Fatal("scope starvation")
				}
				for range count {
					select {
					case r := <-b.started:
						if seen[r.ScheduleID] {
							t.Fatal("duplicate", r.ScheduleID)
						}
						seen[r.ScheduleID] = true
						if len(first) < 5 {
							first = append(first, r)
						}
					case <-time.After(time.Second):
						t.Fatal("dispatch stalled")
					}
				}
				s.mu.Lock()
				q := len(s.queue)
				s.mu.Unlock()
				if q > QueueLimit {
					t.Fatal("queue limit")
				}
				for range count {
					b.release <- struct{}{}
				}
				s.wg.Wait()
			}
			if b.max > 5 {
				t.Fatal("capacity")
			}
			if n >= 20 {
				customers := map[string]int{}
				clusters := map[string]int{}
				for _, r := range first {
					customers[r.CustomerID]++
					if r.CustomerID == "A" {
						clusters[r.ClusterID]++
					}
				}
				if customers["B"] < 2 || clusters["small"] == 0 || clusters["large"] == 0 {
					t.Fatalf("unfair first wave %+v %+v", customers, clusters)
				}
			}
			t.Logf("hosts=%d waves=%d max_active=%d queue<=32; logical capacity at 20s/job: %ds; no overlapping assets", n, waves, b.max, waves*20)
		})
	}
}
func TestDueJitterValidationAndRetry(t *testing.T) {
	now := time.Now().UTC()
	p := profiles(1, now)[0]
	for i := range 1000 {
		p.ID = fmt.Sprint(i)
		initial := Initial(p, now)
		next := Next(p, now)
		if initial.Before(now.Add(time.Second)) || initial.After(now.Add(60*time.Second)) || next.Before(now.Add(60*time.Second)) || next.After(now.Add(66*time.Second)) || Next(p, now) != next {
			t.Fatal("jitter")
		}
	}
	for _, edit := range []func(*Profile){func(p *Profile) { p.Interval = 59 }, func(p *Profile) { p.Budget = 21 }, func(p *Profile) { p.Collectors = nil }, func(p *Profile) { p.Collectors = []string{"linux.uptime", "linux.uptime"} }, func(p *Profile) { p.Authorized = false }} {
		q := p
		edit(&q)
		if Validate(q) == nil {
			t.Fatal("invalid accepted")
		}
	}
	for _, code := range []string{"host_key_mismatch", "unknown_host_key", "authentication_failed", "permission_denied", "cancelled", "stale_profile", "credential_unavailable", "unsupported_source", "execution_timeout"} {
		if Retryable(collection.Run{State: "failed", Results: []collection.Result{{TransportOutcome: code}}}) {
			t.Fatal("unsafe retry", code)
		}
	}
	if !Retryable(collection.Run{State: "failed", Results: []collection.Result{{TransportOutcome: "connection_timeout"}}}) {
		t.Fatal("no transient retry")
	}
}
func TestPauseStopRevisionDatabaseAndCancellation(t *testing.T) {
	now := time.Now().UTC()
	f := &fakeRepo{snap: Snapshot{Profiles: profiles(20, now)}}
	b := &barrierRunner{t: t, started: make(chan collection.Request, 5), release: make(chan struct{}, 5)}
	s := New(f, b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if e := s.Step(ctx, now); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	startedCount := len(s.active)
	s.mu.Unlock()
	for range startedCount {
		<-b.started
	}
	f.mu.Lock()
	f.snap.Paused = true
	f.mu.Unlock()
	if e := s.Step(ctx, now); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	if len(s.queue) != 0 || len(s.active) != startedCount {
		t.Fatal("pause semantics")
	}
	s.mu.Unlock()
	f.mu.Lock()
	f.fail = true
	f.mu.Unlock()
	if s.Step(ctx, now) == nil {
		t.Fatal("database outage ignored")
	}
	b.mu.Lock()
	if !b.stopped {
		t.Fatal("not fail closed")
	}
	b.mu.Unlock()
	cancel()
	s.wg.Wait()
	s.mu.Lock()
	if len(s.active) != 0 {
		t.Fatal("capacity leak")
	}
	s.mu.Unlock()
	f.mu.Lock()
	f.fail = false
	f.snap.Paused = false
	for i := range f.snap.Profiles {
		f.snap.Profiles[i].Eligible = false
	}
	f.mu.Unlock()
	if e := s.Step(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	select {
	case <-b.started:
		t.Fatal("revoked queued request dispatched")
	default:
	}
}
