package collection

import (
	"context"
	"sync"
	"time"
)

// Request is application-owned scheduling provenance, never a remote command.
// Repository validation binds it to a current, explicitly authorized profile.
type Request struct {
	Source, ScheduleID, CustomerID, ClusterID string
	Revision                                  int64
	Collectors                                []string
	Budget                                    time.Duration
}
type requestKey struct{}

func WithRequest(ctx context.Context, r Request) context.Context {
	return context.WithValue(ctx, requestKey{}, r)
}
func Requested(ctx context.Context) Request {
	r, _ := ctx.Value(requestKey{}).(Request)
	if r.Source == "" {
		r.Source = "operator"
	}
	return r
}

type AdmissionScope struct {
	Customer string
	Clusters []string
}

type waiter struct {
	scope     AdmissionScope
	asset     string
	scheduled bool
	ready     chan struct{}
	cancel    context.CancelFunc
	admitted  bool
}

// admission is the one shared manual/scheduled capacity authority. Waiting is
// bounded to 32 requests; duplicate assets coalesce. Alternating classes bound
// manual priority and guarantee scheduled progress when capacity is released.
type admission struct {
	mu            sync.Mutex
	active        map[string]*waiter
	queue         []*waiter
	stopped       bool
	lastScheduled bool
}

func (a *admission) acquire(ctx context.Context, asset string, scheduled bool, scopes ...AdmissionScope) (context.Context, func(), error) {
	a.mu.Lock()
	if a.active == nil {
		a.active = map[string]*waiter{}
	}
	if a.stopped || a.active[asset] != nil || len(a.queue) >= 32 {
		a.mu.Unlock()
		return ctx, nil, ErrBusy
	}
	for _, w := range a.queue {
		if w.asset == asset {
			a.mu.Unlock()
			return ctx, nil, ErrBusy
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	w := &waiter{asset: asset, scheduled: scheduled, ready: make(chan struct{}), cancel: cancel}
	if len(scopes) > 0 {
		w.scope = scopes[0]
	}
	a.queue = append(a.queue, w)
	a.dispatch()
	a.mu.Unlock()
	release := func() {
		a.mu.Lock()
		if a.active[asset] == w {
			delete(a.active, asset)
		}
		for i, q := range a.queue {
			if q == w {
				a.queue = append(a.queue[:i], a.queue[i+1:]...)
				break
			}
		}
		cancel()
		a.dispatch()
		a.mu.Unlock()
	}
	select {
	case <-ctx.Done():
		release()
		return ctx, nil, ctx.Err()
	case <-w.ready:
	}
	if ctx.Err() != nil {
		release()
		return ctx, nil, ctx.Err()
	}
	return ctx, release, nil
}
func (a *admission) dispatch() {
	for !a.stopped && len(a.active) < 5 && len(a.queue) > 0 {
		ix := -1
		for i, w := range a.queue {
			if !a.scopeAvailable(w.scope) {
				continue
			}
			if ix < 0 {
				ix = i
			}
			if w.scheduled != a.lastScheduled {
				ix = i
				break
			}
		}
		if ix < 0 {
			break
		}
		w := a.queue[ix]
		a.queue = append(a.queue[:ix], a.queue[ix+1:]...)
		a.lastScheduled = w.scheduled
		a.active[w.asset] = w
		w.admitted = true
		close(w.ready)
	}
}
func (s *Service) EmergencyStop(stopped bool) {
	a := &s.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopped = stopped
	if stopped {
		for _, w := range a.active {
			w.cancel()
		}
		for _, w := range a.queue {
			w.cancel()
		}
		a.queue = nil
	}
	a.dispatch()
}
func (s *Service) Capacity() (active, queued int) {
	a := &s.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.active), len(a.queue)
}

func (a *admission) scopeAvailable(scope AdmissionScope) bool {
	customer := 0
	clusters := map[string]int{}
	for _, w := range a.active {
		if scope.Customer != "" && w.scope.Customer == scope.Customer {
			customer++
		}
		for _, c := range w.scope.Clusters {
			clusters[c]++
		}
	}
	if customer >= 3 {
		return false
	}
	for _, c := range scope.Clusters {
		if clusters[c] >= 2 {
			return false
		}
	}
	return true
}
