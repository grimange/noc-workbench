package collection

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestSharedAdmissionBoundedFairAndCancelled(t *testing.T) {
	a := &admission{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	releases := []func(){}
	for i := range 5 {
		_, release, e := a.acquire(ctx, fmt.Sprint(i), false)
		if e != nil {
			t.Fatal(e)
		}
		releases = append(releases, release)
	}
	if _, _, e := a.acquire(ctx, "0", true); !errors.Is(e, ErrBusy) {
		t.Fatal("duplicate active asset")
	}
	type admitted struct {
		scheduled bool
		release   func()
		err       error
	}
	ready := make(chan admitted, 32)
	for i := range 32 {
		go func() {
			_, release, e := a.acquire(ctx, fmt.Sprint(i+5), i%2 == 0)
			ready <- admitted{i%2 == 0, release, e}
		}()
	}
	deadline := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		n := len(a.queue)
		a.mu.Unlock()
		if n == 32 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queue synchronization")
		}
		runtime.Gosched()
	}
	if _, _, e := a.acquire(ctx, "overflow", false); !errors.Is(e, ErrBusy) {
		t.Fatal("queue overflow")
	}
	releases[0]()
	r := <-ready
	if !r.scheduled || r.err != nil {
		t.Fatal("scheduled starvation")
	}
	releases[1]()
	r2 := <-ready
	if r2.scheduled || r2.err != nil {
		t.Fatal("manual starvation")
	}
	cancel()
	r.release()
	r2.release()
	for _, release := range releases[2:] {
		release()
	}
	for range 30 {
		r := <-ready
		if r.release != nil {
			r.release()
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.active) != 0 || len(a.queue) != 0 {
		t.Fatal("capacity leak")
	}
}
func TestEmergencyStopPersistsUntilReleaseInAdmission(t *testing.T) {
	s := &Service{}
	ctx, release, e := s.admission.acquire(context.Background(), "active", true)
	if e != nil {
		t.Fatal(e)
	}
	s.EmergencyStop(true)
	if ctx.Err() == nil {
		t.Fatal("inflight not cancelled")
	}
	release()
	if _, _, e = s.admission.acquire(context.Background(), "manual", false); !errors.Is(e, ErrBusy) {
		t.Fatal("manual bypass")
	}
	s.EmergencyStop(false)
	_, release, e = s.admission.acquire(context.Background(), "manual", false)
	if e != nil {
		t.Fatal(e)
	}
	release()
}

func TestSharedScopeBudgetsIncludeManualAndSecondaryClusters(t *testing.T) {
	a := &admission{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	releases := []func(){}
	for i := range 3 {
		_, release, e := a.acquire(ctx, fmt.Sprint(i), i%2 == 0, AdmissionScope{Customer: "large", Clusters: []string{fmt.Sprint(i), "secondary" + fmt.Sprint(i%2)}})
		if e != nil {
			t.Fatal(e)
		}
		releases = append(releases, release)
	}
	ready := make(chan func(), 1)
	go func() {
		_, r, e := a.acquire(ctx, "fourth", false, AdmissionScope{Customer: "large"})
		if e == nil {
			ready <- r
		}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		n := len(a.queue)
		a.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queue barrier")
		}
		runtime.Gosched()
	}
	select {
	case <-ready:
		t.Fatal("manual bypassed customer cap")
	default:
	}
	// Another customer sharing the secondary cluster is also delayed at its cap.
	blockedCtx, blockedCancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, r, e := a.acquire(blockedCtx, "shared-cluster", true, AdmissionScope{Customer: "small", Clusters: []string{"secondary0"}})
		if r != nil {
			r()
		}
		done <- e
	}()
	deadline = time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		n := len(a.queue)
		a.mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cluster queue barrier")
		}
		runtime.Gosched()
	}
	_, other, e := a.acquire(ctx, "unrelated", false, AdmissionScope{Customer: "small", Clusters: []string{"other"}})
	if e != nil {
		t.Fatal(e)
	}
	blockedCancel()
	if e := <-done; e == nil {
		t.Fatal("secondary cluster cap bypass")
	}
	releases[0]()
	select {
	case r := <-ready:
		r()
	case <-time.After(time.Second):
		t.Fatal("scope capacity not released")
	}
	other()
	for _, r := range releases[1:] {
		r()
	}
}
