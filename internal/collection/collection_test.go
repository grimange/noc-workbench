package collection_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type fake struct {
	mu    sync.Mutex
	calls int
	code  sshcli.Category
	block chan struct{}
}

func (f *fake) Execute(ctx context.Context, p workspace.Principal, t sshcli.Target, id string) (sshcli.Result, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	start := time.Now().UTC()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return sshcli.Result{StartedAt: start, EndedAt: time.Now().UTC()}, &sshcli.Failure{Category: sshcli.Cancelled}
		}
	}
	raw := sshcli.Result{StartedAt: start, EndedAt: time.Now().UTC()}
	if id == "linux.uptime.v1" {
		if f.code != "" {
			return raw, &sshcli.Failure{Category: f.code}
		}
		raw.Stdout = []byte("123.45 999.9\n")
	} else {
		raw.Stdout = []byte("private raw secret")
		return raw, errors.New("sensitive internal error")
	}
	return raw, nil
}
func TestUnknownBeforeExecution(t *testing.T) {
	f := &fake{}
	_, e := linux.Registry().Collect(context.Background(), f, workspace.Principal{}, sshcli.Target{}, []string{"linux.uptime", "arbitrary; touch /tmp/bad"})
	if !errors.Is(e, collection.ErrUnknown) || f.calls != 0 {
		t.Fatal(e, f.calls)
	}
}
func TestPartialFailuresAndProvenance(t *testing.T) {
	f := &fake{}
	target := sshcli.Target{AssetID: "asset", EndpointID: "endpoint", ProfileID: "profile", ProfileVersion: 7}
	r, e := linux.Registry().Collect(context.Background(), f, workspace.Principal{}, target, linux.Registry().IDs())
	if e != nil {
		t.Fatal(e)
	}
	for _, rr := range r.Results {
		if rr.CollectorID == "linux.uptime" {
			if rr.Outcome != "success" || len(rr.Observations) != 1 {
				t.Fatal(rr)
			}
			o := rr.Observations[0]
			if o.AssetID != target.AssetID || o.EndpointID != target.EndpointID || o.ProfileID != target.ProfileID || o.ProfileVersion != 7 || o.Transport != "ssh" || o.Quality != "valid" || o.ObservedAt.IsZero() || o.ReceivedAt.Before(o.ObservedAt) || o.Value.Number != 123.45 {
				t.Fatal(o)
			}
		} else {
			if rr.Outcome != "failed" || len(rr.Observations) != 0 || len(rr.Diagnostics) != 1 || strings.Contains(rr.Diagnostics[0].Code, "secret") {
				t.Fatal(rr)
			}
		}
	}
}
func TestFailureTaxonomyNeverZero(t *testing.T) {
	for _, code := range []sshcli.Category{sshcli.UnknownKey, sshcli.ChangedKey, sshcli.AuthenticationFailed, sshcli.PermissionDenied, sshcli.ConnectionTimeout, sshcli.ExecutionTimeout, sshcli.Cancelled, sshcli.OutputTruncated, sshcli.CommandNotFound, sshcli.CommandFailed} {
		f := &fake{code: code}
		r, _ := linux.Registry().Collect(context.Background(), f, workspace.Principal{}, sshcli.Target{}, []string{"linux.uptime"})
		rr := r.Results[0]
		if len(rr.Observations) != 0 || rr.Diagnostics[0].Code != string(code) {
			t.Fatal(rr)
		}
	}
}
func TestConcurrentRequestGuardAndSnapshotIsolation(t *testing.T) {
	f := &fake{block: make(chan struct{})}
	s := collection.NewService(f, linux.Registry())
	target := sshcli.Target{AssetID: "asset", ProfileVersion: 1}
	p := workspace.Principal{ID: "actor"}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = s.Collect(context.Background(), p, target) }()
	deadline := time.Now().Add(time.Second)
	for {
		f.mu.Lock()
		n := f.calls
		f.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not started")
		}
		time.Sleep(time.Millisecond)
	}
	if _, e := s.Collect(context.Background(), p, target); !errors.Is(e, collection.ErrBusy) {
		t.Fatal(e)
	}
	close(f.block)
	<-done
	r, ok := s.Latest(p, target)
	if !ok {
		t.Fatal("missing snapshot")
	}
	r.Results[1].Observations[0].Key = "mutated"
	r2, _ := s.Latest(p, target)
	if r2.Results[1].Observations[0].Key == "mutated" {
		t.Fatal("shared result")
	}
	target.ProfileVersion++
	if _, ok := s.Latest(p, target); ok {
		t.Fatal("stale authority snapshot")
	}
	target.ProfileVersion--
	if _, ok := s.Latest(workspace.Principal{ID: "other"}, target); ok {
		t.Fatal("cross actor")
	}
}

func TestCollectionBudgetIncludesAdmissionWait(t *testing.T) {
	f := &fake{block: make(chan struct{})}
	svc := collection.NewService(f, linux.Registry())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.Collect(ctx, workspace.Principal{}, sshcli.Target{AssetID: string(rune('a' + i))})
		}()
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		f.mu.Lock()
		n := f.calls
		f.mu.Unlock()
		if n == 5 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("execution barrier")
		case <-ticker.C:
		}
	}
	start := time.Now()
	queued := collection.WithRequest(ctx, collection.Request{Source: "scheduled", Collectors: []string{"linux.uptime"}, Budget: time.Second})
	_, e := svc.Collect(queued, workspace.Principal{}, sshcli.Target{AssetID: "queued"})
	elapsed := time.Since(start)
	if !errors.Is(e, context.DeadlineExceeded) || elapsed > 1500*time.Millisecond {
		t.Errorf("admission exceeded total budget: %v %s", e, elapsed)
	}
	f.mu.Lock()
	n := f.calls
	f.mu.Unlock()
	if n != 5 {
		t.Error("expired queued request executed SSH", n)
	}
	close(f.block)
	wg.Wait()
}

type provenanceExecutor struct{ command string }

func (x provenanceExecutor) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, _ string) (sshcli.Result, error) {
	at := time.Now().UTC()
	return sshcli.Result{CommandID: x.command, StartedAt: at, EndedAt: at, Stdout: []byte("1 2")}, nil
}
func TestAlternateProvenanceIsExplicit(t *testing.T) {
	r, e := collection.NewRegistry([]collection.Spec{{ID: "linux.uptime", Version: "1", CommandID: "linux.uptime.v1", AlternateCommandIDs: []string{"reviewed.helper.v1"}, Parse: linux.Uptime}})
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"reviewed.helper.v1", "forged.command.v1"} {
		run, e := r.Collect(context.Background(), provenanceExecutor{id}, workspace.Principal{}, sshcli.Target{}, []string{"linux.uptime"})
		if e != nil {
			t.Fatal(e)
		}
		v := run.Results[0]
		if id == "reviewed.helper.v1" {
			if v.Outcome != "success" || v.CommandID != id || v.Observations[0].CommandID != id {
				t.Fatal(v)
			}
		} else if len(v.Observations) != 0 || v.Outcome != "failed" {
			t.Fatal("unreviewed provenance parsed", v)
		}
	}
}
