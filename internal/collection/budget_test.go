package collection_test

import (
	"context"
	"fmt"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"testing"
	"time"
)

type deadlineExecutor struct {
	t      *testing.T
	want   time.Duration
	calls  int
	cancel context.CancelFunc
}

func (e *deadlineExecutor) Execute(ctx context.Context, _ workspace.Principal, _ sshcli.Target, _ string) (sshcli.Result, error) {
	e.calls++
	d, ok := ctx.Deadline()
	left := time.Until(d)
	if !ok || left > e.want || left < e.want-time.Second {
		e.t.Fatalf("aggregate deadline %s want %s", left, e.want)
	}
	if e.cancel != nil {
		e.cancel()
		<-ctx.Done()
		return sshcli.Result{}, &sshcli.Failure{Category: sshcli.Cancelled}
	}
	return sshcli.Result{}, nil
}
func TestExpandedScheduledBudgetBoundariesAndCancellation(t *testing.T) {
	var specs []collection.Spec
	for i := 0; i < 9; i++ {
		specs = append(specs, collection.Spec{ID: fmt.Sprint(i), Version: "1", CommandID: "fixed", Parse: func([]byte) ([]collection.Observation, []collection.Diagnostic) { return nil, nil }})
	}
	r, err := collection.NewRegistry(specs)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, source   string
		n              int
		budget, want   time.Duration
		reject, cancel bool
	}{
		{name: "eight legacy", source: "scheduled", n: 8, budget: 20 * time.Second, want: 20 * time.Second},
		{name: "eight", source: "scheduled", n: 8, budget: 40 * time.Second, want: 40 * time.Second},
		{name: "full Linux", source: "scheduled", n: 7, budget: 40 * time.Second, want: 40 * time.Second},
		{name: "nine", source: "scheduled", n: 9, budget: 40 * time.Second, want: 40 * time.Second},
		{name: "small rejected", source: "scheduled", n: 6, budget: 40 * time.Second, reject: true},
		{name: "over maximum", source: "scheduled", n: 9, budget: 41 * time.Second, reject: true},
		{name: "manual unchanged", n: 9, budget: 40 * time.Second, want: 10 * time.Second},
		{name: "cancellation", source: "scheduled", n: 9, budget: 40 * time.Second, want: 40 * time.Second, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			x := &deadlineExecutor{t: t, want: tc.want}
			if tc.cancel {
				x.cancel = cancel
			}
			s := collection.NewService(x, r)
			ctx = collection.WithRequest(ctx, collection.Request{Source: tc.source, Collectors: r.IDs()[:tc.n], Budget: tc.budget})
			run, err := s.Collect(ctx, workspace.Principal{}, sshcli.Target{AssetID: "synthetic"})
			if tc.reject {
				if err == nil || x.calls != 0 {
					t.Fatal("ineligible budget executed", err, x.calls)
				}
				return
			}
			if err != nil || x.calls != tc.n {
				t.Fatal(err, x.calls)
			}
			if tc.cancel && run.State == "completed" {
				t.Fatal("cancelled run completed")
			}
		})
	}
}
