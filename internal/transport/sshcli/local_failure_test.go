package sshcli

import (
	"context"
	"errors"
	"noc-workbench/internal/workspace"
	"strings"
	"testing"
)

func TestLocalFailureClassificationAndCause(t *testing.T) {
	secret := errors.New("private storage details")
	for _, tc := range []struct {
		cause error
		want  Category
	}{
		{secret, StorageFailure}, {context.Canceled, Cancelled}, {context.DeadlineExceeded, ExecutionTimeout}, {workspace.ErrDenied, PermissionDenied},
		{&Failure{Category: GuardConflict}, GuardConflict}, {&Failure{Category: GuardUncertain}, GuardUncertain},
	} {
		err := LocalFailure(tc.cause)
		var f *Failure
		if !errors.As(err, &f) || f.Category != tc.want || !errors.Is(err, tc.cause) || strings.Contains(err.Error(), "private") {
			t.Fatalf("classification/cause: %v", err)
		}
	}
}

func TestFinalApprovalLocalFailureDoesNotBecomeDenial(t *testing.T) {
	for _, boundary := range []string{"check", "profile", "execute"} {
		t.Run(boundary, func(t *testing.T) {
			p, e := fixture(t)
			cause := errors.New("private database failure")
			e.executable = "/must-not-start"
			e.approval = approvalFunc(func(_ context.Context, _ workspace.Principal, _ Target, permission workspace.Permission) (Profile, error) {
				if boundary == "profile" || boundary == "execute" && permission == ExecutePermission {
					return Profile{}, cause
				}
				return p, nil
			})
			ctx := context.Background()
			if boundary == "check" {
				ctx = WithExecutionCheck(ctx, func(context.Context) error { return cause })
			}
			r, err := e.Execute(ctx, actor, p.Target, "lab.probe.v1")
			if r.Category != StorageFailure || !errors.Is(err, cause) {
				t.Fatalf("lost local cause: %v %v", r.Category, err)
			}
		})
	}
}
