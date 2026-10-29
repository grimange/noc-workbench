package connections

import (
	"context"
	"errors"
	"testing"
	"time"

	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type cleanupRepository struct {
	Repository
	end func(context.Context, string, string) error
}

func (r cleanupRepository) RecoverSSH(context.Context) error { return nil }
func (r cleanupRepository) BeginSSH(context.Context, workspace.Principal, sshcli.Target) (string, error) {
	return "token", nil
}
func (r cleanupRepository) SSHAllowed(context.Context, sshcli.Target, string) error { return nil }
func (r cleanupRepository) EndSSH(ctx context.Context, profile, token string) error {
	return r.end(ctx, profile, token)
}

func TestGuardCleanupPersistenceBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Completed or cancelled remote work must not cancel cleanup.
	called := false
	s := Service{Repository: cleanupRepository{end: func(save context.Context, profile, token string) error {
		called = true
		if save.Err() != nil || profile != "profile" || token != "token" {
			t.Fatal("cleanup lost its independent context or exact guard identity")
		}
		deadline, ok := save.Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining <= time.Second || remaining > 2*time.Second {
			t.Fatalf("cleanup persistence budget: %v", remaining)
		}
		return nil
	}}}
	if err := s.endSSH(ctx, "profile", "token"); err != nil || !called {
		t.Fatalf("cleanup acknowledgement: %v", err)
	}
}

func TestGuardCleanupFailureIsLocalAndSanitized(t *testing.T) {
	attempts := 0
	s := Service{Repository: cleanupRepository{end: func(context.Context, string, string) error {
		attempts++
		return errors.New("sensitive storage detail")
	}}}
	err := s.endSSH(context.Background(), "profile", "token")
	var failure *sshcli.Failure
	if !errors.As(err, &failure) || failure.Category != sshcli.GuardUnavailable || err.Error() != "SSH transport: ssh_guard_unavailable" {
		t.Fatalf("cleanup must fail closed with only its local diagnostic: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("cleanup must remain bounded: %d attempts", attempts)
	}
}

func TestGuardCleanupLostAcknowledgement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempts := 0
	s := Service{Repository: cleanupRepository{end: func(save context.Context, profile, token string) error {
		attempts++
		if save.Err() != nil || profile != "profile" || token != "exact-token" {
			t.Fatal("retry lost its independent budget or token")
		}
		if attempts == 1 {
			return context.DeadlineExceeded // DELETE may already have committed.
		}
		return nil
	}}}
	if e := s.endSSH(ctx, "profile", "exact-token"); e != nil || attempts != 2 {
		t.Fatalf("acknowledgement recovery: %d %v", attempts, e)
	}
}

func TestGuardReviewCleanupIsNotRetried(t *testing.T) {
	attempts := 0
	s := Service{Repository: cleanupRepository{end: func(context.Context, string, string) error {
		attempts++
		return context.DeadlineExceeded
	}}}
	if s.endSSH(context.Background(), "profile", "") == nil || attempts != 1 {
		t.Fatal("empty-token review must not be retried automatically")
	}
}
