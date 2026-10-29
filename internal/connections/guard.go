package connections

import (
	"context"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"time"
)

// DurableGuard records uncertainty BEFORE contact. A surviving marker is never
// evidence of approval: restart reconciliation invalidates the existing approval.
// Implementations must fail closed when storage is unavailable.
type DurableGuard interface {
	RecoverSSH(context.Context) error
	BeginSSH(context.Context, workspace.Principal, sshcli.Target) (string, error)
	SSHAllowed(context.Context, sshcli.Target, string) error
	EndSSH(context.Context, string, string) error
}
type guardContextKey struct{}

func (s *Service) beginSSH(ctx context.Context, p workspace.Principal, t sshcli.Target) (context.Context, string, error) {
	if g, ok := s.Repository.(DurableGuard); ok {
		token, e := g.BeginSSH(ctx, p, t)
		if e != nil {
			return ctx, "", e
		}
		return context.WithValue(ctx, guardContextKey{}, token), token, nil
	}
	return ctx, "", nil
}
func (s *Service) endSSH(ctx context.Context, id, token string) error {
	if g, ok := s.Repository.(DurableGuard); ok {
		// Cleanup acknowledges a durable database write, independently of the
		// remote execution deadline. Match collection persistence's bounded budget;
		// a missing acknowledgement still fails closed and retains recovery guards.
		for attempt := 0; attempt < 2; attempt++ {
			save, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			err := g.EndSSH(save, id, token)
			cancel()
			if err == nil {
				return nil
			}
			// Remote work has ended. An exact-token delete is safe to acknowledge
			// again after a lost response; never repeat an empty-token review.
			if token == "" {
				break
			}
		}
		return &sshcli.Failure{Category: sshcli.GuardUnavailable}
	}
	return nil
}
func (s *Service) guardAllowed(ctx context.Context, t sshcli.Target) error {
	if g, ok := s.Repository.(DurableGuard); ok {
		token, _ := ctx.Value(guardContextKey{}).(string)
		return g.SSHAllowed(ctx, t, token)
	}
	return nil
}
