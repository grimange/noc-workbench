package connections

import (
	"context"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"time"
)

// Execute is the Linux discovery adapter to the SAME shared NW-007 executor.
// Unlike enrollment verification, discovery requires a fully verified revision.
// This live guard is repeated for each command, including after earlier failures.
func (s *Service) Execute(ctx context.Context, p workspace.Principal, t sshcli.Target, id string) (sshcli.Result, error) {
	r, err := s.Repository.Enrollment(ctx, t.EndpointID, t.ProfileID)
	if err != nil || r.Target() != t || r.State != "connection_verified" {
		now := time.Now().UTC()
		return sshcli.Result{StartedAt: now, EndedAt: now, Category: sshcli.PermissionDenied}, &sshcli.Failure{Category: sshcli.PermissionDenied}
	}
	if s.allowed(p, sshcli.ExecutePermission, r) != nil {
		return sshcli.Result{}, workspace.ErrDenied
	}
	guarded, token, guardErr := s.beginSSH(ctx, p, t)
	if guardErr != nil {
		now := time.Now().UTC()
		return sshcli.Result{StartedAt: now, EndedAt: now, Category: sshcli.PermissionDenied}, &sshcli.Failure{Category: sshcli.PermissionDenied}
	}
	result, err := s.executor.Execute(guarded, p, t, id)
	if result.Category == sshcli.ChangedKey || result.Category == sshcli.UnknownKey {
		// Checking the remote identity is trust verification. Reuse the existing
		// verify audit operation, preserving the exact failed category and CAS revision.
		// Never let a restored old key silently resume discovery after this event.
		s.quarantined.Store(r.ID, true)
		clearTrust(&r)
		r.State = "identity_changed"
		now := time.Now().UTC()
		r.Details.AttemptedAt = &now
		r.Details.LastCategory = string(result.Category)
		saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if _, saveErr := s.Repository.SaveEnrollment(saveCtx, p, r, t.ProfileVersion, "verify"); saveErr != nil {
			// Keep the process quarantine until an explicit, successfully saved review.
			// Report a bounded category rather than storage errors or remote output.
			result.Category = sshcli.Internal
			return result, &sshcli.Failure{Category: sshcli.Internal}
		}
	}
	if e := s.endSSH(ctx, r.ID, token); e != nil {
		return result, &sshcli.Failure{Category: sshcli.Internal}
	}
	return result, err
}
