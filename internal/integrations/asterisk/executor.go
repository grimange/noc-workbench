package asterisk

import (
	"context"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
	"time"
)

// Authority is the existing application's scoped, durable opt-in boundary.
// It supplements SSH enrollment; it never grants transport authority.
type Authority interface {
	IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error
}
type Executor struct {
	Next      collection.Executor
	Authority Authority
}

func (e Executor) Execute(ctx context.Context, p workspace.Principal, t sshcli.Target, id string) (sshcli.Result, error) {
	if strings.HasPrefix(id, "asterisk.") {
		if e.Authority == nil || e.Authority.IntegrationAllowed(ctx, p, t, "asterisk") != nil {
			now := time.Now().UTC()
			return sshcli.Result{StartedAt: now, EndedAt: now, Category: sshcli.PermissionDenied}, &sshcli.Failure{Category: sshcli.PermissionDenied}
		}
		ctx = sshcli.WithExecutionCheck(ctx, func(c context.Context) error { return e.Authority.IntegrationAllowed(c, p, t, "asterisk") })
	}
	return e.Next.Execute(ctx, p, t, id)
}
