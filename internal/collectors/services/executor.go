package services

import (
	"context"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type Authority interface {
	IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error
}
type Executor struct {
	Next      collection.Executor
	Authority Authority
}

func (e Executor) Execute(ctx context.Context, p workspace.Principal, t sshcli.Target, id string) (sshcli.Result, error) {
	if id == Collector+".v1" {
		if e.Authority == nil {
			return sshcli.LocalResult(workspace.ErrDenied)
		}
		if err := e.Authority.IntegrationAllowed(ctx, p, t, "runtime_services"); err != nil {
			return sshcli.LocalResult(err)
		}
		ctx = sshcli.WithExecutionCheck(ctx, func(c context.Context) error { return e.Authority.IntegrationAllowed(c, p, t, "runtime_services") })
	}
	return e.Next.Execute(ctx, p, t, id)
}
