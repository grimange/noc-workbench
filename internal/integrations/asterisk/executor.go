package asterisk

import (
	"context"
	"errors"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
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
	if strings.HasPrefix(id, "asterisk.") && id != "asterisk.auth.v1" && id != "asterisk.auth.helper.v1" {
		if e.Authority == nil {
			return sshcli.LocalResult(workspace.ErrDenied)
		}
		if err := e.Authority.IntegrationAllowed(ctx, p, t, "asterisk"); err != nil {
			return sshcli.LocalResult(err)
		}
		helper := strings.Contains(id, ".helper.")
		if id == "asterisk.identity.v1" || id == "asterisk.registrations.v1" || id == "asterisk.activity.v1" || id == "asterisk.media.v1" {
			helperErr := e.Authority.IntegrationAllowed(ctx, p, t, "asterisk_helper")
			if helperErr != nil && !errors.Is(helperErr, workspace.ErrDenied) {
				return sshcli.LocalResult(helperErr)
			}
			helper = helperErr == nil
			if helper {
				id = strings.TrimSuffix(id, ".v1") + ".helper.v1"
			}
		}
		check := func(c context.Context) error {
			if strings.HasPrefix(id, "asterisk.media.") {
				if err := e.Authority.IntegrationAllowed(c, p, t, "asterisk_media"); err != nil {
					return err
				}
				if err := e.Authority.IntegrationAllowed(c, p, t, "asterisk_activity"); err != nil {
					return err
				}
			}
			if strings.HasPrefix(id, "asterisk.activity.") {
				if err := e.Authority.IntegrationAllowed(c, p, t, "asterisk_activity"); err != nil {
					return err
				}
			}
			if err := e.Authority.IntegrationAllowed(c, p, t, "asterisk"); err != nil {
				return err
			}
			if helper {
				return e.Authority.IntegrationAllowed(c, p, t, "asterisk_helper")
			}
			return nil
		}
		if err := check(ctx); err != nil {
			return sshcli.LocalResult(err)
		}
		ctx = sshcli.WithExecutionCheck(ctx, check)
	}
	return e.Next.Execute(ctx, p, t, id)
}
