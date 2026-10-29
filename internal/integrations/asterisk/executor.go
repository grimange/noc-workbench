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
	if strings.HasPrefix(id, "asterisk.") && id != "asterisk.auth.v1" && id != "asterisk.auth.helper.v1" {
		deny := func() (sshcli.Result, error) {
			now := time.Now().UTC()
			return sshcli.Result{StartedAt: now, EndedAt: now, Category: sshcli.PermissionDenied}, &sshcli.Failure{Category: sshcli.PermissionDenied}
		}
		if e.Authority == nil || e.Authority.IntegrationAllowed(ctx, p, t, "asterisk") != nil {
			return deny()
		}
		helper := strings.Contains(id, ".helper.")
		if id == "asterisk.identity.v1" || id == "asterisk.registrations.v1" || id == "asterisk.activity.v1" || id == "asterisk.media.v1" {
			helper = e.Authority.IntegrationAllowed(ctx, p, t, "asterisk_helper") == nil
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
		if check(ctx) != nil {
			return deny()
		}
		ctx = sshcli.WithExecutionCheck(ctx, check)
	}
	return e.Next.Execute(ctx, p, t, id)
}
