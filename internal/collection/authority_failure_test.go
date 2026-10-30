package collection_test

import (
	"context"
	"errors"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/baseline"
	"noc-workbench/internal/collectors/services"
	"noc-workbench/internal/integrations/asterisk"
	auth "noc-workbench/internal/integrations/asteriskauth"
	"noc-workbench/internal/integrations/mariadb"
	"noc-workbench/internal/integrations/vicidialdiscovery"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"testing"
)

type unavailableAuthority struct {
	cause  error
	cursor bool
}

func (a unavailableAuthority) IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error {
	if a.cursor {
		return nil
	}
	return a.cause
}
func (a unavailableAuthority) AuthCursors(context.Context, workspace.Principal, sshcli.Target) (map[string]auth.Cursor, error) {
	return nil, a.cause
}
func TestCapabilityStorageErrorsDoNotBecomeDenial(t *testing.T) {
	cause := errors.New("private fixture storage failure")
	for _, cursor := range []bool{false, true} {
		a := unavailableAuthority{cause: cause, cursor: cursor}
		executors := []struct {
			id       string
			executor collection.Executor
		}{
			{"asterisk.auth.v1", auth.Executor{Repository: a}},
		}
		if !cursor {
			executors = append(executors, []struct {
				id       string
				executor collection.Executor
			}{
				{"linux.baseline.v1", baseline.Executor{Authority: a}}, {"linux.services.v1", services.Executor{Authority: a}},
				{"vicidial.discovery.v1", vicidialdiscovery.Executor{Authority: a}}, {"asterisk.registrations.v1", asterisk.Executor{Authority: a}},
				{"mariadb.health.v1", mariadb.Executor{Authority: a}},
			}...)
		}
		for _, x := range executors {
			r, err := x.executor.Execute(context.Background(), workspace.Principal{}, sshcli.Target{}, x.id)
			if r.Category != sshcli.StorageFailure || !errors.Is(err, cause) {
				t.Fatalf("%s cursor=%v: %s %v", x.id, cursor, r.Category, err)
			}
		}
	}
}
