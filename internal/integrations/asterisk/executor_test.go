package asterisk

import (
	"context"
	"errors"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type grantAuthority map[string]bool

func (a grantAuthority) IntegrationAllowed(_ context.Context, _ workspace.Principal, _ sshcli.Target, n string) error {
	if !a[n] {
		return workspace.ErrDenied
	}
	return nil
}

type commandRecorder struct {
	id    string
	calls int
}

func (r *commandRecorder) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, id string) (sshcli.Result, error) {
	r.id = id
	r.calls++
	return sshcli.Result{CommandID: id}, nil
}
func TestGatewaySelectionRequiresBothGrants(t *testing.T) {
	for _, tc := range []struct {
		asterisk, helper bool
		id, want         string
		denied           bool
	}{
		{false, false, "asterisk.identity.v1", "", true}, {false, true, "asterisk.identity.helper.v1", "", true},
		{true, false, "asterisk.identity.helper.v1", "", true}, {true, false, "asterisk.identity.v1", "asterisk.identity.v1", false},
		{true, true, "asterisk.identity.v1", "asterisk.identity.helper.v1", false},
		{true, true, "asterisk.registrations.v1", "asterisk.registrations.helper.v1", false},
		{true, true, "asterisk.channels.v1", "asterisk.channels.v1", false},
	} {
		r := &commandRecorder{}
		a := grantAuthority{"asterisk": tc.asterisk, "asterisk_helper": tc.helper}
		_, e := (Executor{Next: r, Authority: a}).Execute(context.Background(), workspace.Principal{}, sshcli.Target{}, tc.id)
		if (e != nil) != tc.denied || r.id != tc.want {
			t.Fatal(tc, r, e)
		}
	}
}
func TestFixedGatewayArgumentsAndFraming(t *testing.T) {
	b, e := os.ReadFile("../../../scripts/asterisk-observe")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "asterisk")
	gateway := filepath.Join(dir, "gateway")
	// Only the test copy replaces the absolute binary path. The installed script
	// has no environment-controlled executable or command substitution.
	if e = os.WriteFile(fake, []byte("#!/bin/sh\ncase \"$4\" in 'core show version') echo 'Asterisk 18.26.4-vici built on Linux';; *) echo \"No such command '$4'\"; exit 1;; esac\n"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(gateway, []byte(strings.ReplaceAll(string(b), "/usr/sbin/asterisk", fake)), 0700); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{nil, {"arbitrary"}, {"identity", "extra"}, {"registrations;core restart now"}} {
		if e := exec.Command(gateway, args...).Run(); e == nil {
			t.Fatal("accepted arguments", args)
		}
	}
	out, e := exec.Command(gateway, "registrations").Output()
	if e != nil {
		t.Fatal(e)
	}
	obs, d := Registrations(out)
	if len(d) != 0 || len(obs) != 5 {
		t.Fatalf("framing or unsupported exit handling: %s %+v", out, d)
	}
	if e = os.WriteFile(fake, []byte("#!/bin/sh\nexec sleep 30\n"), 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	if e = exec.CommandContext(ctx, gateway, "identity").Run(); e == nil || ctx.Err() != nil {
		t.Fatal("gateway deadline not enforced", e, ctx.Err())
	}
}

// The downstream transport rechecks both grants after waiting for capacity.
type revokeBeforeTransport struct {
	authority grantAuthority
	revoke    string
	next      collection.Executor
}

func (x revokeBeforeTransport) Execute(c context.Context, p workspace.Principal, t sshcli.Target, id string) (sshcli.Result, error) {
	x.authority[x.revoke] = false
	return x.next.Execute(c, p, t, id)
}

type noTransportApproval struct{ t *testing.T }

func (a noTransportApproval) Approve(context.Context, workspace.Principal, sshcli.Target, workspace.Permission) (sshcli.Profile, error) {
	a.t.Error("revoked capability reached transport approval")
	return sshcli.Profile{}, workspace.ErrDenied
}
func TestGatewayRevocationAtTransportBoundary(t *testing.T) {
	for _, capability := range []string{"asterisk", "asterisk_helper"} {
		t.Run(capability, func(t *testing.T) {
			authority := grantAuthority{"asterisk": true, "asterisk_helper": true}
			transport, err := sshcli.New(noTransportApproval{t})
			if err != nil {
				t.Fatal(err)
			}
			id := "11111111-1111-4111-8111-111111111111"
			target := sshcli.Target{AssetID: id, EndpointID: id, ProfileID: id, ProfileVersion: 1}
			next := revokeBeforeTransport{authority, capability, transport}
			_, err = (Executor{Next: next, Authority: authority}).Execute(context.Background(), workspace.Principal{ID: workspace.OperatorID}, target, "asterisk.registrations.v1")
			var f *sshcli.Failure
			if !errors.As(err, &f) || f.Category != sshcli.PermissionDenied {
				t.Fatal(err)
			}
		})
	}
}

func TestMediaGatewayChildFailures(t *testing.T) {
	b, e := os.ReadFile("../../../scripts/asterisk-observe")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "asterisk")
	gateway := filepath.Join(dir, "gateway")
	if e = os.WriteFile(gateway, []byte(strings.ReplaceAll(string(b), "/usr/sbin/asterisk", fake)), 0700); e != nil {
		t.Fatal(e)
	}
	for _, failed := range []string{"core show version", "sip show channelstats", "pjsip show channelstats"} {
		script := "#!/bin/sh\ncase \"$4\" in '" + failed + "') echo partial;exit 1;; *) echo ok;; esac\n"
		if e = os.WriteFile(fake, []byte(script), 0700); e != nil {
			t.Fatal(e)
		}
		out, e := exec.Command(gateway, "media").CombinedOutput()
		if e == nil || strings.Contains(string(out), "NW_MEDIA_END") {
			t.Fatalf("failed child %s accepted: %s %v", failed, out, e)
		}
	}
}
