package sshcli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"noc-workbench/internal/workspace"
)

const id = "11111111-1111-4111-8111-111111111111"

var actor = workspace.Principal{ID: workspace.OperatorID}

type approvalFunc func(context.Context, workspace.Principal, Target, workspace.Permission) (Profile, error)

func (f approvalFunc) Approve(c context.Context, a workspace.Principal, t Target, p workspace.Permission) (Profile, error) {
	return f(c, a, t, p)
}
func fixture(t *testing.T) (Profile, *Executor) {
	t.Helper()
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(public)
	material := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	path := filepath.Join(t.TempDir(), "identity")
	b := []byte("synthetic identity")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	p := Profile{Target: Target{id, id, id, 1}, EndpointUpdatedAt: time.Now().UTC(), CustomerID: id, EnvironmentID: id, Host: "127.0.0.1", Address: "127.0.0.1", Port: 2222, User: "lab", IdentityFile: path, IdentitySHA256: digest(b), HostKey: material, Fingerprint: ssh.FingerprintSHA256(key)}
	e, _ := New(approvalFunc(func(_ context.Context, _ workspace.Principal, _ Target, _ workspace.Permission) (Profile, error) {
		return p, nil
	}))
	return p, e
}
func fake(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	return p
}
func category(t *testing.T, err error, want Category) {
	t.Helper()
	var f *Failure
	if !errors.As(err, &f) || f.Category != want {
		t.Fatalf("category=%v want=%s", err, want)
	}
}

func TestReviewedCommandDeadlines(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		ceiling time.Duration
		parent  time.Duration
		want    time.Duration
	}{
		{"baseline", "linux.baseline.v1", 20 * time.Second, time.Minute, 18 * time.Second},
		{"services", "linux.services.v1", 20 * time.Second, time.Minute, 12 * time.Second},
		{"ordinary", "linux.identity.v1", 20 * time.Second, time.Minute, 5 * time.Second},
		{"custom_ceiling", "linux.baseline.v1", 2 * time.Second, time.Minute, 2 * time.Second},
		{"collection_deadline", "linux.baseline.v1", 20 * time.Second, time.Second, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := DefaultLimits()
			if limits.TotalTimeout < registry["linux.baseline.v1"].timeout {
				t.Fatal("default ceiling truncates reviewed baseline deadline")
			}
			limits.TotalTimeout = tc.ceiling
			stop := errors.New("stop before remote execution")
			var remaining time.Duration
			e, err := NewWithLimits(approvalFunc(func(ctx context.Context, _ workspace.Principal, _ Target, _ workspace.Permission) (Profile, error) {
				deadline, ok := ctx.Deadline()
				if !ok {
					t.Fatal("missing execution deadline")
				}
				remaining = time.Until(deadline)
				return Profile{}, stop
			}), limits)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), tc.parent)
			defer cancel()
			_, err = e.Execute(ctx, actor, Target{AssetID: id}, tc.command)
			if !errors.Is(err, stop) {
				t.Fatalf("unexpected error: %v", err)
			}
			if remaining <= 0 || remaining > tc.want || remaining < tc.want-time.Second/2 {
				t.Fatalf("deadline %v, want %v", remaining, tc.want)
			}
		})
	}
}
func TestArgumentsAndStaticCommand(t *testing.T) {
	p, e := fixture(t)
	e.executable = fake(t, `for arg do printf '%s\n' "$arg"; done`)
	r, err := e.Execute(context.Background(), actor, p.Target, "lab.probe.v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"/dev/null", "-oStrictHostKeyChecking=yes", "-oBatchMode=yes", "-oIdentityAgent=none", "-oControlPath=none", "-oProxyCommand=none", "-oClearAllForwardings=yes", "printf 'NOC_WORKBENCH_SSH_LAB_OK\\n'"} {
		if !strings.Contains(string(r.Stdout), v) {
			t.Fatalf("missing %s", v)
		}
	}
	if r.ExitCode != 0 || r.Duration <= 0 || r.ProfileID != p.Target.ProfileID || r.ProfileVersion != p.Target.ProfileVersion || r.ActorID != actor.ID || len(r.Stderr) != 0 {
		t.Fatal("bad metadata")
	}
	_, err = e.Execute(context.Background(), actor, p.Target, "lab.probe.v1; touch /tmp/injected")
	category(t, err, Unsupported)
}
func TestTrustAndProfileChanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Profile)
		cat    Category
	}{
		{"unknown", func(p *Profile) { p.Fingerprint = "" }, UnknownKey},
		{"changed", func(p *Profile) { p.Fingerprint = "SHA256:wrong" }, ChangedKey},
		{"material", func(p *Profile) { p.HostKey = "command=evil ssh-ed25519 AAAA" }, Unsupported},
		{"revision", func(p *Profile) { p.Target.ProfileVersion++ }, InvalidTarget},
		{"destination", func(p *Profile) { p.Address = "127.0.0.2" }, InvalidTarget},
		{"identity", func(p *Profile) { p.IdentitySHA256 = strings.Repeat("0", 64) }, Unsupported},
		{"user", func(p *Profile) { p.User = "x; touch /tmp/injected" }, InvalidTarget},
		{"host", func(p *Profile) { p.Host = "-oProxyCommand=evil" }, InvalidTarget},
		{"scope", func(p *Profile) { p.EnvironmentID = "bad" }, InvalidTarget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, e := fixture(t)
			original := p.Target
			tc.change(&p)
			e.approval = approvalFunc(func(context.Context, workspace.Principal, Target, workspace.Permission) (Profile, error) {
				return p, nil
			})
			e.executable = "/must-not-start"
			_, err := e.Execute(context.Background(), actor, original, "lab.probe.v1")
			category(t, err, tc.cat)
		})
	}
	p, e := fixture(t)
	e.executable = fake(t, "exit 0")
	e.approval = approvalFunc(func(context.Context, workspace.Principal, Target, workspace.Permission) (Profile, error) {
		return p, errors.New("secret")
	})
	_, err := e.Execute(context.Background(), actor, p.Target, "lab.probe.v1")
	category(t, err, StorageFailure)
}
func TestDNSChange(t *testing.T) {
	p, e := fixture(t)
	p.Host = "synthetic.example.invalid"
	e.approval = approvalFunc(func(context.Context, workspace.Principal, Target, workspace.Permission) (Profile, error) {
		return p, nil
	})
	e.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.2")}}, nil
	}
	_, err := e.Execute(context.Background(), actor, p.Target, "lab.probe.v1")
	category(t, err, InvalidTarget)
}
func TestBoundedProcess(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		cat        Category
		timeout    time.Duration
	}{
		{"output", "while :; do printf 'synthetic-output'; done", OutputTruncated, time.Second},
		{"deadline", "sleep 60 & wait", ExecutionTimeout, 100 * time.Millisecond},
		{"missing", "exit 127", CommandNotFound, time.Second},
		{"failed", "exit 3", CommandFailed, time.Second},
		{"auth", "echo 'Permission denied (publickey).' >&2; exit 255", AuthenticationFailed, time.Second},
		{"connect_timeout", "echo 'ssh: connect to host 127.0.0.1 port 22: Connection timed out' >&2; exit 255", ConnectionTimeout, time.Second},
		{"banner_timeout", "printf 'Connection timed out during banner exchange\\nConnection to 127.0.0.1 port 22 timed out\\n' >&2; exit 255", ConnectionTimeout, time.Second},
		{"ambiguous_timeout", "echo 'remote diagnostic: Connection timed out during banner exchange' >&2; exit 255", Internal, time.Second},
		{"auth_before_banner", "printf 'Permission denied (publickey).\\nConnection timed out during banner exchange\\n' >&2; exit 255", AuthenticationFailed, time.Second},
		{"trust_before_banner", "printf 'REMOTE HOST IDENTIFICATION HAS CHANGED\\nConnection timed out during banner exchange\\n' >&2; exit 255", ChangedKey, time.Second},
		{"permission", "exit 126", PermissionDenied, time.Second},
		{"ambiguous", "echo 'secret' >&2; exit 255", Internal, time.Second},
		{"refused", "echo 'ssh: connect to host 127.0.0.1 port 22: Connection refused' >&2; exit 255", ConnectionRefused, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, e := fixture(t)
			e.executable = fake(t, tc.body)
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			start := time.Now()
			r, err := e.Execute(ctx, actor, p.Target, "lab.probe.v1")
			category(t, err, tc.cat)
			if time.Since(start) > 2*time.Second || len(r.Stdout) > 65536 || len(r.Stderr) > 0 {
				t.Fatal("unbounded process or diagnostics")
			}
		})
	}
	p, e := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := e.Execute(ctx, actor, p.Target, "lab.probe.v1")
	category(t, err, Cancelled)
}
func TestConcurrency(t *testing.T) {
	p, e := fixture(t)
	e.executable = fake(t, "sleep 0.05")
	var concurrent, peak atomic.Int32
	e.approval = approvalFunc(func(_ context.Context, _ workspace.Principal, tg Target, perm workspace.Permission) (Profile, error) {
		if perm == ProfileUse {
			n := concurrent.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(15 * time.Millisecond)
			concurrent.Add(-1)
		}
		q := p
		q.Target = tg
		return q, nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tg := p.Target
			tg.AssetID = fmt.Sprintf("%08x-1111-4111-8111-111111111111", i)
			if _, err := e.Execute(context.Background(), actor, tg, "lab.probe.v1"); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if peak.Load() > 5 {
		t.Fatal("global limit")
	}
	peak.Store(0)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.Execute(context.Background(), actor, p.Target, "lab.probe.v1"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if peak.Load() != 1 || len(e.hosts) != 0 {
		t.Fatal("host limit or capacity leak")
	}
}

func TestChildTreeAndCapacityRelease(t *testing.T) {
	p, e := fixture(t)
	pidfile := filepath.Join(t.TempDir(), "pid")
	e.executable = fake(t, "sleep 60 &\nprintf '%s' $! > '"+pidfile+"'\nwait")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := e.Execute(ctx, actor, p.Target, "lab.probe.v1")
	category(t, err, ExecutionTimeout)
	b, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatal("child never started")
	}
	// A dead orphan may briefly be a zombie or kernel-dead task awaiting the OS reaper. It must
	// never remain running, and the adapter must have reaped its direct child.
	state, err := os.ReadFile("/proc/" + string(b) + "/stat")
	if err == nil && !strings.Contains(string(state), ") Z ") && !strings.Contains(string(state), ") X ") {
		t.Fatalf("descendant survived: %s", state)
	}
	e.executable = fake(t, "exit 0")
	if _, err = e.Execute(context.Background(), actor, p.Target, "lab.probe.v1"); err != nil {
		t.Fatal("capacity not released", err)
	}
	if len(e.hosts) != 0 {
		t.Fatal("host gate leaked")
	}
}
func TestInspectionApprovalAndKeyMaterial(t *testing.T) {
	p, e := fixture(t)
	e.approval = approvalFunc(func(context.Context, workspace.Principal, Target, workspace.Permission) (Profile, error) {
		return p, errors.New("denied")
	})
	_, err := e.Inspect(context.Background(), actor, p.Target)
	category(t, err, PermissionDenied)
	for _, material := range []string{p.HostKey + " comment", p.HostKey + "\n" + p.HostKey, strings.Repeat("x", 16385), "garbage"} {
		if _, err := Fingerprint(material); err == nil {
			t.Fatal("malformed material accepted")
		}
	}
	if _, err := Trust(p.HostKey, p.Fingerprint); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredLimits(t *testing.T) {
	p, e := fixture(t)
	limits := DefaultLimits()
	limits.OutputBytes = 8
	limits.GlobalHosts = 2
	limits.TotalTimeout = 100 * time.Millisecond
	e, err := NewWithLimits(e.approval, limits)
	if err != nil {
		t.Fatal(err)
	}
	e.executable = fake(t, "printf 1234567890")
	r, err := e.Execute(context.Background(), actor, p.Target, "lab.probe.v1")
	category(t, err, OutputTruncated)
	if len(r.Stdout) != 8 || cap(e.global) != 2 {
		t.Fatal("limits not applied")
	}
	limits.GlobalHosts = 6
	if _, err = NewWithLimits(e.approval, limits); err == nil {
		t.Fatal("unreviewed capacity accepted")
	}
}

func TestCancellationDuringAuthorizationAndDNS(t *testing.T) {
	for _, where := range []string{"approval", "dns"} {
		t.Run(where, func(t *testing.T) {
			p, e := fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if where == "approval" {
				e.approval = approvalFunc(func(context.Context, workspace.Principal, Target, workspace.Permission) (Profile, error) {
					cancel()
					return p, context.Canceled
				})
			} else {
				p.Host = "lab.example.invalid"
				e.approval = approvalFunc(func(context.Context, workspace.Principal, Target, workspace.Permission) (Profile, error) {
					return p, nil
				})
				e.lookup = func(context.Context, string) ([]net.IPAddr, error) { cancel(); return nil, context.Canceled }
			}
			_, err := e.Execute(ctx, actor, p.Target, "lab.probe.v1")
			category(t, err, Cancelled)
		})
	}
}

func TestExecutionCheckAfterCapacity(t *testing.T) {
	p, e := fixture(t)
	e.executable = "/must-not-start"
	release, err := e.acquire(context.Background(), p.Target.AssetID)
	if err != nil {
		t.Fatal(err)
	}
	var allowed atomic.Bool
	allowed.Store(true)
	called := make(chan struct{}, 1)
	ctx := WithExecutionCheck(context.Background(), func(context.Context) error {
		called <- struct{}{}
		if !allowed.Load() {
			return workspace.ErrDenied
		}
		return nil
	})
	done := make(chan error, 1)
	go func() { _, err := e.Execute(ctx, actor, p.Target, "asterisk.identity.v1"); done <- err }()
	// The authority is revoked while capacity is held; no child may start.
	allowed.Store(false)
	release()
	category(t, <-done, PermissionDenied)
	select {
	case <-called:
	default:
		t.Fatal("post-capacity check missing")
	}
}

func TestRegistrationStaticAllowlist(t *testing.T) {
	p, e := fixture(t)
	e.executable = fake(t, `for arg do printf '%s\n' "$arg"; done`)
	r, err := e.Execute(context.Background(), actor, p.Target, "asterisk.registrations.v1")
	if err != nil {
		t.Fatal(err)
	}
	text := string(r.Stdout)
	for _, command := range []string{"core show version", "sip show peers", "sip show registry", "pjsip show endpoints", "pjsip show contacts", "pjsip show registrations"} {
		if strings.Count(text, "asterisk -rx '"+command+"'") != 1 {
			t.Fatal("fixed command missing or duplicated", command)
		}
	}
	for _, forbidden := range []string{"sudo ", "asterisk -rx \"", "restart", " reload", " -L", " -R"} {
		if strings.Contains(text, forbidden) {
			t.Fatal("unexpected authority", forbidden)
		}
	}
	for _, id := range []string{"asterisk.registrations.v1; core stop now", "sip show peers", "asterisk.registrations.v1 $(id)"} {
		_, err = e.Execute(context.Background(), actor, p.Target, id)
		category(t, err, Unsupported)
	}
}

func TestActivityFixedSnapshotAllowlist(t *testing.T) {
	p, e := fixture(t)
	e.executable = fake(t, `for arg do printf '%s\n' "$arg"; done`)
	r, err := e.Execute(context.Background(), actor, p.Target, "asterisk.activity.v1")
	if err != nil {
		t.Fatal(err)
	}
	text := string(r.Stdout)
	for _, fixed := range []string{"core show version", "core show channels concise", "bridge show all", "meetme list concise", "confbridge list"} {
		if strings.Count(text, "asterisk -rx '"+fixed+"'") != 1 {
			t.Fatal("fixed activity command missing", fixed)
		}
	}
	if !strings.Contains(text, "set -e;") || !strings.Contains(text, "-oClearAllForwardings=yes") {
		t.Fatal("failure or no-forwarding boundary weakened")
	}
	for _, id := range []string{"asterisk.activity.v1; id", "asterisk.activity.helper.v1 room", "confbridge list room", "asterisk.activity.v1 $(id)"} {
		_, err = e.Execute(context.Background(), actor, p.Target, id)
		category(t, err, Unsupported)
	}
	r, err = e.Execute(context.Background(), actor, p.Target, "asterisk.activity.helper.v1")
	if err != nil || !strings.Contains(string(r.Stdout), "/usr/bin/sudo -n -- /usr/local/sbin/noc-asterisk-observe activity") {
		t.Fatal("fixed helper argument", err)
	}
}

func TestMediaFixedSnapshotAllowlist(t *testing.T) {
	p, e := fixture(t)
	e.executable = fake(t, `for arg do printf '%s\n' "$arg"; done`)
	r, err := e.Execute(context.Background(), actor, p.Target, "asterisk.media.v1")
	if err != nil {
		t.Fatal(err)
	}
	text := string(r.Stdout)
	if !strings.Contains(text, "set -e;") || !strings.Contains(text, "-oClearAllForwardings=yes") {
		t.Fatal("failure/forwarding boundary", text)
	}
	for _, c := range []string{"core show version", "sip show channelstats", "pjsip show channelstats"} {
		if strings.Count(text, "asterisk -rx '"+c+"'") != 1 {
			t.Fatal(c)
		}
	}
	for _, id := range []string{"asterisk.media.v1; id", "asterisk.media.helper.v1 extra", "sip show channelstats"} {
		_, err = e.Execute(context.Background(), actor, p.Target, id)
		category(t, err, Unsupported)
	}
	r, err = e.Execute(context.Background(), actor, p.Target, "asterisk.media.helper.v1")
	if err != nil || !strings.Contains(string(r.Stdout), "/usr/bin/sudo -n -- /usr/local/sbin/noc-asterisk-observe media") {
		t.Fatal(err)
	}
}
