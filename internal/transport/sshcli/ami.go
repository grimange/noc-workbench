package sshcli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

// AMICredential is an administrator-owned, protected catalog entry. Only its ID
// and digest enter the database. Neither the browser nor the database chooses
// a forwarding destination or supplies a password/private key.
type AMICredential struct {
	ID, ProfileID                         string
	ProfileVersion                        int64
	SSHUser, IdentityFile, IdentitySHA256 string
	Port                                  uint16
	Username, Secret                      string
	Enabled                               bool
}

func (c AMICredential) Valid() bool {
	return c.SSHUser != "root" && len(c.ID) > 0 && len(c.ID) <= 64 && userPattern.MatchString(c.ID) && inventory.ValidID(c.ProfileID) && c.ProfileVersion > 0 && userPattern.MatchString(c.SSHUser) && filepath.IsAbs(c.IdentityFile) && !strings.ContainsAny(c.IdentityFile, "%\r\n\x00") && len(c.IdentitySHA256) == 64 && c.Port > 0 && userPattern.MatchString(c.Username) && len(c.Secret) >= 16 && len(c.Secret) <= 256 && !strings.ContainsAny(c.Secret, "\r\n\x00")
}
func AMIDigest(c AMICredential) string { b, _ := json.Marshal(c); return digest(b) }
func ReadAMICredentials(path string) ([]AMICredential, error) {
	if path == "" {
		return nil, nil
	}
	b, err := protectedRead(path, 65536)
	if err != nil {
		return nil, err
	}
	var entries []AMICredential
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&entries) != nil || d.Decode(new(any)) != io.EOF || len(entries) > 32 {
		return nil, fail(Unsupported)
	}
	seen := map[string]bool{}
	for _, c := range entries {
		if !c.Valid() || seen[c.ID] {
			return nil, fail(Unsupported)
		}
		seen[c.ID] = true
	}
	return entries, nil
}

type AMIApproval interface {
	ApproveAMI(context.Context, workspace.Principal, Target) (Profile, error)
}
type AMIForwarder struct {
	Approval   AMIApproval
	executable string
}

func NewAMIForwarder(a AMIApproval) *AMIForwarder {
	return &AMIForwarder{Approval: a, executable: "/usr/bin/ssh"}
}

// Check refreshes enrollment, host-key approval and both protected credentials
// without contacting the server. Managed sessions repeat this while connected.
func (f *AMIForwarder) Check(ctx context.Context, actor workspace.Principal, t Target, c AMICredential) error {
	if f.Approval == nil || !c.Valid() || !c.Enabled || c.ProfileID != t.ProfileID || c.ProfileVersion != t.ProfileVersion {
		return fail(PermissionDenied)
	}
	p, err := f.Approval.ApproveAMI(ctx, actor, t)
	if err != nil {
		return LocalFailure(err)
	}
	if err = validProfile(p, t); err != nil {
		return err
	}
	if _, err = Trust(p.HostKey, p.Fingerprint); err != nil {
		return err
	}
	key, err := protectedRead(c.IdentityFile, 1024*1024)
	if err != nil || digest(key) != c.IdentitySHA256 {
		return fail(PermissionDenied)
	}
	return nil
}

// Open opens only direct-tcpip to the protected catalog's loopback AMI port.
// It deliberately neither uses nor relaxes the ordinary command executor.
func (f *AMIForwarder) Open(ctx context.Context, actor workspace.Principal, t Target, c AMICredential) (io.ReadWriteCloser, error) {
	if f.Approval == nil || !c.Valid() || !c.Enabled || c.ProfileID != t.ProfileID || c.ProfileVersion != t.ProfileVersion {
		return nil, fail(PermissionDenied)
	}
	p, err := f.Approval.ApproveAMI(ctx, actor, t)
	if err != nil {
		return nil, LocalFailure(err)
	}
	if validProfile(p, t) != nil {
		return nil, fail(InvalidTarget)
	}
	e := &Executor{lookup: net.DefaultResolver.LookupIPAddr}
	if err = e.resolve(ctx, p); err != nil {
		return nil, err
	}
	if _, err = Trust(p.HostKey, p.Fingerprint); err != nil {
		return nil, err
	}
	key, err := protectedRead(c.IdentityFile, 1024*1024)
	if err != nil || digest(key) != c.IdentitySHA256 {
		return nil, fail(PermissionDenied)
	}
	dir, err := os.MkdirTemp("", "nw-ami-")
	if err != nil {
		return nil, fail(Internal)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	identity, known := filepath.Join(dir, "identity"), filepath.Join(dir, "known_hosts")
	alias := "nw-ami-" + digest([]byte(p.Fingerprint))
	if os.WriteFile(identity, key, 0600) != nil || os.WriteFile(known, []byte(alias+" "+strings.TrimSpace(p.HostKey)+"\n"), 0600) != nil {
		cleanup()
		return nil, fail(Internal)
	}
	args := []string{"-F", "/dev/null", "-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oRequestTTY=no", "-oForwardAgent=no", "-oForwardX11=no", "-oForwardX11Trusted=no", "-oTunnel=no", "-oAddKeysToAgent=no", "-oEnableSSHKeysign=no", "-oEscapeChar=none", "-oClearAllForwardings=yes", "-oExitOnForwardFailure=yes", "-oControlMaster=no", "-oControlPath=none", "-oControlPersist=no", "-oProxyCommand=none", "-oProxyJump=none", "-oPermitLocalCommand=no", "-oLocalCommand=none", "-oKnownHostsCommand=none", "-oCanonicalizeHostname=no", "-oVerifyHostKeyDNS=no", "-oUpdateHostKeys=no", "-oGlobalKnownHostsFile=/dev/null", "-oUserKnownHostsFile=" + known, "-oHostKeyAlias=" + alias, "-oIdentityAgent=none", "-oIdentitiesOnly=yes", "-oPasswordAuthentication=no", "-oKbdInteractiveAuthentication=no", "-oPreferredAuthentications=publickey", "-oConnectionAttempts=1", "-oConnectTimeout=5", "-oServerAliveInterval=10", "-oServerAliveCountMax=2", "-i", identity, "-p", strconv.Itoa(int(p.Port)), "-l", c.SSHUser, "-W", "127.0.0.1:" + strconv.Itoa(int(c.Port)), "--", p.Address}
	child, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(child, f.executable, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 250 * time.Millisecond
	stderr := &capped{remaining: 8192, stop: func() {}}
	cmd.Stderr = stream{stderr, true}
	in, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		cleanup()
		return nil, fail(Internal)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		cancel()
		cleanup()
		return nil, fail(Internal)
	}
	if err = cmd.Start(); err != nil {
		in.Close()
		out.Close()
		cancel()
		cleanup()
		return nil, fail(Internal)
	}
	s := &amiPipe{in: in, out: out, cancel: cancel, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); cleanup(); close(s.done) }()
	return s, nil
}

type amiPipe struct {
	in     io.WriteCloser
	out    io.ReadCloser
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func (s *amiPipe) Read(b []byte) (int, error)  { return s.out.Read(b) }
func (s *amiPipe) Write(b []byte) (int, error) { return s.in.Write(b) }
func (s *amiPipe) Close() error {
	s.once.Do(func() { s.cancel(); s.in.Close(); s.out.Close(); <-s.done })
	return nil
}
