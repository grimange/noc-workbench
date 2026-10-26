package sshcli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"noc-workbench/internal/workspace"
)

// Explicit opt-in authorizes only a disposable sshd bound to 127.0.0.1. This
// fixture never reads personal keys/config or contacts enrolled infrastructure.
func TestRealOpenSSHLab(t *testing.T) {
	if os.Getenv("NOC_SSH_LAB") != "1" {
		t.Skip("set NOC_SSH_LAB=1 to authorize disposable loopback sshd")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"host", "identity", "wrong"} {
		if out, err := exec.Command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, name)).CombinedOutput(); err != nil {
			t.Fatalf("keygen: %v %s", err, out)
		}
	}
	pub, err := os.ReadFile(filepath.Join(dir, "identity.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "authorized"), pub, 0600); err != nil {
		t.Fatal(err)
	}
	host, err := os.ReadFile(filepath.Join(dir, "host.pub"))
	if err != nil {
		t.Fatal(err)
	}
	// Strip ssh-keygen's comment; independent fingerprint evidence comes from
	// the server-side host-key file, not network keyscan output.
	fields := strings.Fields(string(host))
	material := fields[0] + " " + fields[1]
	fp, err := Fingerprint(material)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("ListenAddress 127.0.0.1\nPort %d\nHostKey %s/host\nPidFile %s/pid\nAuthorizedKeysFile %s/authorized\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nAllowUsers %s\nAllowTcpForwarding no\nAllowAgentForwarding no\nPermitTTY no\nX11Forwarding no\nPermitUserRC no\n", port, dir, dir, dir, current.Username)
	if err = os.WriteFile(filepath.Join(dir, "sshd.conf"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "sshd.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	daemon := exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", filepath.Join(dir, "sshd.conf"))
	daemon.Stderr = log
	daemon.Stdout = log
	if err = daemon.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { daemon.Process.Kill(); daemon.Wait() }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, er := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
		if er == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lab sshd not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	p, _ := fixture(t)
	p.User = current.Username
	p.Port = uint16(port)
	p.HostKey = material
	p.Fingerprint = fp
	p.IdentityFile = filepath.Join(dir, "identity")
	key, _ := os.ReadFile(p.IdentityFile)
	p.IdentitySHA256 = digest(key)
	e, _ := New(approvalFunc(func(context.Context, workspace.Principal, Target, workspace.Permission) (Profile, error) {
		return p, nil
	}))
	candidates, err := e.Inspect(context.Background(), actor, p.Target)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Fingerprint != fp {
		t.Fatal("inspection not server identity")
	}
	for i := 0; i < 2; i++ {
		r, er := e.Execute(context.Background(), actor, p.Target, "lab.probe.v1")
		if er != nil {
			logs, _ := os.ReadFile(filepath.Join(dir, "sshd.log"))
			t.Fatalf("real SSH: %v; server: %s", er, logs)
		}
		if string(r.Stdout) != "NOC_WORKBENCH_SSH_LAB_OK\n" || r.ExitCode != 0 {
			t.Fatal("wrong lab result")
		}
	}
	// A substituted valid host key must fail inside real OpenSSH, even when the
	// caller has mistakenly approved that other fingerprint.
	other, _ := os.ReadFile(filepath.Join(dir, "wrong.pub"))
	f := strings.Fields(string(other))
	p.HostKey = f[0] + " " + f[1]
	p.Fingerprint, _ = Fingerprint(p.HostKey)
	_, err = e.Execute(context.Background(), actor, p.Target, "lab.probe.v1")
	category(t, err, ChangedKey)
	p.HostKey = material
	p.Fingerprint = fp
	p.IdentityFile = filepath.Join(dir, "wrong")
	key, _ = os.ReadFile(p.IdentityFile)
	p.IdentitySHA256 = digest(key)
	_, err = e.Execute(context.Background(), actor, p.Target, "lab.probe.v1")
	category(t, err, AuthenticationFailed)
	t.Log("PASS real loopback OpenSSH ordinary-user authentication, independent host fingerprint, inspection, repeated static command, changed-key and wrong-identity rejection")
}
