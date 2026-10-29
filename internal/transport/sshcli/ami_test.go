package sshcli

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"noc-workbench/internal/workspace"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type amiApprovalFunc func(context.Context, workspace.Principal, Target) (Profile, error)

func (f amiApprovalFunc) ApproveAMI(c context.Context, p workspace.Principal, t Target) (Profile, error) {
	return f(c, p, t)
}
func TestAMIForwardingIsSeparateAndFixed(t *testing.T) {
	p, _ := fixture(t)
	c := AMICredential{ID: "synthetic", ProfileID: p.Target.ProfileID, ProfileVersion: 1, SSHUser: "amionly", IdentityFile: p.IdentityFile, IdentitySHA256: p.IdentitySHA256, Port: 5038, Username: "monitor", Secret: "synthetic-secret-value", Enabled: true}
	f := NewAMIForwarder(amiApprovalFunc(func(context.Context, workspace.Principal, Target) (Profile, error) { return p, nil }))
	f.executable = fake(t, `for arg do printf '%s\n' "$arg"; done; cat >/dev/null`)
	stream, e := f.Open(context.Background(), actor, p.Target, c)
	if e != nil {
		t.Fatal(e)
	}
	// Read exactly the argv lines; the fake process remains alive until Close.
	var lines []string
	reader := bufio.NewReader(stream)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
		if strings.TrimSpace(line) == p.Address {
			break
		}
	}
	out := strings.Join(lines, "")
	stream.Close()
	for _, v := range []string{"-W", "127.0.0.1:5038", "-oStrictHostKeyChecking=yes", "-oClearAllForwardings=yes", "-oControlPath=none", "-oProxyCommand=none", "-oRequestTTY=no"} {
		if !strings.Contains(out, v) {
			t.Fatalf("missing forwarding restriction %s", v)
		}
	}
	if strings.Contains(out, c.Secret) || strings.Contains(out, c.Username) || strings.Contains(out, "-n\n") {
		t.Fatal("secret or stdin suppression in SSH argv")
	}
	// No destination string exists in the public capability: only a validated uint16
	// port from the protected catalog; SSH endpoint remains enrollment-controlled.
	for name, change := range map[string]func(){"revision": func() { c.ProfileVersion++ }, "revoked": func() { c.Enabled = false }, "key": func() { c.IdentitySHA256 = strings.Repeat("0", 64) }, "root": func() { c.SSHUser = "root" }, "hostkey": func() { p.Fingerprint = "SHA256:changed" }, "endpoint": func() { p.Address = "127.0.0.2" }} {
		t.Run(name, func(t *testing.T) {
			origC, origP := c, p
			defer func() { c, p = origC, origP }()
			change()
			s, e := f.Open(context.Background(), actor, origP.Target, c)
			if e == nil {
				s.Close()
				t.Fatal("unapproved forwarding")
			}
		})
	}
}
func TestAMIProtectedCatalog(t *testing.T) {
	p, _ := fixture(t)
	c := AMICredential{ID: "synthetic", ProfileID: p.Target.ProfileID, ProfileVersion: 1, SSHUser: "ami", IdentityFile: p.IdentityFile, IdentitySHA256: p.IdentitySHA256, Port: 5038, Username: "monitor", Secret: "synthetic-secret-value", Enabled: true}
	path := filepath.Join(t.TempDir(), "catalog.json")
	b, _ := json.Marshal([]AMICredential{c})
	os.WriteFile(path, b, 0600)
	got, e := ReadAMICredentials(path)
	if e != nil || len(got) != 1 || AMIDigest(got[0]) != AMIDigest(c) {
		t.Fatal("catalog")
	}
	os.Chmod(path, 0644)
	if _, e = ReadAMICredentials(path); e == nil {
		t.Fatal("publicly readable credential accepted")
	}
	os.Chmod(path, 0600)
	link := path + "-link"
	os.Symlink(path, link)
	if _, e = ReadAMICredentials(link); e == nil {
		t.Fatal("symlink")
	}
	for _, s := range []string{string(b) + "{}", strings.Replace(string(b), "\"ID\"", "\"Unexpected\"", 1), "[" + string(b[1:len(b)-1]) + "," + string(b[1:len(b)-1]) + "]"} {
		os.WriteFile(path, []byte(s), 0600)
		if _, e = ReadAMICredentials(path); e == nil {
			t.Fatal("invalid catalog")
		}
	}
}
func TestAMIProcessCancellation(t *testing.T) {
	p, _ := fixture(t)
	c := AMICredential{ID: "synthetic", ProfileID: p.Target.ProfileID, ProfileVersion: 1, SSHUser: "ami", IdentityFile: p.IdentityFile, IdentitySHA256: p.IdentitySHA256, Port: 5038, Username: "monitor", Secret: "synthetic-secret-value", Enabled: true}
	f := NewAMIForwarder(amiApprovalFunc(func(context.Context, workspace.Principal, Target) (Profile, error) { return p, nil }))
	f.executable = fake(t, `printf 'ready'; cat >/dev/null`)
	ctx, cancel := context.WithCancel(context.Background())
	s, e := f.Open(ctx, actor, p.Target, c)
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 5)
	if _, e = io.ReadFull(s, b); e != nil {
		t.Fatal(e)
	}
	cancel()
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Read(b); e == nil {
		t.Fatal("child alive after cancellation")
	}
}
