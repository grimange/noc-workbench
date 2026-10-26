// Package testlab provides disposable, opt-in loopback-only SSH fixtures.
package testlab

import (
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

	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"noc-workbench/internal/transport/sshcli"
)

type Lab struct {
	Dir, HostKey, Fingerprint, User string
	Port                            int
	Credential                      sshcli.Credential
	Catalog                         string
	restart                         func()
}

func Start(t *testing.T) Lab {
	t.Helper()
	if os.Getenv("NOC_SSH_LAB") != "1" {
		t.Skip("NOC_SSH_LAB=1 authorizes a disposable loopback SSH daemon")
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
	fp, err := sshcli.Fingerprint(material)
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
	t.Cleanup(func() { log.Close() })
	daemon := exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", filepath.Join(dir, "sshd.conf"))
	daemon.Stderr = log
	daemon.Stdout = log
	if err = daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { daemon.Process.Kill(); daemon.Wait() })
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

	key, err := os.ReadFile(filepath.Join(dir, "identity"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(key)
	credential := sshcli.Credential{ID: "synthetic-lab", User: current.Username, IdentityFile: filepath.Join(dir, "identity"), IdentitySHA256: hex.EncodeToString(sum[:]), Enabled: true}
	catalog := filepath.Join(dir, "credentials.json")
	data, _ := json.Marshal([]sshcli.Credential{credential})
	if err = os.WriteFile(catalog, data, 0600); err != nil {
		t.Fatal(err)
	}
	restart := func() {
		daemon.Process.Kill()
		daemon.Wait()
		daemon = exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", filepath.Join(dir, "sshd.conf"))
		daemon.Stderr = log
		daemon.Stdout = log
		if err := daemon.Start(); err != nil {
			t.Fatal(err)
		}
	}
	return Lab{Dir: dir, HostKey: material, Fingerprint: fp, User: current.Username, Port: port, Credential: credential, Catalog: catalog, restart: restart}
}

// ReplaceHostKey restarts this disposable daemon's server-side identity. The
// fixture is loopback-only; callers retain the old bytes to test restoration.
func (l Lab) ReplaceHostKey(t *testing.T, key []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(l.Dir, "host"), key, 0600); err != nil {
		t.Fatal(err)
	}
	// Compare the independently derived public key to a bounded loopback scan so
	// tests do not race the disposable daemon startup.
	pub, err := exec.Command("/usr/bin/ssh-keygen", "-y", "-f", filepath.Join(l.Dir, "host")).Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.Dir, "host.pub"), pub, 0600); err != nil {
		t.Fatal(err)
	}
	l.restart()
	fields := strings.Fields(string(pub))
	want := fields[0] + " " + fields[1]
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("/usr/bin/ssh-keyscan", "-T", "1", "-t", "ed25519", "-p", strconv.Itoa(l.Port), "127.0.0.1").Output()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && f[0] != "#" && f[1]+" "+f[2] == want {
				return
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	log, _ := os.ReadFile(filepath.Join(l.Dir, "sshd.log"))
	t.Fatalf("lab identity reload not observed: %s", log)
}
