package sshcli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAsteriskAuthFixedReader(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	out, err := exec.Command(python, "-I", "asterisk_auth_reader_test.py").CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}

func TestAsteriskAuthStdinProtocol(t *testing.T) {
	p, e := fixture(t)
	e.executable = fake(t, `for arg do printf '%s\n' "$arg"; done
printf 'INPUT:'
cat`)
	input := []byte(`{"security":{"identity":"1:2","offset":0,"generation":1,"anchor":"","gap":false,"discard":false}}`)
	for _, id := range []string{"asterisk.auth.v1", "asterisk.auth.helper.v1"} {
		r, err := e.Execute(WithAsteriskAuthCursor(context.Background(), input), actor, p.Target, id)
		if err != nil {
			t.Fatal(err)
		}
		out := string(r.Stdout)
		if id == "asterisk.auth.helper.v1" && !strings.Contains(out, "/usr/bin/sudo -n -u asterisk -- /usr/local/sbin/noc-asterisk-auth-read") {
			t.Fatal("unexpected helper execution identity")
		}
		if !strings.Contains(out, "INPUT:"+string(input)) || strings.Contains(out, "\n-n\n") || !strings.Contains(out, "-oStrictHostKeyChecking=yes") {
			t.Fatal("unsafe stdin or SSH flags", out)
		}
	}
	_, err := e.Execute(context.Background(), actor, p.Target, "asterisk.auth.v1")
	category(t, err, Unsupported)
	_, err = e.Execute(WithAsteriskAuthCursor(context.Background(), input), actor, p.Target, "asterisk.auth.v1; arbitrary")
	category(t, err, Unsupported)
	wrapper, err := os.ReadFile("../../../scripts/asterisk-auth-read")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "reader")
	if err = os.WriteFile(path, wrapper, 0700); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"identity"}, {"/etc/shadow"}, {";evil"}} {
		if exec.Command(path, args...).Run() == nil {
			t.Fatal("helper accepted arguments", args)
		}
	}
}
