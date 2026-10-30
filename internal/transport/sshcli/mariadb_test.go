package sshcli

import (
	"context"
	"strings"
	"testing"
)

func TestMariaDBFixedCommandAndNoForwarding(t *testing.T) {
	p, e := fixture(t)
	e.executable = fake(t, `for arg do printf '%s\n' "$arg"; done`)
	r, err := e.Execute(context.Background(), actor, p.Target, "mariadb.health.v1")
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(r.Stdout)), "\n")
	want := "/usr/bin/sudo -n -u nwdbmon -- /usr/local/sbin/noc-mariadb-observe"
	if args[len(args)-1] != want {
		t.Fatal("fixed command changed", args[len(args)-1])
	}
	for _, v := range []string{"-oClearAllForwardings=yes", "-oForwardAgent=no", "-oRequestTTY=no", "-oStrictHostKeyChecking=yes", "/dev/null"} {
		if !strings.Contains(string(r.Stdout), v) {
			t.Fatal("missing transport restriction", v)
		}
	}
	for _, bad := range []string{"mariadb.health.v1 --socket=/tmp/evil", "mariadb.health.v1; SELECT * FROM leads", "mariadb.health.v2"} {
		_, err = e.Execute(context.Background(), actor, p.Target, bad)
		category(t, err, Unsupported)
	}
}
