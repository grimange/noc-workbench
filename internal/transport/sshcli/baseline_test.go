package sshcli

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestBaselineAllowlist(t *testing.T) {
	c, ok := registry["linux.baseline.v1"]
	if !ok || c.limit != 65536 || c.timeout > 20*time.Second {
		t.Fatal("unbounded baseline")
	}
	for _, bad := range []string{"sudo ", "ps -ef", "args=", "--property=ExecStart", "Environment=", "cat /etc/crontab"} {
		if strings.Contains(c.text, bad) {
			t.Fatal("unsafe collector", bad)
		}
	}
}
func TestBaselineLocal(t *testing.T) {
	if os.Getenv("NOC_BASELINE_LOCAL") != "1" {
		t.Skip("explicit local read-only command verification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "/bin/sh", "-c", baselineCommand).Output()
	if e != nil || !strings.HasSuffix(string(b), "\nEND\n") {
		t.Fatalf("local command %v", e)
	}
	if path := os.Getenv("NOC_BASELINE_OUTPUT"); path != "" {
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
