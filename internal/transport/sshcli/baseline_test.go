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

// Processes can disappear between the shell's glob expansion and awk's input
// open. GNU awk aborts automatic input opening without running END; explicit
// getline must instead skip the vanished process and finish the sample.
func TestBaselineVanishedProcess(t *testing.T) {
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("awk unavailable")
	}
	start := strings.Index(baselineCommand, "timeout 5 awk '\n")
	end := strings.Index(baselineCommand, "' /proc/[0-9]*/stat 2>/dev/null")
	if start < 0 || end < start {
		t.Fatal("baseline sampler contract changed")
	}
	program := baselineCommand[start+len("timeout 5 awk '\n") : end]
	// The production one-second interval measures CPU. This test exercises path
	// disappearance, so use unchanged CPU counters without waiting for an interval.
	if strings.Count(program, `system("sleep 1");`) != 1 {
		t.Fatal("measurement interval changed")
	}
	program = strings.Replace(program, `system("sleep 1");`, "", 1)
	dir := t.TempDir()
	present := dir + "/present"
	// /proc/PID/stat fields after comm: state, then fields 4 through 24.
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[11], fields[12], fields[19], fields[21] = "S", "10", "5", "123", "8"
	stat := "42 (example) " + strings.Join(fields, " ") + "\n"
	if err := os.WriteFile(present, []byte(stat), 0600); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][]string{
		{dir + "/gone", present},
		{present, dir + "/gone"},
		{dir + "/gone"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		output, err := exec.CommandContext(ctx, awk, append([]string{program}, paths...)...).CombinedOutput()
		cancel()
		if err != nil || !strings.Contains(string(output), "cpu|") || !strings.HasSuffix(string(output), "process_status|sampled_up_to_4096\n") {
			t.Fatalf("vanished process aborted sampler: %v %s", err, output)
		}
		if len(paths) == 2 && strings.Count(string(output), "process|42|example|") != 1 {
			t.Fatalf("surviving process lost or duplicated: %s", output)
		}
	}
}
