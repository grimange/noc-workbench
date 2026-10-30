package sshcli

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type capped struct {
	mu             sync.Mutex
	stdout, stderr bytes.Buffer
	remaining      int
	truncated      bool
	stop           func()
}
type stream struct {
	c      *capped
	stderr bool
}

func (s stream) Write(p []byte) (int, error) {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	keep := n
	if keep > c.remaining {
		keep = c.remaining
		c.truncated = true
		c.stop()
	}
	c.remaining -= keep
	if s.stderr {
		c.stderr.Write(p[:keep])
	} else {
		c.stdout.Write(p[:keep])
	}
	return n, nil
}
func contextFailure(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return fail(Cancelled)
	}
	return fail(ExecutionTimeout)
}
func run(ctx context.Context, executable string, args []string, limit int) ([]byte, []byte, int, error) {
	return runInput(ctx, executable, args, limit, nil)
}
func runInput(ctx context.Context, executable string, args []string, limit int, input []byte) ([]byte, []byte, int, error) {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(childCtx, executable, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 250 * time.Millisecond
	out := &capped{remaining: limit, stop: cancel}
	cmd.Stdout = stream{out, false}
	cmd.Stderr = stream{out, true}
	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return nil, nil, -1, contextFailure(ctx)
		}
		return nil, nil, -1, fail(Internal)
	}
	err := cmd.Wait()
	// Also kill descendants left after a parent exits or closes its pipes.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	code := cmd.ProcessState.ExitCode()
	if out.truncated {
		return out.stdout.Bytes(), nil, code, fail(OutputTruncated)
	}
	if ctx.Err() != nil {
		return out.stdout.Bytes(), nil, code, contextFailure(ctx)
	}
	if err == nil {
		return out.stdout.Bytes(), nil, code, nil
	}
	cat := CommandFailed
	switch code {
	case 127:
		cat = CommandNotFound
	case 126:
		cat = PermissionDenied
	case 255:
		cat = classify(out.stderr.String())
	}
	// Raw stderr is deliberately not returned: it may contain a credential or
	// attacker-controlled server text. Category is the diagnostic contract.
	return out.stdout.Bytes(), nil, code, fail(cat)
}
func classify(message string) Category {
	// Only narrow OpenSSH C-locale diagnostics; 255 alone is ambiguous.
	switch {
	case bytes.Contains([]byte(message), []byte("REMOTE HOST IDENTIFICATION HAS CHANGED")):
		return ChangedKey
	case bytes.Contains([]byte(message), []byte("No ED25519 host key is known for")), bytes.Contains([]byte(message), []byte("No RSA host key is known for")), bytes.Contains([]byte(message), []byte("No ECDSA host key is known for")):
		return UnknownKey
	case bytes.Contains([]byte(message), []byte("Permission denied (publickey")):
		return AuthenticationFailed
	case bytes.Contains([]byte(message), []byte("Could not resolve hostname")):
		return DNSFailure
	case bytes.Contains([]byte(message), []byte("connect to host")) && bytes.Contains([]byte(message), []byte("Connection refused")):
		return ConnectionRefused
	case bytes.Contains([]byte(message), []byte("connect to host")) && bytes.Contains([]byte(message), []byte("Connection timed out")):
		return ConnectionTimeout
	case hasDiagnosticLine(message, "Connection timed out during banner exchange"):
		// ConnectTimeout also covers SSH identification exchange after TCP
		// connects. OpenSSH emits this without the "connect to host" prefix.
		return ConnectionTimeout
	default:
		return Internal
	}
}

func hasDiagnosticLine(message, diagnostic string) bool {
	for _, line := range bytes.Split([]byte(message), []byte{'\n'}) {
		if bytes.Equal(bytes.TrimSpace(line), []byte(diagnostic)) {
			return true
		}
	}
	return false
}
