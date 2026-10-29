package asteriskami

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type testRepo struct {
	mu          sync.Mutex
	binding     Binding
	transitions chan Transition
	events      chan Event
	snapshots   chan struct{}
	begins      int
	recovered   int
	block       <-chan struct{}
	fail        bool
}

func (r *testRepo) AMIBindings(context.Context, workspace.Principal) ([]Binding, error) {
	r.mu.Lock()
	b := r.binding
	r.mu.Unlock()
	r.snapshots <- struct{}{}
	return []Binding{b}, nil
}
func (r *testRepo) SetAMIGrant(context.Context, workspace.Principal, collection.HistoryScope, sshcli.Target, string, string, bool) error {
	return nil
}
func (r *testRepo) RecoverAMI(context.Context) error {
	r.mu.Lock()
	r.recovered++
	r.mu.Unlock()
	return nil
}
func (r *testRepo) RecoverAMIBinding(context.Context, Binding) error { return nil }
func (r *testRepo) BeginAMISession(context.Context, Binding, time.Time) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.begins++
	return fmt.Sprint(r.begins), nil
}
func (r *testRepo) AMITransition(_ context.Context, _ Binding, _ string, state, reason string, at time.Time, dropped int64, gap bool) error {
	r.transitions <- Transition{state, reason, at, gap, dropped}
	return nil
}
func (r *testRepo) PersistAMIEvent(ctx context.Context, _ Binding, _ string, e Event, _ int64) error {
	if r.block != nil {
		select {
		case <-r.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if r.fail {
		return errors.New("synthetic persistence failure")
	}
	r.events <- e
	return nil
}

type testForward struct {
	opens    chan net.Conn
	checked  chan struct{}
	checkErr error
}

func (f *testForward) Check(context.Context, workspace.Principal, sshcli.Target, sshcli.AMICredential) error {
	if f.checked != nil {
		f.checked <- struct{}{}
	}
	return f.checkErr
}
func (f *testForward) Open(ctx context.Context, _ workspace.Principal, _ sshcli.Target, _ sshcli.AMICredential) (io.ReadWriteCloser, error) {
	a, b := net.Pipe()
	context.AfterFunc(ctx, func() { a.Close() })
	f.opens <- b
	return a, nil
}
func workerFixture(t *testing.T) (*Service, *testRepo, *testForward, sshcli.AMICredential) {
	t.Helper()
	c := sshcli.AMICredential{ID: "synthetic", ProfileID: "11111111-1111-4111-8111-111111111111", ProfileVersion: 1, SSHUser: "ami", IdentityFile: "/synthetic/key", IdentitySHA256: fmt.Sprintf("%064d", 0), Port: 5038, Username: "monitor", Secret: "synthetic-secret-value", Enabled: true}
	p := filepath.Join(t.TempDir(), "credentials.json")
	b, _ := json.Marshal([]sshcli.AMICredential{c})
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	r := &testRepo{binding: Binding{Target: sshcli.Target{ProfileID: c.ProfileID, ProfileVersion: 1}, Ref: c.ID, Digest: sshcli.AMIDigest(c), Enabled: true, Eligible: true}, transitions: make(chan Transition, 10000), events: make(chan Event, 10000), snapshots: make(chan struct{}, 100)}
	f := &testForward{opens: make(chan net.Conn, 10), checked: make(chan struct{}, 100)}
	return &Service{Repository: r, Forwarder: f, Catalog: p}, r, f, c
}
func acceptLogin(t *testing.T, c net.Conn) {
	t.Helper()
	if _, e := io.WriteString(c, "Asterisk Call Manager/7.0.3\r\n"); e != nil {
		t.Error(e)
		return
	}
	d := NewDecoder(c)
	f, e := d.Read()
	if e != nil || f.One("Action") != "Login" || f.One("Events") != "system" {
		t.Error("login", e)
		return
	}
	if _, e = io.WriteString(c, "Response: Success\r\nActionID: nw-login\r\n\r\n"); e != nil {
		t.Error(e)
	}
}
func awaitTransition(t *testing.T, r *testRepo, state string) Transition {
	t.Helper()
	for {
		select {
		case tr := <-r.transitions:
			if tr.State == state {
				return tr
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("missing %s transition", state)
			return Transition{}
		}
	}
}
func TestManagedLifecyclePauseResumeRevokeAndShutdown(t *testing.T) {
	s, r, f, _ := workerFixture(t)
	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.run(ctx, ticks) }()
	defer cancel()
	<-r.snapshots
	c := <-f.opens
	acceptLogin(t, c)
	awaitTransition(t, r, "connected")
	// A second reconciliation must retain the same owner, not create a session.
	ticks <- time.Now()
	<-r.snapshots
	<-f.checked
	<-f.checked
	r.mu.Lock()
	if r.begins != 1 {
		t.Fatal("duplicate session")
	}
	r.binding.Paused = true
	r.mu.Unlock()
	ticks <- time.Now()
	<-r.snapshots
	tr := awaitTransition(t, r, "paused")
	if !tr.Gap || tr.Reason != "monitoring_paused" {
		t.Fatal(tr)
	}
	c.Close()
	r.mu.Lock()
	r.binding.Paused = false
	r.mu.Unlock()
	ticks <- time.Now()
	<-r.snapshots
	c = <-f.opens
	acceptLogin(t, c)
	awaitTransition(t, r, "connected")
	r.mu.Lock()
	r.binding.Enabled = false
	r.mu.Unlock()
	ticks <- time.Now()
	<-r.snapshots
	tr = awaitTransition(t, r, "unauthorized")
	if !tr.Gap {
		t.Fatal("revocation missing gap")
	}
	c.Close()
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.recovered != 1 || r.begins != 2 {
		t.Fatal("restart recovery/session count", r.recovered, r.begins)
	}
}
func TestDisconnectBackoffAndPersistenceFailure(t *testing.T) {
	s, r, f, cfg := workerFixture(t)
	waits := make(chan time.Duration, 2)
	resume := make(chan struct{})
	s.wait = func(ctx context.Context, d time.Duration) bool {
		waits <- d
		select {
		case <-resume:
			return true
		case <-ctx.Done():
			return false
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.sessionLoop(ctx, r.binding, cfg) }()
	c := <-f.opens
	acceptLogin(t, c)
	awaitTransition(t, r, "connected")
	c.Close()
	tr := awaitTransition(t, r, "reconnecting")
	if !tr.Gap {
		t.Fatal("disconnect coverage")
	}
	if d := <-waits; d != time.Second {
		t.Fatal(d)
	}
	resume <- struct{}{}
	c = <-f.opens
	acceptLogin(t, c)
	awaitTransition(t, r, "connected")
	r.fail = true
	io.WriteString(c, "Event: PeerStatus\r\nPeer: SIP/example\r\nPeerStatus: Registered\r\n\r\n")
	tr = awaitTransition(t, r, "disconnected")
	if tr.Reason != "persistence_failed" || !tr.Gap || tr.Dropped < 1 {
		t.Fatal(tr)
	}
	<-waits
	cancel()
	<-done
	c.Close()
	for i, want := range []time.Duration{1, 2, 4, 8, 16, 32, 32, 32} {
		if Backoff(i) != want*time.Second {
			t.Fatal(i)
		}
	}
}
func TestBoundedQueueOverflowIsVisible(t *testing.T) {
	s, r, f, cfg := workerFixture(t)
	release := make(chan struct{})
	r.block = release
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.connection(ctx, r.binding, "1", cfg) }()
	c := <-f.opens
	acceptLogin(t, c)
	awaitTransition(t, r, "connected")
	// The first persistence is held while the socket consumes more than 128 events.
	for i := 0; i < 400; i++ {
		if _, e := io.WriteString(c, "Event: FullyBooted\r\n\r\n"); e != nil {
			t.Fatal(e)
		}
	}
	c.Close()
	close(release)
	if e := <-done; e == nil {
		t.Fatal("disconnect missing")
	}
	tr := awaitTransition(t, r, "connected")
	if !tr.Gap || tr.Dropped == 0 {
		t.Fatal("overflow was not reported", tr)
	}
}
func TestShutdownJoinsActiveStream(t *testing.T) {
	s, r, f, _ := workerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.run(ctx, make(chan time.Time)) }()
	c := <-f.opens
	acceptLogin(t, c)
	awaitTransition(t, r, "connected")
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	tr := awaitTransition(t, r, "disconnected")
	if tr.Reason != "application_shutdown" || !tr.Gap {
		t.Fatal(tr)
	}
	c.Close()
}
func TestActivityAuthorityChangesSubscriptionAndDropsUnsolicitedEvents(t *testing.T) {
	s, r, f, _ := workerFixture(t)
	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.run(ctx, ticks) }()
	accept := func(expected string) net.Conn {
		t.Helper()
		<-r.snapshots
		c := <-f.opens
		io.WriteString(c, "Asterisk Call Manager/7.0.3\r\n")
		frame, e := NewDecoder(c).Read()
		if e != nil || frame.One("Events") != expected {
			t.Fatal("subscription", frame, e)
		}
		io.WriteString(c, "Response: Success\r\nActionID: nw-login\r\n\r\n")
		awaitTransition(t, r, "connected")
		return c
	}
	c := accept("system")
	// A subsequent persisted system frame is a deterministic processing barrier.
	io.WriteString(c, "Event: Newchannel\r\nUniqueid: 1.1\r\nChannel: SIP/phone-00000001\r\n\r\nEvent: FullyBooted\r\n\r\n")
	if e := <-r.events; e.Name != "FullyBooted" {
		t.Fatal("unsolicited call data persisted", e)
	}
	r.mu.Lock()
	r.binding.Activity = true
	r.mu.Unlock()
	ticks <- time.Now()
	c.Close()
	c = accept("system,call")
	io.WriteString(c, "Event: Newchannel\r\nUniqueid: 1.1\r\nChannel: SIP/phone-00000001\r\n\r\n")
	if e := <-r.events; e.Name != "Newchannel" {
		t.Fatal(e)
	}
	r.mu.Lock()
	r.binding.Activity = false
	r.mu.Unlock()
	ticks <- time.Now()
	c.Close()
	c = accept("system")
	io.WriteString(c, "Event: Newstate\r\nUniqueid: 1.1\r\n\r\nEvent: FullyBooted\r\n\r\n")
	if e := <-r.events; e.Name != "FullyBooted" {
		t.Fatal("revoked call data persisted", e)
	}
	cancel()
	c.Close()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.begins != 3 {
		t.Fatal("subscription change session ownership", r.begins)
	}
}
