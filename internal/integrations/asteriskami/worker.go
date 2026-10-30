package asteriskami

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"noc-workbench/internal/collection"
	activity "noc-workbench/internal/integrations/asteriskactivity"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type Binding struct {
	Scope                     collection.HistoryScope
	Target                    sshcli.Target
	Ref, Digest               string
	BlockReason               string
	Enabled, Eligible, Paused bool
	Activity                  bool
	Media                     bool
}
type Session struct {
	ID, State, Reason                              string
	StartedAt, UpdatedAt, ConnectedAt, LastEventAt time.Time
	EndedAt                                        *time.Time
	Dropped                                        int64
	Gap                                            bool
}
type Record struct {
	Event
	SessionID, ParserVersion string
	Gap                      bool
}
type View struct {
	Authorized, Current          bool
	Ref, State, Reason           string
	Session                      Session
	LastConnectedAt, LastEventAt time.Time
	Events                       []Record
	Transitions                  []Transition
}
type Transition struct {
	State, Reason string
	At            time.Time
	Gap           bool
	Dropped       int64
}
type Choice struct {
	ID   string
	Port uint16
}
type Repository interface {
	AMIBindings(context.Context, workspace.Principal) ([]Binding, error)
	SetAMIGrant(context.Context, workspace.Principal, collection.HistoryScope, sshcli.Target, string, string, bool) error
	RecoverAMI(context.Context) error
	RecoverAMIBinding(context.Context, Binding) error
	BeginAMISession(context.Context, Binding, time.Time) (string, error)
	AMITransition(context.Context, Binding, string, string, string, time.Time, int64, bool) error
	PersistAMIEvent(context.Context, Binding, string, Event, int64) error
}
type Forwarder interface {
	Check(context.Context, workspace.Principal, sshcli.Target, sshcli.AMICredential) error
	Open(context.Context, workspace.Principal, sshcli.Target, sshcli.AMICredential) (io.ReadWriteCloser, error)
}
type Service struct {
	Repository Repository
	Forwarder  Forwarder
	Catalog    string
	wait       func(context.Context, time.Duration) bool
}

func (s *Service) Choices(t sshcli.Target) []Choice {
	entries, e := sshcli.ReadAMICredentials(s.Catalog)
	if e != nil {
		return nil
	}
	var out []Choice
	for _, c := range entries {
		if c.Enabled && c.ProfileID == t.ProfileID && c.ProfileVersion == t.ProfileVersion {
			out = append(out, Choice{c.ID, c.Port})
		}
	}
	return out
}
func (s *Service) Authorize(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, ref string, enabled bool) error {
	if !enabled {
		return s.Repository.SetAMIGrant(ctx, p, h, t, "", "", false)
	}
	entries, e := sshcli.ReadAMICredentials(s.Catalog)
	if e != nil {
		return workspace.ErrDenied
	}
	for _, c := range entries {
		if c.ID == ref && c.Enabled && c.ProfileID == t.ProfileID && c.ProfileVersion == t.ProfileVersion {
			return s.Repository.SetAMIGrant(ctx, p, h, t, c.ID, sshcli.AMIDigest(c), true)
		}
	}
	return workspace.ErrDenied
}

// Run owns sessions, never polling collectors. Reconciliation observes the same
// schedule/pause/stop/enrollment authority, independently of browser requests.
func (s *Service) Run(ctx context.Context) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	return s.run(ctx, tick.C)
}
func (s *Service) run(ctx context.Context, ticks <-chan time.Time) error {
	if err := s.Repository.RecoverAMI(ctx); err != nil {
		return err
	}
	type running struct {
		binding Binding
		cancel  context.CancelCauseFunc
		done    chan struct{}
	}
	active := map[string]running{}
	stop := func(key, reason string) {
		r := active[key]
		r.cancel(errors.New(reason))
		<-r.done
		delete(active, key)
	}
	defer func() {
		for key := range active {
			stop(key, "application_shutdown")
		}
	}()
	for {
		entries, ce := sshcli.ReadAMICredentials(s.Catalog)
		credentials := map[string]sshcli.AMICredential{}
		if ce == nil {
			for _, c := range entries {
				credentials[c.ID] = c
			}
		}
		check, cancel := context.WithTimeout(ctx, 5*time.Second)
		bindings, err := s.Repository.AMIBindings(check, workspace.Principal{ID: workspace.OperatorID})
		cancel()
		desired := map[string]Binding{}
		if err == nil {
			for _, b := range bindings {
				c, ok := credentials[b.Ref]
				if ok && b.Enabled && b.Eligible && !b.Paused {
					check, cancel := context.WithTimeout(ctx, 5*time.Second)
					if err := s.Forwarder.Check(check, workspace.Principal{ID: workspace.OperatorID}, b.Target, c); err != nil {
						b.Eligible = false
						b.BlockReason = "authority_unavailable"
						var f *sshcli.Failure
						if errors.Is(err, workspace.ErrDenied) || errors.As(err, &f) && (f.Category == sshcli.PermissionDenied || f.Category == sshcli.ChangedKey || f.Category == sshcli.UnknownKey || f.Category == "credential_unavailable") {
							b.BlockReason = "authorization_revoked"
						}
					}
					cancel()
				}
				desired[b.Target.ProfileID] = b
			}
		}
		for key, r := range active {
			b, ok := desired[key]
			c, exists := credentials[b.Ref]
			reason := "authorization_revoked"
			if err != nil {
				reason = "authority_unavailable"
			} else if b.BlockReason != "" {
				reason = b.BlockReason
			} else if b.Paused {
				reason = "monitoring_paused"
			}
			if !ok || !b.Enabled || !b.Eligible || b.Paused || !exists || !c.Enabled || sshcli.AMIDigest(c) != b.Digest || r.binding != b {
				stop(key, reason)
			}
		}
		if err == nil {
			for key, b := range desired {
				c, ok := credentials[b.Ref]
				if _, running := active[key]; running || !b.Enabled || !b.Eligible || b.Paused || !ok || !c.Enabled || sshcli.AMIDigest(c) != b.Digest {
					continue
				}
				child, cancel := context.WithCancelCause(ctx)
				done := make(chan struct{})
				active[key] = running{b, cancel, done}
				go func() { defer close(done); s.sessionLoop(child, b, c) }()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticks:
		}
	}
}
func Backoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 5 {
		attempt = 5
	}
	return time.Duration(1<<attempt) * time.Second
}
func (s *Service) sessionLoop(ctx context.Context, b Binding, c sshcli.AMICredential) {
	for attempt := 0; ctx.Err() == nil; attempt++ {
		check, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := s.Repository.RecoverAMIBinding(check, b)
		var id string
		if err == nil {
			id, err = s.Repository.BeginAMISession(check, b, time.Now().UTC())
		}
		cancel()
		if err == nil {
			err = s.connection(ctx, b, id, c)
			state, reason := "reconnecting", "transport_disconnected"
			if errors.Is(err, ErrUnauthorized) {
				state, reason = "unauthorized", "ami_login_rejected"
			} else if errors.Is(err, ErrProtocol) {
				state, reason = "unsupported", "invalid_ami_frame"
			}
			if ctx.Err() != nil {
				reason = "application_shutdown"
				if cause := context.Cause(ctx); cause != nil {
					switch cause.Error() {
					case "monitoring_paused":
						state, reason = "paused", "monitoring_paused"
					case "authorization_revoked":
						state, reason = "unauthorized", "authorization_revoked"
					case "authority_unavailable", "monitoring_disabled":
						state, reason = "disconnected", cause.Error()
					default:
						state = "disconnected"
					}
				}
			}
			s.transition(b, id, state, reason, 0, true)
		}
		if s.wait != nil {
			if !s.wait(ctx, Backoff(attempt)) {
				return
			}
		} else {
			timer := time.NewTimer(Backoff(attempt))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}
func (s *Service) transition(b Binding, id, state, reason string, dropped int64, gap bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.Repository.AMITransition(ctx, b, id, state, reason, time.Now().UTC(), dropped, gap)
}
func (s *Service) connection(ctx context.Context, b Binding, id string, c sshcli.AMICredential) error {
	// Establishment, including SSH greeting and AMI authentication, is bounded.
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	handshake := time.AfterFunc(10*time.Second, cancel)
	stream, err := s.Forwarder.Open(child, workspace.Principal{ID: workspace.OperatorID}, b.Target, c)
	if err != nil {
		handshake.Stop()
		return err
	}
	defer stream.Close()
	if err = s.transition(b, id, "authenticating", "", 0, false); err != nil {
		handshake.Stop()
		return err
	}
	d, err := Login(child, stream, c.Username, c.Secret, b.Activity, b.Media)
	handshake.Stop()
	if err != nil {
		return err
	}
	if err = s.transition(b, id, "connected", "", 0, false); err != nil {
		return err
	}
	queue := make(chan Event, 128)
	result := make(chan error, 1)
	var dropped atomic.Int64
	go func() {
		var seq int64
		result <- Receive(child, stream, d, func(f Frame) {
			e, ok := Normalize(f, time.Now().UTC())
			if !ok || (e.Media != nil && (!b.Media || !b.Activity)) || (!b.Activity && activity.IsEvent(e.Name)) {
				return
			}
			seq++
			e.Sequence = seq
			select {
			case queue <- e:
			default:
				dropped.Add(1)
			}
		})
		close(queue)
	}()
	// Slow/failed persistence never blocks the socket reader indefinitely. On
	// failure close the connection and record a coverage gap; AMI cannot replay.
	heartbeat := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-heartbeat.C:
			if err = s.transition(b, id, "connected", "", dropped.Load(), dropped.Load() > 0); err != nil {
				cancel()
				stream.Close()
				<-result
				return err
			}
		case e, ok := <-queue:
			if !ok {
				s.transition(b, id, "connected", "", dropped.Load(), dropped.Load() > 0)
				return <-result
			}
			write, done := context.WithTimeout(child, 5*time.Second)
			err = s.Repository.PersistAMIEvent(write, b, id, e, dropped.Load())
			done()
			if err != nil {
				cancel()
				stream.Close()
				<-result
				s.transition(b, id, "disconnected", "persistence_failed", dropped.Load()+int64(len(queue))+1, true)
				return err
			}
		case <-ctx.Done():
			cancel()
			stream.Close()
			<-result
			return ctx.Err()
		}
	}
}
