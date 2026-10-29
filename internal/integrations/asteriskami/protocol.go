// Package asteriskami receives a small, versioned allowlist of observational
// events. It exposes no arbitrary AMI action or raw-frame logging interface.
package asteriskami

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	ErrProtocol     = errors.New("ami_invalid_frame")
	ErrUnauthorized = errors.New("ami_unauthorized")
	ErrDisconnected = errors.New("ami_disconnected")
	ErrHeartbeat    = errors.New("ami_heartbeat_timeout")
)

const MaxFrame = 64 * 1024

// Frame retains repeated headers for protocol correctness; normalization rejects
// ambiguous repeated operational fields. Frames are transient and never logged.
type Frame map[string][]string

func (f Frame) One(key string) string {
	v := f[strings.ToLower(key)]
	if len(v) != 1 {
		return ""
	}
	return v[0]
}

type Decoder struct{ r *bufio.Reader }

func NewDecoder(r io.Reader) *Decoder { return &Decoder{bufio.NewReaderSize(r, 8192)} }
func (d *Decoder) line() (string, error) {
	b, err := d.r.ReadSlice('\n')
	if errors.Is(err, io.EOF) && len(b) == 0 {
		return "", ErrDisconnected
	}
	if err != nil || len(b) < 2 || b[len(b)-2] != '\r' {
		return "", ErrProtocol
	}
	for _, v := range b[:len(b)-2] {
		if v < 32 && v != '\t' || v == 127 {
			return "", ErrProtocol
		}
	}
	return string(b[:len(b)-2]), nil
}
func (d *Decoder) Greeting() error {
	s, e := d.line()
	if e != nil {
		return e
	}
	if !strings.HasPrefix(s, "Asterisk Call Manager/") || len(s) > 80 {
		return ErrProtocol
	}
	v := strings.TrimPrefix(s, "Asterisk Call Manager/")
	if v == "" {
		return ErrProtocol
	}
	for _, r := range v {
		if (r < '0' || r > '9') && r != '.' {
			return ErrProtocol
		}
	}
	return nil
}
func (d *Decoder) Read() (Frame, error) {
	f := Frame{}
	size, count := 0, 0
	for {
		s, e := d.line()
		if e != nil {
			if count > 0 && errors.Is(e, ErrDisconnected) {
				return nil, ErrProtocol
			}
			return nil, e
		}
		size += len(s) + 2
		if size > MaxFrame {
			return nil, ErrProtocol
		}
		if s == "" {
			if count == 0 {
				continue
			}
			return f, nil
		}
		count++
		if count > 128 {
			return nil, ErrProtocol
		}
		k, v, ok := strings.Cut(s, ":")
		if !ok || k == "" || len(k) > 64 || strings.ContainsAny(k, " \t") {
			return nil, ErrProtocol
		}
		for _, r := range k {
			if r < 'A' || r > 'Z' {
				if r < 'a' || r > 'z' {
					if r < '0' || r > '9' {
						if r != '-' {
							return nil, ErrProtocol
						}
					}
				}
			}
		}
		k = strings.ToLower(k)
		f[k] = append(f[k], strings.TrimSpace(v))
	}
}

// Login's only configurable wire values come from a protected credential. The
// subscription is fixed to system and call events; no write class is required.
func Login(ctx context.Context, c io.ReadWriteCloser, username, secret string, activity ...bool) (*Decoder, error) {
	if username == "" || len(username) > 64 || len(secret) < 16 || len(secret) > 256 || strings.ContainsAny(username+secret, "\r\n\x00") {
		return nil, ErrUnauthorized
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	d := NewDecoder(c)
	if e := d.Greeting(); e != nil {
		return nil, e
	}
	events := "system"
	if len(activity) == 1 && activity[0] {
		events = "system,call"
	}
	if _, e := fmt.Fprintf(c, "Action: Login\r\nActionID: nw-login\r\nUsername: %s\r\nSecret: %s\r\nEvents: %s\r\n\r\n", username, secret, events); e != nil {
		return nil, ErrDisconnected
	}
	frame, e := d.Read()
	if e != nil {
		return nil, e
	}
	if frame.One("ActionID") != "nw-login" || frame.One("Response") != "Success" {
		return nil, ErrUnauthorized
	}
	return d, nil
}

// Receive sends only a fixed Ping heartbeat. A silent server is distinguished
// from an idle event stream by a response deadline, not by event frequency.
func Receive(ctx context.Context, c io.ReadWriteCloser, d *Decoder, emit func(Frame)) error {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	return receive(ctx, c, d, emit, ticker.C, func() (<-chan time.Time, func()) {
		t := time.NewTimer(10 * time.Second)
		return t.C, func() { t.Stop() }
	})
}
func receive(ctx context.Context, c io.ReadWriteCloser, d *Decoder, emit func(Frame), ticks <-chan time.Time, after func() (<-chan time.Time, func())) error {
	ctx, cancel := context.WithCancel(ctx)
	type result struct {
		f Frame
		e error
	}
	frames := make(chan result, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			f, e := d.Read()
			select {
			case frames <- result{f, e}:
			case <-ctx.Done():
				return
			}
			if e != nil {
				return
			}
		}
	}()
	defer func() { cancel(); c.Close(); <-done }()
	var deadline <-chan time.Time
	stop := func() {}
	defer func() {
		stop()
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			if deadline != nil {
				continue
			}
			if _, e := io.WriteString(c, "Action: Ping\r\nActionID: nw-heartbeat\r\n\r\n"); e != nil {
				return ErrDisconnected
			}
			deadline, stop = after()
		case <-deadline:
			return ErrHeartbeat
		case r := <-frames:
			if r.e != nil {
				return r.e
			}
			if r.f.One("Event") != "" {
				emit(r.f)
			} else if r.f.One("ActionID") == "nw-heartbeat" && r.f.One("Response") == "Success" && r.f.One("Ping") == "Pong" {
				stop()
				deadline = nil
			}
		}
	}
}
