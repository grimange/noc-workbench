package asteriskami

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFramesGreetingRepeatedMalformedBounded(t *testing.T) {
	for _, s := range []string{"Asterisk Call Manager/7.0.3\r\n", "Asterisk Call Manager/5.0\r\n"} {
		if NewDecoder(strings.NewReader(s)).Greeting() != nil {
			t.Fatal("valid greeting")
		}
	}
	for _, s := range []string{"Welcome\r\n", "Asterisk Call Manager/evil\r\n", "Asterisk Call Manager/7.0\n"} {
		if NewDecoder(strings.NewReader(s)).Greeting() == nil {
			t.Fatal("bad greeting accepted")
		}
	}
	f, e := NewDecoder(strings.NewReader("Event: PeerStatus\r\nVariable: a=1\r\nVariable: b=2\r\n\r\n")).Read()
	if e != nil || len(f["variable"]) != 2 || f.One("Variable") != "" {
		t.Fatal("repeated headers lost")
	}
	for name, s := range map[string]string{"LF": "Event: Foo\n\n", "partial": "Event: PeerStatus\r\nPeer: SIP/10", "fold": "Event: Foo\r\n bad\r\n\r\n", "control": "Event: F\x00oo\r\n\r\n", "longline": "Event: " + strings.Repeat("x", 8192) + "\r\n\r\n", "bigframe": strings.Repeat("Header: "+strings.Repeat("x", 1024)+"\r\n", 65) + "\r\n", "headers": strings.Repeat("X: a\r\n", 129) + "\r\n"} {
		t.Run(name, func(t *testing.T) {
			if _, e := NewDecoder(strings.NewReader(s)).Read(); e == nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
}
func TestLoginAndUnauthorized(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(fmt.Sprint(success), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				io.WriteString(server, "Asterisk Call Manager/7.0.3\r\n")
				f, e := NewDecoder(server).Read()
				if e != nil {
					done <- e
					return
				}
				if f.One("Action") != "Login" || f.One("Events") != "system" || f.One("Username") != "monitor" || f.One("Secret") != "synthetic-secret-123" {
					done <- errors.New("unexpected login action")
					return
				}
				response := "Error"
				if success {
					response = "Success"
				}
				_, e = fmt.Fprintf(server, "Response: %s\r\nActionID: nw-login\r\n\r\n", response)
				done <- e
			}()
			_, e := Login(context.Background(), client, "monitor", "synthetic-secret-123")
			if success && e != nil || !success && !errors.Is(e, ErrUnauthorized) {
				t.Fatal("incorrect authentication result")
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := Login(ctx, client, "monitor", "synthetic-secret-123"); done <- e }()
	cancel()
	if <-done == nil {
		t.Fatal("cancelled greeting accepted")
	}
	if _, e := Login(context.Background(), client, "monitor\r\nAction: Command", "synthetic-secret-123"); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("header injection")
	}
}
func TestReceiveHeartbeatCancellationAndGap(t *testing.T) {
	for _, pong := range []bool{true, false} {
		t.Run(fmt.Sprint(pong), func(t *testing.T) {
			c, s := net.Pipe()
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ticks, timeout := make(chan time.Time, 1), make(chan time.Time, 1)
			armed := make(chan struct{})
			emitted := make(chan Frame, 1)
			done := make(chan error, 1)
			go func() {
				done <- receive(ctx, c, NewDecoder(c), func(f Frame) { emitted <- f }, ticks, func() (<-chan time.Time, func()) { close(armed); return timeout, func() {} })
			}()
			serverDone := make(chan error, 1)
			go func() {
				f, e := NewDecoder(s).Read()
				if e != nil {
					serverDone <- e
					return
				}
				if f.One("Action") != "Ping" {
					serverDone <- errors.New("nonallowlisted action")
					return
				}
				if pong {
					_, e = io.WriteString(s, "Response: Success\r\nPing: Pong\r\nActionID: nw-heartbeat\r\n\r\nEvent: FullyBooted\r\n\r\n")
				}
				serverDone <- e
			}()
			ticks <- time.Time{}
			<-armed
			if pong {
				<-emitted
				cancel()
				if !errors.Is(<-done, context.Canceled) {
					t.Fatal("cancel")
				}
			} else {
				timeout <- time.Time{}
				if !errors.Is(<-done, ErrHeartbeat) {
					t.Fatal("timeout")
				}
			}
			if e := <-serverDone; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestNormalizationMinimizesSensitiveFields(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixtures := []struct{ raw, name, endpoint, address, state string }{
		{"Event: ContactStatus\r\nEndpointName: phone1\r\nAOR: office\r\nURI: sip:secret-user:password@192.0.2.10:5060;transport=udp\r\nContactStatus: Reachable\r\nRoundtripUsec: 1250\r\nCallerIDNum: sensitive\r\nAuthorization: sensitive-hash\r\n\r\n", "ContactStatus", "phone1", "192.0.2.10:5060", "Reachable"},
		{"Event: PeerStatus\r\nPeer: SIP/phone2\r\nPeerStatus: Registered\r\nAddress: [2001:db8::10]:5060\r\n\r\n", "PeerStatus", "phone2", "[2001:db8::10]:5060", "Registered"},
		{"Event: Registry\r\nChannelType: SIP\r\nUsername: trunk1\r\nStatus: Registered\r\nDomain: 192.0.2.20\r\n\r\n", "Registry", "trunk1", "192.0.2.20", "Registered"},
		{"Event: PeerStatus\r\nPeer: SIP/one\r\nPeer: SIP/two\r\nPeerStatus: attacker-controlled-secret\r\nAddress: unknown.invalid\r\n\r\n", "PeerStatus", "", "", ""},
		{"Event: FullyBooted\r\nTimestamp: 1767323045.125\r\n\r\n", "FullyBooted", "", "", "Fully booted"},
	}
	for _, tc := range fixtures {
		f, e := NewDecoder(strings.NewReader(tc.raw)).Read()
		if e != nil {
			t.Fatal(e)
		}
		v, ok := Normalize(f, now)
		v.Sequence = 1
		if !ok || v.Name != tc.name || v.Endpoint != tc.endpoint || v.Address != tc.address || v.State != tc.state || !v.ReceivedAt.Equal(now) || !ValidEvent(v) {
			t.Fatalf("normalization %#v", v)
		}
		if tc.name == "ContactStatus" && (v.RTT == nil || *v.RTT != 1.25) {
			t.Fatal("RTT units")
		}
	}
	if _, ok := Normalize(Frame{"event": {"DialBegin"}, "calleridnum": {"sensitive"}}, now); ok {
		t.Fatal("unrelated telephony event accepted")
	}
	if _, ok := Normalize(Frame{"event": {"ContactStatus", "PeerStatus"}}, now); ok {
		t.Fatal("ambiguous event")
	}
	for _, s := range []string{"sip:user:secret@example.invalid", "bad\r\nsecret", "[2001:db8::1%zone]:5060"} {
		if address(s) != "" {
			t.Fatal("unsupported address retained")
		}
	}
	for _, s := range []string{"NaN", "+Inf", "0", "-1", "99999999999"} {
		e, _ := Normalize(Frame{"event": {"FullyBooted"}, "timestamp": {s}}, now)
		if e.SourceAt != nil {
			t.Fatal("invalid source timestamp")
		}
	}
}

func TestDisconnectVersusTruncatedProtocol(t *testing.T) {
	if e := NewDecoder(strings.NewReader("")).Greeting(); !errors.Is(e, ErrDisconnected) {
		t.Fatal("clean greeting disconnect", e)
	}
	if _, e := NewDecoder(strings.NewReader("Event: FullyBooted\r\n")).Read(); !errors.Is(e, ErrProtocol) {
		t.Fatal("incomplete frame", e)
	}
	a, b := net.Pipe()
	b.Close()
	defer a.Close()
	if _, e := Login(context.Background(), a, "monitor", "synthetic-secret-value"); !errors.Is(e, ErrDisconnected) {
		t.Fatal("login transport disconnect", e)
	}
}
func TestExplicitActivitySubscription(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		io.WriteString(server, "Asterisk Call Manager/7.0.3\r\n")
		f, e := NewDecoder(server).Read()
		if e != nil || f.One("Events") != "system,call" {
			done <- errors.New("call subscription missing")
			return
		}
		_, e = io.WriteString(server, "Response: Success\r\nActionID: nw-login\r\n\r\n")
		done <- e
	}()
	if _, e := Login(context.Background(), client, "monitor", "synthetic-secret-123", true); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
