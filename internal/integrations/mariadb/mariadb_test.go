package mariadb

import (
	"context"
	"encoding/json"
	"fmt"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
	"testing"
	"time"
)

func ptr(v uint64) *uint64 { return &v }
func fixture() Snapshot {
	return Snapshot{Protocol: 1, Status: "ready", Version: "10.11.15-MariaDB-log", Identity: "db.example.invalid", ServerID: 1, LatencyMS: 2, Metrics: map[string]uint64{"Threads_connected": 13, "Threads_running": 1, "Max_used_connections": 19, "Connections": 100, "Aborted_connects": 0, "Uptime": 123, "max_connections": 2000}, ActivityStatus: "ready", Replication: "ready"}
}
func TestReadinessActivityAndRoundTrip(t *testing.T) {
	s := fixture()
	b, _ := json.Marshal(s)
	obs, ds := Parse(b)
	if len(ds) != 0 || len(obs) != 1 {
		t.Fatal(obs, ds)
	}
	got, e := Decode(obs)
	if e != nil || got.Metrics["Threads_connected"] != 13 || got.Role() != "Unknown" {
		t.Fatal(got, e)
	}
	delete(s.Metrics, "Threads_running")
	b, _ = json.Marshal(s)
	obs, ds = Parse(b)
	if len(obs) != 1 || len(ds) != 1 || ds[0].Code != "missing_metrics" {
		t.Fatal(obs, ds)
	}
	if s.Activity()[1].Value != "Unavailable" {
		t.Fatal(s.Activity())
	}
	// No rates are derived; restart counter resets remain original samples.
	s.Metrics["Connections"] = 1
	if s.Activity()[3].Value != "1" {
		t.Fatal(s.Activity())
	}
}
func TestFailuresNeverZerosOrRawMessages(t *testing.T) {
	for _, code := range []string{"connection_unavailable", "authentication_denied", "permission_denied", "query_failure", "timeout", "unsupported", "unknown"} {
		b := []byte(fmt.Sprintf(`{"protocol":1,"status":%q,"activity_status":"unknown","replication":"unknown","metrics":{},"server_id":0,"latency_ms":0}`, code))
		obs, ds := Parse(b)
		if len(obs) != 0 || len(ds) != 1 || ds[0].Code != code {
			t.Fatal(code, obs, ds)
		}
	}
	for _, bad := range []string{``, `{`, `{"protocol":1,"password":"secret"}`, `{"protocol":1,"status":"secret SQL"}`, strings.Repeat("x", 65537)} {
		obs, ds := Parse([]byte(bad))
		if len(obs) != 0 || len(ds) != 1 || ds[0].Code != "parse_error" {
			t.Fatal(obs, ds)
		}
	}
}
func TestReplicationSemanticsMultipleChannels(t *testing.T) {
	base := Channel{Name: "east", Source: "192.0.2.4", Port: ptr(3306), IO: "Yes", SQL: "Yes", Lag: ptr(0)}
	cases := []struct {
		name   string
		change func(*Channel)
		want   string
	}{
		{"healthy", func(c *Channel) {}, "Operating"}, {"null", func(c *Channel) { c.Lag = nil }, "Unknown"},
		{"delay", func(c *Channel) { c.Lag = ptr(5) }, "Delayed"}, {"io", func(c *Channel) { c.IO = "Connecting" }, "I/O failure"},
		{"sql", func(c *Channel) { c.SQL = "No" }, "SQL/applier failure"}, {"stopped", func(c *Channel) { c.IO = "No"; c.SQL = "No" }, "Configured but stopped"},
		{"io error", func(c *Channel) { c.IOError = 123 }, "I/O failure"}, {"sql error", func(c *Channel) { c.SQLError = 321 }, "SQL/applier failure"},
	}
	for _, tc := range cases {
		c := base
		tc.change(&c)
		if c.Condition() != tc.want {
			t.Fatal(tc.name, c.Condition())
		}
	}
	s := fixture()
	other := base
	other.Name = "west"
	other.SQL = "No"
	s.Channels = []Channel{other, base}
	b, _ := json.Marshal(s)
	obs, ds := Parse(b)
	got, e := Decode(obs)
	if len(ds) != 0 || e != nil || len(got.Channels) != 2 || got.Role() != "Replica" || got.Channels[0].Condition() != "Operating" || got.Channels[1].Condition() != "SQL/applier failure" {
		t.Fatal(got, ds, e)
	}
	s.Replication = "permission_denied"
	s.Channels = nil
	b, _ = json.Marshal(s)
	obs, ds = Parse(b)
	if len(obs) != 1 || len(ds) != 1 || s.Role() != "Unknown" {
		t.Fatal(obs, ds)
	}
}
func TestProtocolRejectsUnsafeOrIncompleteData(t *testing.T) {
	for _, mutate := range []func(*Snapshot){func(s *Snapshot) { s.Metrics["SQL"] = 1 }, func(s *Snapshot) { s.Version = "mysql" }, func(s *Snapshot) { s.Identity = "password=sensitive" }, func(s *Snapshot) { s.LatencyMS = 6000 }, func(s *Snapshot) { s.Channels = []Channel{{Source: "host with SQL"}} }, func(s *Snapshot) { s.Channels = make([]Channel, 65) }} {
		s := fixture()
		mutate(&s)
		b, _ := json.Marshal(s)
		o, d := Parse(b)
		if len(o) != 0 || len(d) != 1 {
			t.Fatal(o, d)
		}
	}
	s := fixture()
	b, _ := json.Marshal(s)
	obs, _ := Parse(b)
	obs = append(obs, obs[0])
	if _, e := Decode(obs); e == nil {
		t.Fatal("duplicate manifest")
	}
}

type authority struct{ deny bool }

func (a *authority) IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error {
	if a.deny {
		return workspace.ErrDenied
	}
	return nil
}

type executor struct {
	calls int
	check bool
}

func (e *executor) Execute(ctx context.Context, p workspace.Principal, t sshcli.Target, id string) (sshcli.Result, error) {
	e.calls++
	if ctx.Err() != nil {
		return sshcli.Result{}, ctx.Err()
	}
	return sshcli.Result{StartedAt: time.Now()}, nil
}
func TestGrantRevocationAndCancellation(t *testing.T) {
	a := &authority{deny: true}
	next := &executor{}
	e := Executor{Next: next, Authority: a}
	_, err := e.Execute(context.Background(), workspace.Principal{}, sshcli.Target{}, Collector+".v1")
	if err == nil || next.calls != 0 {
		t.Fatal(err, next)
	}
	a.deny = false
	_, err = e.Execute(context.Background(), workspace.Principal{}, sshcli.Target{}, Collector+".v1")
	if err != nil || next.calls != 1 {
		t.Fatal(err, next)
	}
}

func TestNullNumbersCannotManufactureZeros(t *testing.T) {
	b, _ := json.Marshal(fixture())
	for _, key := range Metrics {
		var fields map[string]any
		json.Unmarshal(b, &fields)
		fields["metrics"].(map[string]any)[key] = nil
		bad, _ := json.Marshal(fields)
		if o, d := Parse(bad); len(o) != 0 || len(d) != 1 || d[0].Code != "parse_error" {
			t.Fatal(key, o, d)
		}
	}
	for _, key := range []string{"io_error", "sql_error"} {
		s := fixture()
		s.Channels = []Channel{{Name: "east", Source: "192.0.2.4", Port: ptr(3306), IO: "Yes", SQL: "Yes", Lag: ptr(0)}}
		b, _ := json.Marshal(s)
		var fields map[string]any
		json.Unmarshal(b, &fields)
		delete(fields["channels"].([]any)[0].(map[string]any), key)
		bad, _ := json.Marshal(fields)
		if o, _ := Parse(bad); len(o) != 0 {
			t.Fatal("missing error number accepted", key)
		}
		fields["channels"].([]any)[0].(map[string]any)[key] = nil
		bad, _ = json.Marshal(fields)
		if o, _ := Parse(bad); len(o) != 0 {
			t.Fatal("null error number accepted", key)
		}
	}
}
func TestCancellationReachesExecutor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := Executor{Authority: &authority{}, Next: &executor{}}
	if _, err := e.Execute(ctx, workspace.Principal{}, sshcli.Target{}, Collector+".v1"); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestActivityFailureDoesNotEraseReadiness(t *testing.T) {
	s := fixture()
	s.ActivityStatus = "permission_denied"
	s.Metrics = map[string]uint64{}
	b, _ := json.Marshal(s)
	o, d := Parse(b)
	if len(o) != 1 || len(d) != 2 || d[0].Code != "activity_permission_denied" {
		t.Fatal(o, d)
	}
	got, err := Decode(o)
	if err != nil || got.Status != "ready" || got.Replication != "ready" || got.ActivityStatus != "permission_denied" {
		t.Fatal(got, err)
	}
}
