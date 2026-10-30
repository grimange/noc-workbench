// Package mariadb implements only the reviewed local socket monitoring protocol.
package mariadb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

const Collector = "mariadb.health"
const Key = "mariadb.snapshot"
const Limit = 64

var Metrics = []string{"Threads_connected", "Threads_running", "Max_used_connections", "Connections", "Aborted_connects", "Uptime", "max_connections"}
var token = regexp.MustCompile(`^[A-Za-z0-9_.:@+-]{1,128}$`)
var version = regexp.MustCompile(`^10\.[0-9]{1,2}\.[0-9]{1,3}-MariaDB[A-Za-z0-9_.+-]{0,80}$`)

type Channel struct {
	Name     string  `json:"name"`
	Source   string  `json:"source"`
	Port     *uint64 `json:"port"`
	IO       string  `json:"io"`
	SQL      string  `json:"sql"`
	Lag      *uint64 `json:"lag"`
	IOError  uint64  `json:"io_error"`
	SQLError uint64  `json:"sql_error"`
}
type Snapshot struct {
	Protocol       int               `json:"protocol"`
	Status         string            `json:"status"`
	Version        string            `json:"version"`
	Identity       string            `json:"identity"`
	ServerID       uint64            `json:"server_id"`
	LatencyMS      uint64            `json:"latency_ms"`
	Metrics        map[string]uint64 `json:"metrics"`
	ActivityStatus string            `json:"activity_status"`
	Replication    string            `json:"replication"`
	Channels       []Channel         `json:"channels,omitempty"`
}

// Required numeric fields must be present integers. encoding/json otherwise
// silently accepts null as zero, which would manufacture a measurement.
func requiredNumbers(b []byte, keys ...string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return errors.New("fields")
	}
	for _, key := range keys {
		raw, ok := fields[key]
		var value uint64
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil {
			return errors.New("number")
		}
	}
	return nil
}
func (s *Snapshot) UnmarshalJSON(b []byte) error {
	type plain Snapshot
	var value plain
	if requiredNumbers(b, "protocol", "server_id", "latency_ms") != nil || decode(b, &value) != nil {
		return errors.New("snapshot")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return errors.New("fields")
	}
	var metrics map[string]json.RawMessage
	if json.Unmarshal(fields["metrics"], &metrics) != nil {
		return errors.New("metrics")
	}
	for _, raw := range metrics {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("metric null")
		}
	}
	*s = Snapshot(value)
	return nil
}
func (c *Channel) UnmarshalJSON(b []byte) error {
	type plain Channel
	var value plain
	if requiredNumbers(b, "io_error", "sql_error") != nil || decode(b, &value) != nil {
		return errors.New("channel")
	}
	*c = Channel(value)
	return nil
}

func known(s string) bool {
	switch s {
	case "ready", "connection_unavailable", "authentication_denied", "permission_denied", "query_failure", "timeout", "unsupported", "unknown":
		return true
	}
	return false
}
func decode(b []byte, v any) error {
	if len(b) > 65536 {
		return errors.New("size")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errors.New("format")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing")
	}
	return nil
}
func Validate(s Snapshot) error {
	if s.Protocol != 1 || !known(s.Status) || !known(s.Replication) || !known(s.ActivityStatus) || len(s.Channels) > Limit || s.LatencyMS > 5000 {
		return errors.New("protocol")
	}
	if s.Status != "ready" {
		if s.Version != "" || s.Identity != "" || s.ServerID != 0 || len(s.Metrics) != 0 || len(s.Channels) != 0 || s.Replication != "unknown" || s.ActivityStatus != "unknown" {
			return errors.New("failed payload")
		}
		return nil
	}
	if !version.MatchString(s.Version) || !token.MatchString(s.Identity) || s.ServerID > 4294967295 {
		return errors.New("identity")
	}
	for k := range s.Metrics {
		found := false
		for _, key := range Metrics {
			found = found || key == k
		}
		if !found {
			return errors.New("metric")
		}
	}
	if s.Replication != "ready" && len(s.Channels) != 0 {
		return errors.New("incomplete channels")
	}
	seen := map[string]bool{}
	for _, c := range s.Channels {
		if (c.Name != "" && !token.MatchString(c.Name)) || seen[c.Name] || !token.MatchString(c.Source) || c.Port == nil || *c.Port == 0 || *c.Port > 65535 || c.IOError > 4294967295 || c.SQLError > 4294967295 {
			return errors.New("channel")
		}
		seen[c.Name] = true
		if c.IO != "Yes" && c.IO != "No" && c.IO != "Connecting" && c.IO != "Unknown" {
			return errors.New("io")
		}
		if c.SQL != "Yes" && c.SQL != "No" && c.SQL != "Unknown" {
			return errors.New("sql")
		}
	}
	return nil
}
func Parse(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	var s Snapshot
	if decode(b, &s) != nil || Validate(s) != nil {
		return nil, []collection.Diagnostic{{Code: "parse_error"}}
	}
	if s.Status != "ready" {
		return nil, []collection.Diagnostic{{Code: s.Status}}
	}
	channels := s.Channels
	s.Channels = nil
	obs := []collection.Observation{}
	add := func(resource string, v any) {
		b, _ := json.Marshal(v)
		obs = append(obs, collection.Observation{Key: Key, Resource: resource, Unit: "text", Value: collection.Text(string(b))})
	}
	// Stable channel ordering avoids artificial series changes between samples.
	sort.Slice(channels, func(i, j int) bool { return channels[i].Name < channels[j].Name })
	add("manifest", s)
	for i, c := range channels {
		add(fmt.Sprintf("channel/%03d", i), c)
	}
	var ds []collection.Diagnostic
	if s.ActivityStatus != "ready" {
		ds = append(ds, collection.Diagnostic{Code: "activity_" + s.ActivityStatus})
	}
	if s.Replication != "ready" {
		ds = append(ds, collection.Diagnostic{Code: s.Replication})
	}
	if len(s.Metrics) != len(Metrics) {
		ds = append(ds, collection.Diagnostic{Code: "missing_metrics"})
	}
	return obs, ds
}
func Decode(obs []collection.Observation) (Snapshot, error) {
	var s Snapshot
	seen := map[string]bool{}
	var channels []Channel
	for _, o := range obs {
		if o.Key != Key || o.Value.Kind != "text" || seen[o.Resource] {
			return s, errors.New("observation")
		}
		seen[o.Resource] = true
		if o.Resource == "manifest" {
			if decode([]byte(o.Value.Text), &s) != nil || len(s.Channels) != 0 {
				return s, errors.New("manifest")
			}
		} else {
			var c Channel
			if o.Resource != fmt.Sprintf("channel/%03d", len(channels)) || decode([]byte(o.Value.Text), &c) != nil {
				return s, errors.New("channel")
			}
			channels = append(channels, c)
		}
	}
	s.Channels = channels
	if !seen["manifest"] || s.Status != "ready" || Validate(s) != nil {
		return s, errors.New("snapshot")
	}
	return s, nil
}
func (s Snapshot) Role() string {
	if s.Replication == "ready" && len(s.Channels) > 0 {
		return "Replica"
	}
	return "Unknown"
}
func (c Channel) Condition() string {
	if c.IOError != 0 {
		return "I/O failure"
	}
	if c.SQLError != 0 {
		return "SQL/applier failure"
	}
	if c.IO == "No" && c.SQL == "No" {
		return "Configured but stopped"
	}
	if c.IO == "No" || c.IO == "Connecting" {
		return "I/O failure"
	}
	if c.SQL == "No" {
		return "SQL/applier failure"
	}
	if c.IO != "Yes" || c.SQL != "Yes" || c.Lag == nil {
		return "Unknown"
	}
	if *c.Lag > 0 {
		return "Delayed"
	}
	return "Operating"
}
func Specs() []collection.Spec {
	return []collection.Spec{{ID: Collector, Version: "1", CommandID: Collector + ".v1", Parse: Parse, Optional: true}}
}

type Authority interface {
	IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error
}
type Executor struct {
	Next      collection.Executor
	Authority Authority
}

func (e Executor) Execute(ctx context.Context, p workspace.Principal, t sshcli.Target, id string) (sshcli.Result, error) {
	if id == Collector+".v1" {
		check := func(c context.Context) error {
			if e.Authority == nil {
				return workspace.ErrDenied
			}
			return e.Authority.IntegrationAllowed(c, p, t, "mariadb")
		}
		if err := check(ctx); err != nil {
			return sshcli.LocalResult(err)
		}
		ctx = sshcli.WithExecutionCheck(ctx, check)
	}
	return e.Next.Execute(ctx, p, t, id)
}
