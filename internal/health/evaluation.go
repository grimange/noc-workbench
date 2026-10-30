// Package health interprets persisted evidence without performing I/O or reading a clock.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/workspace"
)

const Version = "linux-evidence.v1"

// MaxPolicies bounds all supported family and observation selectors, with room
// for additive optional adapters without truncating valid configurations.
const MaxPolicies = 64

var ErrPolicy = errors.New("invalid or unsupported evaluation policy")
var ErrEvidence = errors.New("invalid or excessive evaluation evidence")

type Policy struct {
	ID                      string
	Revision                int64
	Version, Selector, Rule string
	Scope                   string // canonical or asset override
	TTLSeconds              int
	// Threshold uses the selector's unit: percent, bytes, seconds, or zero for
	// an evidence-backed boolean condition.
	Threshold float64
	Enabled   bool
	CreatedAt time.Time
	Actor     string
}

func (p Policy) Validate() error {
	if p.Version != Version || p.Revision < 1 || p.TTLSeconds < 1 || p.TTLSeconds > 604800 || !SupportedSelector(p.Selector) || math.IsNaN(p.Threshold) || math.IsInf(p.Threshold, 0) {
		return ErrPolicy
	}
	switch p.Rule {
	case "none":
		if p.Threshold != 0 {
			return ErrPolicy
		}
	case "filesystem_used_high":
		if p.Selector != "linux.filesystem.utilization_percent" || p.Threshold < 0 || p.Threshold > 100 {
			return ErrPolicy
		}
	case "memory_available_low":
		if p.Selector != "linux.mem.available_bytes" || p.Threshold < 0 || p.Threshold > math.Pow(2, 53) || math.Trunc(p.Threshold) != p.Threshold {
			return ErrPolicy
		}
	case "condition_failed":
		if !OperationalSelector(p.Selector) || p.Selector == "monitoring.continuity" || p.Selector == "database.replication.lag_seconds" || p.Threshold != 0 {
			return ErrPolicy
		}
	case "monitoring_interrupted":
		if p.Selector != "monitoring.continuity" || p.Threshold < 180 || p.Threshold > 86400 {
			return ErrPolicy
		}
	case "value_high":
		if p.Selector != "database.replication.lag_seconds" || p.Threshold <= 0 || p.Threshold > 86400 {
			return ErrPolicy
		}
	default:
		return ErrPolicy
	}
	return nil
}
func SupportedSelector(s string) bool {
	if OperationalSelector(s) {
		return true
	}
	switch s {
	case "asterisk.registrations", "asterisk.registration.snapshot", "linux.baseline", "linux.baseline.cpu_percent", "linux.baseline.pressure_some_percent", "linux.baseline.swap_total_bytes", "linux.baseline.swap_free_bytes", "linux.baseline.processes", "linux.baseline.units", "linux.baseline.jobs", "linux.baseline.status", "linux.services", "linux.service.runtime", "vicidial.discovery", "vicidial.discovery.snapshot", "vicidial.api.version", "vicidial.api.campaigns", "vicidial.api.agents", "vicidial.api.build", "vicidial.campaigns.configured_count", "vicidial.campaigns.active_count", "vicidial.agents.visible_logged_in_count", "vicidial.agents.visible_in_call_count", "vicidial.agents.visible_paused_count", "asterisk.identity", "asterisk.channels", "asterisk.modules", "asterisk.pjsip", "asterisk.version", "asterisk.cli.available", "asterisk.channels.active", "asterisk.modules.pjsip.available", "asterisk.modules.chan_pjsip.available", "asterisk.pjsip.registrations.count", "linux.identity", "linux.uptime", "linux.load", "linux.memory", "linux.filesystems", "linux.hostname", "linux.os.name", "linux.os.version", "linux.kernel.release", "linux.architecture", "linux.uptime.seconds", "linux.load.1m", "linux.load.5m", "linux.load.15m", "linux.cpu.logical_count", "linux.mem.total_bytes", "linux.mem.available_bytes", "linux.mem.free_bytes", "linux.filesystem.identifier", "linux.filesystem.total_bytes", "linux.filesystem.used_bytes", "linux.filesystem.available_bytes", "linux.filesystem.utilization_percent":
		return true
	}
	return false
}

type Input struct {
	AuthorizationDiagnostic    string
	Scope                      collection.HistoryScope
	At                         time.Time
	Active, Trusted            bool
	LatestAttempt, LastSuccess *collection.Run
	RecentAttempts             []collection.Run
	Evidence                   []collection.Evidence
	Policies                   []Policy // one applicable revision per selector, selected as-of by repository
	IntervalSeconds            int
	Authority                  map[string]int64 // current verified profile revisions; nil for standalone supplied context
}
type Reading struct {
	Evidence                           collection.Evidence
	Quality, Freshness, Health, Reason string
	PolicyID, PolicyVersion            string
	PolicyRevision                     int64
	TTLSeconds                         int
	AgeSeconds                         int64
	ExpiresAt                          time.Time
	CadenceConflict                    bool
	AgeKnown                           bool
}
type Evaluation struct {
	Version                    string
	EvaluatedAt                time.Time
	Collection                 string
	LatestAttempt, LastSuccess *collection.Run
	Readings                   []Reading
	Health                     string // generic facts never establish comprehensive host/service health
	Reason                     string
	Coverage                   string
}
type Repository interface {
	EvaluationEvidence(context.Context, workspace.Principal, collection.HistoryScope, time.Time) (Input, error)
	SaveEvaluationPolicy(context.Context, workspace.Principal, collection.HistoryScope, Policy) (Policy, error)
}

// Evaluate uses half-open validity [observed_at, observed_at+TTL). At exact
// expiry evidence is stale. It never changes input, extends age on failure, or
// infers an outage from transport or scheduling state.
func Evaluate(in Input) (Evaluation, error) {
	out := Evaluation{Version: Version, EvaluatedAt: in.At.UTC(), Collection: "never_attempted", Health: "unknown", Reason: "Infrastructure observations alone do not establish service health", Coverage: "Retained evidence only; missing historical samples may have expired under retention"}
	if in.At.IsZero() || len(in.Evidence) > 2048 || len(in.Policies) > MaxPolicies {
		return out, ErrEvidence
	}
	policies := map[string]Policy{}
	for _, p := range in.Policies {
		if err := p.Validate(); err != nil {
			return out, err
		}
		if _, ok := policies[p.Selector]; ok {
			return out, ErrPolicy
		}
		if p.CreatedAt.IsZero() || p.CreatedAt.After(in.At) {
			return out, ErrPolicy
		}
		policies[p.Selector] = p
	}
	if in.LatestAttempt != nil {
		r := *in.LatestAttempt
		if !r.StartedAt.IsZero() && !r.StartedAt.After(in.At) {
			if r.EndedAt.IsZero() || r.EndedAt.After(in.At) {
				r.State = "running"
				r.Category = ""
				r.Results = nil
				r.SuccessCount = 0
				r.FailureCount = 0
				r.EndedAt = time.Time{}
			}
			out.Collection = r.State
			out.LatestAttempt = &r
		}
	}
	if in.LastSuccess != nil && !in.LastSuccess.EndedAt.IsZero() && !in.LastSuccess.EndedAt.After(in.At) {
		r := *in.LastSuccess
		out.LastSuccess = &r
	}
	seen := map[string]bool{}
	for _, e := range in.Evidence {
		if e.AssetID != in.Scope.AssetID || e.SourceID != in.Scope.SourceID || (e.SourceID != "" && e.AssetID != "") || !SupportedSelector(e.Key) || len(e.Resource) > 4096 {
			return out, ErrEvidence
		}
		series := e.Key + "\x00" + e.Resource
		if seen[series] {
			return out, ErrEvidence
		}
		seen[series] = true
		r := Reading{Evidence: e, Quality: e.Quality, Freshness: "unknown", Health: "unknown", Reason: "No supported current health rule"}
		p, ok := policies[e.Key]
		if !ok {
			p, ok = policies[e.CollectorID]
		}
		if ok {
			r.PolicyID = p.ID
			r.PolicyRevision = p.Revision
			r.PolicyVersion = p.Version
			r.TTLSeconds = p.TTLSeconds
		}
		switch e.Quality {
		case "valid", "invalid", "partial", "unsupported", "unknown":
		default:
			r.Quality = "unknown"
		}
		usable := e.Quality == "valid" && validValue(e)
		if e.Quality == "valid" && !usable {
			r.Quality = "invalid"
		}
		if e.ObservedAt.IsZero() || e.ReceivedAt.IsZero() || e.ReceivedAt.Before(e.ObservedAt) || e.ObservedAt.After(in.At) || e.ReceivedAt.After(in.At) {
			r.Quality = "invalid"
			r.Reason = "Missing, future or inconsistent evidence timestamp"
			out.Readings = append(out.Readings, r)
			continue
		}
		r.AgeSeconds = int64(in.At.Sub(e.ObservedAt) / time.Second)
		r.AgeKnown = true
		if !ok || !p.Enabled {
			r.Reason = "No enabled applicable policy"
			out.Readings = append(out.Readings, r)
			continue
		}
		r.CadenceConflict = in.IntervalSeconds > p.TTLSeconds
		r.ExpiresAt = e.ObservedAt.Add(time.Duration(p.TTLSeconds) * time.Second)
		if usable {
			r.Freshness = "stale"
			if in.At.Before(r.ExpiresAt) {
				r.Freshness = "fresh"
			}
		}
		authority := in.Authority == nil || (e.ProfileVersion > 0 && in.Authority[e.ProfileID] == e.ProfileVersion)
		if !in.Active || !in.Trusted || !authority {
			r.Reason = "Current resource or trust authority is unavailable"
		} else if usable && r.Freshness == "fresh" {
			switch p.Rule {
			case "filesystem_used_high":
				if !PersistentFilesystem(e, in.Evidence) {
					r.Reason = "Filesystem persistence unverified or transient mount excluded"
					break
				}
				r.Health = "healthy"
				r.Reason = "Filesystem usage below explicit threshold"
				if float64(e.Value.Integer) >= p.Threshold {
					r.Health = "degraded"
					r.Reason = "Filesystem usage at or above explicit threshold"
				}
			case "memory_available_low":
				r.Health = "healthy"
				r.Reason = "Available memory above explicit threshold"
				if e.Value.Integer <= uint64(p.Threshold) {
					r.Health = "degraded"
					r.Reason = "Available memory at or below explicit threshold"
				}
			}
		} else {
			r.Reason = "Health requires fresh valid evidence"
		}
		out.Readings = append(out.Readings, r)
	}
	sort.Slice(out.Readings, func(i, j int) bool {
		a, b := out.Readings[i], out.Readings[j]
		if a.Evidence.Key != b.Evidence.Key {
			return a.Evidence.Key < b.Evidence.Key
		}
		return a.Evidence.Resource < b.Evidence.Resource
	})
	return out, nil
}
func validValue(e collection.Evidence) bool {
	k, v, u := e.Key, e.Value, e.Unit
	if strings.HasPrefix(k, "linux.baseline.") {
		if e.CollectorID != "linux.baseline" || e.SourceID != "" {
			return false
		}
		switch k {
		case "linux.baseline.cpu_percent", "linux.baseline.pressure_some_percent":
			return e.Resource == "" && v.Kind == "number" && u == "percent" && v.Number >= 0 && v.Number <= 100
		case "linux.baseline.swap_total_bytes", "linux.baseline.swap_free_bytes":
			return e.Resource == "" && v.Kind == "integer" && u == "bytes"
		default:
			return v.Kind == "text" && u == "text" && len(v.Text) > 0 && len(v.Text) <= 4096
		}
	}
	if k == "linux.service.runtime" {
		return e.CollectorID == "linux.services" && e.SourceID == "" && e.Resource != "" && v.Kind == "text" && u == "text" && len(v.Text) > 0 && len(v.Text) <= 512
	}
	if strings.HasPrefix(k, "vicidial.") {
		if e.SourceID == "" || e.Resource != "" {
			return false
		}
		switch k {
		case "vicidial.api.version", "vicidial.api.build":
			return e.CollectorID == "vicidial.api.version" && v.Kind == "text" && u == "text" && len(v.Text) > 0 && len(v.Text) <= 64
		case "vicidial.campaigns.configured_count", "vicidial.campaigns.active_count":
			return e.CollectorID == "vicidial.api.campaigns" && v.Kind == "integer" && u == "count" && v.Integer <= 1
		case "vicidial.agents.visible_logged_in_count", "vicidial.agents.visible_in_call_count", "vicidial.agents.visible_paused_count":
			return e.CollectorID == "vicidial.api.agents" && v.Kind == "integer" && u == "count" && v.Integer <= 1000
		}
		return false
	}
	if k == "asterisk.registration.snapshot" {
		return e.CollectorID == "asterisk.registrations" && e.SourceID == "" && e.Resource != "" && v.Kind == "text" && u == "text" && len(v.Text) <= 4096 && json.Valid([]byte(v.Text))
	}
	if strings.HasPrefix(k, "asterisk.") {
		if e.Resource != "" {
			return false
		}
		switch k {
		case "asterisk.version":
			return e.CollectorID == "asterisk.identity" && v.Kind == "text" && u == "text" && len(v.Text) > 0 && len(v.Text) <= 128
		case "asterisk.cli.available":
			return e.CollectorID == "asterisk.identity" && v.Kind == "integer" && u == "count" && v.Integer == 1
		case "asterisk.channels.active":
			return e.CollectorID == "asterisk.channels" && v.Kind == "integer" && u == "count"
		case "asterisk.modules.pjsip.available", "asterisk.modules.chan_pjsip.available":
			return e.CollectorID == "asterisk.modules" && v.Kind == "integer" && u == "count" && v.Integer <= 1
		case "asterisk.pjsip.registrations.count":
			return e.CollectorID == "asterisk.pjsip" && v.Kind == "integer" && u == "count" && v.Integer <= 4096
		}
		return false
	}
	family := "linux.identity"
	switch {
	case strings.HasPrefix(k, "linux.filesystem."):
		family = "linux.filesystems"
	case strings.HasPrefix(k, "linux.mem."):
		family = "linux.memory"
	case strings.HasPrefix(k, "linux.load."), k == "linux.cpu.logical_count":
		family = "linux.load"
	case k == "linux.uptime.seconds":
		family = "linux.uptime"
	}
	if e.CollectorID != family || (family == "linux.filesystems") != (e.Resource != "") {
		return false
	}
	if k == "linux.filesystem.identifier" || k == "linux.hostname" || strings.HasPrefix(k, "linux.os.") || k == "linux.kernel.release" || k == "linux.architecture" {
		return v.Kind == "text" && u == "text" && len(v.Text) > 0 && len(v.Text) <= 4096
	}
	if k == "linux.uptime.seconds" || strings.HasPrefix(k, "linux.load.") {
		want := "load"
		if k == "linux.uptime.seconds" {
			want = "seconds"
		}
		return v.Kind == "number" && u == want && v.Number >= 0 && !math.IsNaN(v.Number) && !math.IsInf(v.Number, 0)
	}
	if k == "linux.cpu.logical_count" {
		return v.Kind == "integer" && u == "count" && v.Integer > 0
	}
	if k == "linux.filesystem.utilization_percent" {
		return v.Kind == "integer" && u == "percent" && v.Integer <= 100
	}
	return v.Kind == "integer" && u == "bytes"
}
