// Package collection defines typed evidence, durable history contracts and bounded
// on-demand execution. Scheduling and health evaluation are separate concerns.
package collection

import (
	"context"
	"errors"
	"time"

	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type Value struct {
	Kind    string
	Text    string
	Number  float64
	Integer uint64
}

func Text(v string) Value    { return Value{Kind: "text", Text: v} }
func Number(v float64) Value { return Value{Kind: "number", Number: v} }
func Integer(v uint64) Value { return Value{Kind: "integer", Integer: v} }

type Observation struct {
	SourceID                                            string
	SourceRevision                                      int64
	SubjectType, AssetID, EndpointID, ProfileID         string
	ProfileVersion                                      int64
	CollectorID, CollectorVersion, CommandID, Transport string
	Key, Unit, Quality                                  string
	// Resource identifies a filesystem mount or discovered service; it is never an inventory identity.
	Resource string
	Value    Value
	// ObservedAt is the application sampling start; remote clock is not trusted.
	ObservedAt, ReceivedAt time.Time
}
type Diagnostic struct{ Code string }
type Result struct {
	ObservationCount                         int
	CollectorID, Version, CommandID, Outcome string
	TransportOutcome                         string
	StartedAt, EndedAt                       time.Time
	Observations                             []Observation
	Diagnostics                              []Diagnostic
}
type Run struct {
	CollectionSource                 Source
	Source, ScheduleID               string
	ScheduleRevision                 int64
	ID, State, Category, PrincipalID string
	SuccessCount, FailureCount       int
	EndpointRevision                 time.Time
	Target                           sshcli.Target
	StartedAt, EndedAt               time.Time
	Results                          []Result
}
type Parser func([]byte) ([]Observation, []Diagnostic)
type Spec struct {
	ID, Version, CommandID string
	// AlternateCommandIDs are reviewed transports for the same parser contract.
	AlternateCommandIDs []string
	Parse               Parser
	Optional            bool
}
type Registry struct{ specs []Spec }

var ErrUnknown = errors.New("unknown or disabled collector")

func NewRegistry(specs []Spec) (*Registry, error) {
	seen := map[string]bool{}
	for _, s := range specs {
		if s.ID == "" || s.Version == "" || s.CommandID == "" || s.Parse == nil || seen[s.ID] {
			return nil, ErrUnknown
		}
		seen[s.ID] = true
	}
	return &Registry{specs: append([]Spec(nil), specs...)}, nil
}
func (r *Registry) IDs() []string {
	ids := make([]string, 0, len(r.specs))
	for _, s := range r.specs {
		ids = append(ids, s.ID)
	}
	return ids
}

// Extend composes optional adapters without altering the default Linux request.
func (r *Registry) Extend(specs ...Spec) *Registry {
	out, err := NewRegistry(append(append([]Spec(nil), r.specs...), specs...))
	if err != nil {
		panic(err)
	}
	return out
}
func (r *Registry) Defaults() []string {
	var ids []string
	for _, s := range r.specs {
		if !s.Optional {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

type Executor interface {
	Execute(context.Context, workspace.Principal, sshcli.Target, string) (sshcli.Result, error)
}

// Collect validates the entire requested allowlist before any execution. The
// executor rechecks live authority for each individual static command.
func (r *Registry) Collect(ctx context.Context, e Executor, p workspace.Principal, t sshcli.Target, ids []string) (Run, error) {
	run := Run{Target: t, StartedAt: time.Now().UTC()}
	specs := make([]Spec, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		found := false
		for _, s := range r.specs {
			if s.ID == id && !seen[id] {
				specs = append(specs, s)
				found = true
				seen[id] = true
				break
			}
		}
		if !found {
			return run, ErrUnknown
		}
	}
	for _, s := range specs {
		raw, err := e.Execute(ctx, p, t, s.CommandID)
		commandID := s.CommandID
		if raw.CommandID != "" && raw.CommandID != commandID {
			allowed := false
			for _, alternate := range s.AlternateCommandIDs {
				if raw.CommandID == alternate {
					allowed = true
				}
			}
			if allowed {
				commandID = raw.CommandID
			} else {
				err = &sshcli.Failure{Category: sshcli.Unsupported}
			}
		}
		result := Result{CollectorID: s.ID, Version: s.Version, CommandID: commandID, StartedAt: raw.StartedAt, EndedAt: raw.EndedAt, Outcome: "success", TransportOutcome: "success"}
		if err != nil {
			code := string(sshcli.Internal)
			var f *sshcli.Failure
			if errors.As(err, &f) {
				code = string(f.Category)
			}
			result.TransportOutcome = code
			result.Outcome = "failed"
			result.Diagnostics = append(result.Diagnostics, Diagnostic{code})
			// df can exit 1 for an inaccessible mount while reporting other mounts.
			// Never parse truncated, timed-out, or untrusted output as usable facts.
			if s.ID != "linux.filesystems" || code != string(sshcli.CommandFailed) {
				run.Results = append(run.Results, result)
				continue
			}
		}
		obs, diag := s.Parse(raw.Stdout)
		result.ObservationCount = len(obs)
		result.Observations = obs
		result.Diagnostics = boundedDiagnostics(append(result.Diagnostics, diag...))
		if len(result.Diagnostics) > 0 {
			result.Outcome = "partial"
			if len(obs) == 0 {
				result.Outcome = "failed"
			}
		}
		for i := range result.Observations {
			o := &result.Observations[i]
			o.SubjectType = "asset"
			o.AssetID = t.AssetID
			o.EndpointID = t.EndpointID
			o.ProfileID = t.ProfileID
			o.ProfileVersion = t.ProfileVersion
			o.CollectorID = s.ID
			o.CollectorVersion = s.Version
			o.CommandID = commandID
			o.Transport = "ssh"
			o.Quality = "valid"
			o.ObservedAt = raw.StartedAt
			o.ReceivedAt = raw.EndedAt
		}
		run.Results = append(run.Results, result)
	}
	run.EndedAt = time.Now().UTC()
	run.Summarize()
	return run, nil
}

// Repeated malformed rows must not defeat persistence of unrelated evidence.
// Codes contain no remote output; retain distinct causes within a fixed budget.
func boundedDiagnostics(in []Diagnostic) []Diagnostic {
	out := make([]Diagnostic, 0, 16)
	seen := map[string]bool{}
	for _, d := range in {
		if seen[d.Code] {
			continue
		}
		seen[d.Code] = true
		if len(out) == 15 {
			out = append(out, Diagnostic{Code: "diagnostics_truncated"})
			break
		}
		out = append(out, d)
	}
	return out
}
