package health

import (
	"noc-workbench/internal/collection"
	"time"
)

// Operational conditions are read projections of existing evidence and control
// state. They do not collect data or establish comprehensive service health.
func OperationalSelector(s string) bool {
	switch s {
	case "monitoring.continuity", "server.ssh_unreachable", "service.runtime.unavailable", "service.ami.disconnected", "service.authentication.repeated", "database.query.failed", "database.replication.failed", "database.replication.lag_seconds":
		return true
	}
	return false
}

type Condition struct {
	Evidence      collection.Evidence
	State, Reason string // healthy/degraded/unknown; unknown never implies recovery
	Value         *uint64
}

func OperationalReadings(conditions []Condition, policies []Policy, at time.Time) []Reading {
	var out []Reading
	for _, c := range conditions {
		for _, p := range policies {
			if !OperationalSelector(p.Selector) || p.Selector != c.Evidence.Key {
				continue
			}
			r := Reading{Evidence: c.Evidence, PolicyID: p.ID, PolicyRevision: p.Revision, PolicyVersion: p.Version, TTLSeconds: p.TTLSeconds, Quality: "unknown", Freshness: "unknown", Health: "unknown", Reason: c.Reason}
			e := c.Evidence
			if p.Enabled && p.Validate() == nil && !p.CreatedAt.After(at) && !e.ObservedAt.IsZero() && !e.ReceivedAt.Before(e.ObservedAt) && !e.ReceivedAt.After(at) && !e.ObservedAt.After(at) {
				r.ExpiresAt = e.ObservedAt.Add(time.Duration(p.TTLSeconds) * time.Second)
				r.AgeKnown = true
				r.AgeSeconds = int64(at.Sub(e.ObservedAt) / time.Second)
				r.Freshness = "stale"
				if at.Before(r.ExpiresAt) {
					r.Freshness = "fresh"
					if c.State == "healthy" || c.State == "degraded" {
						r.Quality = "valid"
						r.Health = c.State
					}
					if p.Rule == "value_high" && c.Value != nil && r.Quality == "valid" {
						r.Health = "healthy"
						if float64(*c.Value) >= p.Threshold {
							r.Health = "degraded"
						}
					}
				}
			}
			out = append(out, r)
		}
	}
	return out
}

// Connectivity is the shared, order-independent SSH evidence reduction used by
// availability and alerts. Local failures and mixed results are inconclusive.
func Connectivity(r collection.Run) string {
	codes := map[string]bool{}
	switch r.Category {
	case "host_key_mismatch", "unknown_host_key", "authentication_failed", "permission_denied", "credential_unavailable":
		codes[r.Category] = true
	}
	if len(r.Results) == 0 && r.Category != "" && r.Category != "success" {
		codes[r.Category] = true
	}
	for _, c := range r.Results {
		if c.TransportOutcome != "" {
			codes[c.TransportOutcome] = true
		}
	}
	for _, code := range []string{"host_key_mismatch", "unknown_host_key", "authentication_failed", "permission_denied", "credential_unavailable"} {
		if codes[code] {
			return code
		}
	}
	if len(codes) == 0 {
		return ""
	}
	only := true
	for code := range codes {
		if !NetworkFailure(code) {
			only = false
		}
	}
	if only {
		return "connection_timeout"
	}
	if len(codes) == 1 && codes["success"] {
		return "success"
	}
	return "inconclusive"
}
func NetworkFailure(code string) bool {
	return code == "connection_timeout" || code == "connection_refused" || code == "dns_failure"
}
