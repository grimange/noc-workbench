package web

import (
	"fmt"
	"noc-workbench/internal/collection"
	"time"
)

// Availability is SSH reachability, never host power or application health.
// Two adjacent attempts must both establish a network failure. Command failures,
// cancellation and missing results never satisfy this rule.
func availability(d runtimeData, at time.Time) (state, tone, reason string, attention int, checked time.Time) {
	state, tone, reason = "Unknown", "neutral", "No recent conclusive SSH evidence"
	// Attempt time is historical fact, independent of current authority/freshness.
	for _, r := range d.Attempts {
		if r.Target.AssetID == d.Profile.Target.AssetID && !r.EndedAt.IsZero() && !r.EndedAt.After(at) && !r.StartedAt.IsZero() && !r.StartedAt.After(r.EndedAt) {
			checked = r.EndedAt
			break
		}
	}
	if d.Paused {
		return "Paused", tone, "Monitoring intentionally suspended; reachability unknown", 0, checked
	}
	if d.AuthorizationDiagnostic != "" {
		return state, "warning", d.AuthorizationDiagnostic, 3, checked
	}
	if !d.Enabled || !d.Authorized {
		return state, tone, "Monitoring disabled or authorization unavailable", 0, checked
	}
	if d.ConnectivityTTL <= 0 {
		reason = "No enabled freshness policy for SSH evidence"
		return
	}
	ttl := time.Duration(d.ConnectivityTTL) * time.Second
	fresh := func(r collection.Run) bool {
		return !r.EndedAt.IsZero() && !r.EndedAt.After(at) && !r.StartedAt.IsZero() && !r.StartedAt.After(r.EndedAt) && at.Sub(r.StartedAt) < ttl && r.Target == d.Profile.Target
	}
	if len(d.Attempts) == 0 {
		return
	}
	attempts := make([]collection.Run, 0, len(d.Attempts))
	for _, r := range d.Attempts {
		if !r.EndedAt.IsZero() {
			attempts = append(attempts, r)
		}
	}
	if len(attempts) == 0 {
		return
	}
	latest := attempts[0]
	if !fresh(latest) {
		reason = "SSH evidence expired or collection incomplete"
		return
	}
	checked = latest.EndedAt
	code := connectivity(latest)
	switch code {
	case "success":
		return "Reachable", "observed", "Recent authorized SSH collection; application health evaluated separately", 0, checked
	case "authentication_failed", "permission_denied", "credential_unavailable":
		return state, "warning", "SSH authentication / authorization problem", 3, checked
	case "host_key_mismatch", "unknown_host_key":
		return state, "warning", "SSH host-key trust problem", 3, checked
	case "connection_timeout", "connection_refused", "dns_failure":
		if len(attempts) > 1 && fresh(attempts[1]) && attempts[1].StartedAt.Before(latest.StartedAt) && networkFailure(connectivity(attempts[1])) {
			return "SSH unreachable", "warning", "Two consecutive SSH connectivity failures; host power state unknown", 4, checked
		}
		reason = "SSH connectivity failure — awaiting corroboration"
		// A single transient failure does not erase recent successful reachability.
		if len(attempts) > 1 && fresh(attempts[1]) && connectivity(attempts[1]) == "success" {
			return "Reachable", "warning", reason, 2, checked
		}
		return state, "warning", reason, 2, checked
	default:
		return state, tone, "Collection inconclusive for SSH reachability", 1, checked
	}
}
func networkFailure(code string) bool {
	return code == "connection_timeout" || code == "connection_refused" || code == "dns_failure"
}
func connectivity(r collection.Run) string {
	// Order-independent reduction. Trust/authentication diagnostics survive later
	// guard denials; mixed connectivity/command results are inconclusive.
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
	onlyNetwork := true
	for code := range codes {
		if !networkFailure(code) {
			onlyNetwork = false
		}
	}
	if onlyNetwork {
		return "connection_timeout"
	}
	if len(codes) == 1 && codes["success"] {
		return "success"
	}
	return "inconclusive"
}
func observationAge(at, checked time.Time) string {
	age := at.Sub(checked)
	if age < time.Minute {
		return "<1 min ago"
	}
	if age < time.Hour {
		return fmt.Sprintf("%d min ago", int(age.Minutes()))
	}
	if age < 24*time.Hour {
		return fmt.Sprintf("%d hr ago", int(age.Hours()))
	}
	return fmt.Sprintf("%d d ago", int(age.Hours()/24))
}
