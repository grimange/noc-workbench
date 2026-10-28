package web

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	ast "noc-workbench/internal/integrations/asterisk"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type registrationFamily struct {
	Name, Command, Freshness, State string
	Current                         bool
	Snapshot                        ast.RegistrationSnapshot
	Evidence                        collection.Evidence
	Changes                         []string
	PreviousAt                      time.Time
}
type asteriskRegistrationData struct {
	Available, Authorized, Scheduled bool
	Status, Outcome, Diagnostic      string
	AttemptAt                        time.Time
	Families                         []registrationFamily
}

func registrationView(in health.Input, out health.Evaluation, profile scheduler.Profile, allowed, paused bool, history []collection.Evidence) asteriskRegistrationData {
	d := asteriskRegistrationData{Available: true, Authorized: allowed, Status: "Asterisk CLI authorization required", Outcome: "Not attempted"}
	d.Scheduled = allowed && profile.Enabled && profile.Authorized && (profile.Eligible || profile.EvidenceEligible) && !profile.Paused && !paused && slices.Contains(profile.Collectors, ast.RegistrationCollector)
	if allowed {
		d.Status = "Registration snapshots not scheduled"
	}
	if d.Scheduled {
		d.Status = fmt.Sprintf("Registration monitoring active · %d-second target", profile.Interval)
	} else if allowed && paused {
		d.Status = "Monitoring paused — historical snapshots only"
	}
	attempts := append([]collection.Run(nil), in.RecentAttempts...)
	if in.LatestAttempt != nil {
		attempts = append(attempts, *in.LatestAttempt)
	}
	for _, run := range attempts {
		for _, result := range run.Results {
			if result.CollectorID == ast.RegistrationCollector && (d.AttemptAt.IsZero() || run.StartedAt.After(d.AttemptAt)) {
				d.AttemptAt = run.StartedAt
				d.Outcome = result.Outcome
				var codes []string
				for _, diag := range result.Diagnostics {
					codes = append(codes, diag.Code)
				}
				d.Diagnostic = strings.Join(codes, ", ")
			}
		}
	}
	for i, source := range ast.RegistrationSources {
		f := registrationFamily{Name: strings.ReplaceAll(source, "_", " "), Command: ast.RegistrationCommands[i], State: "Unknown", Freshness: "Unavailable"}
		for _, reading := range out.Readings {
			ev := reading.Evidence
			if ev.Key != ast.RegistrationKey || ev.Resource != source {
				continue
			}
			snapshot, e := ast.DecodeRegistration(ev, in.Evidence)
			if e != nil {
				f.State = "Incomplete snapshot"
				continue
			}
			f.Snapshot = snapshot
			f.Evidence = ev
			f.Freshness = reading.Freshness
			authorized := in.Active && in.Trusted && in.Authority[ev.ProfileID] == ev.ProfileVersion && ev.ProfileID == profile.Target.ProfileID && ev.ProfileVersion == profile.Target.ProfileVersion
			f.Current = d.Scheduled && authorized && reading.Freshness == "fresh" && reading.Quality == "valid"
			if d.AttemptAt.After(ev.ObservedAt) && (d.Outcome == "failed" || strings.Contains(d.Diagnostic, source+"_")) {
				f.Current = false
			}
			f.State = "Historical"
			if f.Current {
				f.State = "Current"
			}
			if snapshot.Status == "unsupported" {
				f.State = "Unsupported"
			}
			// Only compare complete successful command snapshots on the same enrollment
			// revision. Time brackets describe polling detection, not remote event time.
			if snapshot.Status == "supported" {
				for _, old := range history {
					if old.Key == ast.RegistrationKey && old.Resource == source && old.RunID != ev.RunID && old.ProfileID == ev.ProfileID && old.ProfileVersion == ev.ProfileVersion && old.ObservedAt.Before(ev.ObservedAt) {
						previous, e := ast.DecodeRegistration(old, history)
						if e == nil && previous.Status == "supported" {
							f.Changes = registrationChanges(previous.Rows, snapshot.Rows)
							f.PreviousAt = old.ObservedAt
							break
						}
					}
				}
			}
			break
		}
		d.Families = append(d.Families, f)
	}
	return d
}
func registrationChanges(before, after []ast.RegistrationRow) []string {
	old := map[string]ast.RegistrationRow{}
	current := map[string]bool{}
	var changes []string
	for _, r := range before {
		old[r.ID] = r
	}
	for _, r := range after {
		current[r.ID] = true
		p, exists := old[r.ID]
		if !exists {
			changes = append(changes, r.ID+": appeared in snapshot")
		} else if p.Registration != r.Registration || p.Reachability != r.Reachability || p.Address != r.Address {
			changes = append(changes, r.ID+": state or contact changed")
		}
	}
	for _, r := range before {
		if !current[r.ID] {
			changes = append(changes, r.ID+": disappeared from snapshot")
		}
	}
	slices.Sort(changes)
	return changes
}
func (s *Server) serverAsteriskData(r *http.Request, v workspace.ServerDetail, in health.Input, out health.Evaluation, rt runtimeData) (asteriskRegistrationData, error) {
	allowed := false
	if authority, ok := s.store.(interface {
		IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error
	}); ok {
		allowed = authority.IntegrationAllowed(r.Context(), operatorPrincipal(), rt.Profile.Target, "asterisk") == nil
	}
	var history []collection.Evidence
	if repo, ok := s.store.(interface {
		RecentCollectorEvidence(context.Context, workspace.Principal, collection.HistoryScope, string, string) ([]collection.Evidence, error)
	}); ok {
		var e error
		history, e = repo.RecentCollectorEvidence(r.Context(), operatorPrincipal(), in.Scope, ast.RegistrationCollector, ast.RegistrationKey)
		if e != nil {
			return asteriskRegistrationData{}, e
		}
	}
	if repo, ok := s.store.(interface {
		LatestCollectorAttempt(context.Context, workspace.Principal, collection.HistoryScope, string) (*collection.Run, error)
	}); ok {
		attempt, e := repo.LatestCollectorAttempt(r.Context(), operatorPrincipal(), in.Scope, ast.RegistrationCollector)
		if e != nil {
			return asteriskRegistrationData{}, e
		}
		if attempt != nil {
			in.RecentAttempts = append(in.RecentAttempts, *attempt)
		}
	}
	return registrationView(in, out, rt.Profile, allowed, rt.Paused, history), nil
}

// Authorization is an explicit POST for the verified revision. Existing baseline
// profiles are extended; neither scoped nor profile pauses are cleared here.
func (s *Server) serverAsterisk(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	repo, ok := s.store.(workspace.ServerRepository)
	authority, has := s.store.(interface {
		SetIntegration(context.Context, workspace.Principal, collection.HistoryScope, sshcli.Target, string, bool) error
	})
	if !ok || !has || s.options.Enrollment == nil || s.options.Discovery == nil || s.options.Scheduler == nil {
		http.Error(w, "Asterisk monitoring unavailable", 503)
		return
	}
	scope, e := (workspace.LocalOperatorPolicy{}).Scope(operatorPrincipal(), workspace.ScheduleManage)
	if e != nil {
		http.Error(w, "Forbidden", 403)
		return
	}
	v, e := repo.ServerDetails(r.Context(), scope, r.PathValue("asset"))
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	if r.PostForm.Get("authorize") != "yes" {
		http.Error(w, "Explicit Asterisk CLI snapshot authorization required", 400)
		return
	}
	records, e := s.options.Enrollment.List(r.Context(), operatorPrincipal(), v.CustomerID, v.EnvironmentID, v.ID)
	if e != nil {
		s.inventoryFailure(w, d, e)
		return
	}
	for _, rec := range records {
		if rec.ID != r.PostForm.Get("profile") || rec.EndpointID != r.PostForm.Get("endpoint") {
			continue
		}
		if rec.State != "connection_verified" || strconv.FormatInt(rec.Revision, 10) != r.PostForm.Get("revision") {
			http.Error(w, "Verified SSH enrollment changed", 409)
			return
		}
		snap, e := s.options.Scheduler.Status(r.Context(), operatorPrincipal())
		if e != nil {
			http.Error(w, "Scheduler unavailable", 503)
			return
		}
		var p scheduler.Profile
		for _, x := range snap.Profiles {
			if x.AssetID == v.ID && x.CustomerID == v.CustomerID && x.EnvironmentID == v.EnvironmentID && x.CollectionSource.ID == "" {
				p = x
				break
			}
		}
		if p.ID == "" || !p.Enabled || !p.Authorized || p.Target != rec.Target() {
			http.Error(w, "Authorize baseline background monitoring for this connection first", 409)
			return
		}
		rev, e := strconv.ParseInt(r.PostForm.Get("schedule_revision"), 10, 64)
		if e != nil || rev != p.Revision {
			http.Error(w, "Schedule changed; reload before authorization", 409)
			return
		}
		if len(maintenance(v.Server, p, snap).Blockers) > 0 {
			http.Error(w, "Monitoring is paused; use contextual monitoring controls first. No pause was changed.", 409)
			return
		}
		if !slices.Contains(p.Collectors, ast.RegistrationCollector) {
			p.Collectors = append(p.Collectors, ast.RegistrationCollector)
		}
		p.Interval = 60
		p.Budget = 20
		p.Paused = p.OwnPaused
		if scheduler.Validate(p) != nil {
			http.Error(w, "Existing profile has no capacity for registration snapshots", 409)
			return
		}
		h := collection.HistoryScope{CustomerID: v.CustomerID, EnvironmentID: v.EnvironmentID, AssetID: v.ID}
		if e = authority.SetIntegration(r.Context(), operatorPrincipal(), h, rec.Target(), "asterisk", true); e != nil {
			s.inventoryFailure(w, d, e)
			return
		}
		run, e := s.options.Discovery.Collect(collection.WithRequest(r.Context(), collection.Request{Source: "operator", Collectors: []string{"asterisk.identity", ast.RegistrationCollector}}), operatorPrincipal(), rec.Target())
		if e != nil {
			http.Error(w, "Authorized snapshot could not run; review collection history. Previous evidence is retained.", 409)
			return
		}
		if run.SuccessCount == 0 {
			http.Error(w, fmt.Sprintf("CLI snapshot %s; inspect Asterisk evidence and collection history for permission, socket or capability diagnostics. Prior evidence is retained.", run.State), 409)
			return
		}
		if _, e = s.options.Scheduler.Save(r.Context(), operatorPrincipal(), p); e != nil {
			http.Error(w, "Snapshot retained; schedule changed or capability unavailable. Reload before retrying.", 409)
			return
		}
		http.Redirect(w, r, "/servers/"+v.ID+"?asterisk=saved", http.StatusSeeOther)
		return
	}
	http.Error(w, "Enrollment does not belong to this server", 404)
}
