package vicidialapi

import (
	"context"
	"errors"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/scheduler"
	"noc-workbench/internal/workspace"
)

type principalKey struct{}
type grantKey struct{}

// Service runs approved HTTP observations through the existing shared admission
// and durable history. No method is called by passive page rendering.
type Service struct {
	Repository collection.SourceHistoryRepository
	Admission  *collection.Service
	authority  CatalogAuthority
	client     *Client
}

func NewService(repo collection.SourceHistoryRepository, admission *collection.Service, catalog string) *Service {
	s := &Service{Repository: repo, Admission: admission}
	s.authority = CatalogAuthority{Path: catalog, References: s}
	s.client = NewClient(s)
	return s
}
func (s *Service) AuthorizeAPIReference(ctx context.Context, id string, rev int64) (Reference, error) {
	p, ok := ctx.Value(principalKey{}).(workspace.Principal)
	if !ok {
		return Reference{}, fail("authorization_rejected")
	}
	v, e := s.Repository.CollectionSource(ctx, p, id, rev)
	if e != nil {
		return Reference{}, fail("authorization_rejected")
	}
	return Reference{ID: v.CredentialReference, IntegrationID: v.ID, Revision: v.Revision, Enabled: v.Enabled}, nil
}

// AuthorizeAPI binds every function to one immutable authorization snapshot.
// Catalog rotation or a campaign/destination change requires a new source revision.
func (s *Service) AuthorizeAPI(ctx context.Context, id string, rev int64) (Grant, error) {
	g, e := s.authority.AuthorizeAPI(ctx, id, rev)
	if e != nil {
		return Grant{}, e
	}
	if expected, ok := ctx.Value(grantKey{}).(Grant); ok && g != expected {
		return Grant{}, fail("authorization_changed")
	}
	return g, nil
}
func CollectorIDs() []string {
	return []string{"vicidial.api.version", "vicidial.api.campaigns", "vicidial.api.agents"}
}
func (s *Service) CollectSource(ctx context.Context, p workspace.Principal, profile scheduler.Profile) (collection.Run, error) {
	return s.Collect(ctx, p, profile.CollectionSource.ID, profile.CollectionSource.Revision)
}
func (s *Service) Collect(ctx context.Context, p workspace.Principal, id string, rev int64) (collection.Run, error) {
	if s == nil || s.Repository == nil || s.Admission == nil {
		return collection.Run{}, fail("authorization_rejected")
	}
	ctx = context.WithValue(ctx, principalKey{}, p)
	source, e := s.Repository.CollectionSource(ctx, p, id, rev)
	if e != nil {
		return collection.Run{}, e
	}
	budget := 20 * time.Second
	if requested := collection.Requested(ctx).Budget; requested > 0 && requested < budget {
		budget = requested
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	ctx, release, e := s.Admission.AcquireSource(ctx, source)
	if e != nil {
		return collection.Run{}, e
	}
	defer release()
	// Admission may wait: revalidate authority again before creating the attempt.
	source, e = s.Repository.CollectionSource(ctx, p, id, rev)
	if e != nil {
		return collection.Run{}, e
	}
	grant, e := s.AuthorizeAPI(ctx, id, rev)
	if e != nil {
		return collection.Run{}, e
	}
	if _, e = validGrant(grant, id, rev); e != nil {
		return collection.Run{}, e
	}
	ctx = context.WithValue(ctx, grantKey{}, grant)
	run, e := s.Repository.BeginSourceCollection(ctx, p, source, CollectorIDs())
	if e != nil {
		return run, e
	}
	compatible := false
	campaignVisible := false
	versionTransient := false
	for i, op := range []Operation{Version, Campaigns, Agents} {
		result := collection.Result{CollectorID: CollectorIDs()[i], Version: "1", CommandID: CollectorIDs()[i] + ".v1", StartedAt: time.Now().UTC(), Outcome: "failed", TransportOutcome: "success"}
		var obs []collection.Observation
		var callErr error
		if op == Agents && !campaignVisible {
			callErr = fail("scope_unverified")
			result.TransportOutcome = "not_attempted"
		} else if i > 0 && !compatible {
			callErr = fail("unsupported_revision")
			if versionTransient {
				callErr = fail("dependency_unavailable")
				result.TransportOutcome = "not_attempted"
			}
		} else {
			// Fixed spacing is cancelable and bounded by the entire attempt deadline.
			if i > 0 {
				timer := time.NewTimer(time.Second)
				select {
				case <-ctx.Done():
					callErr = ctx.Err()
				case <-timer.C:
				}
				timer.Stop()
			}
			if callErr == nil {
				obs, callErr = s.client.Collect(ctx, id, rev, op)
			}
		}
		result.EndedAt = time.Now().UTC()
		if callErr != nil {
			code := "api_unavailable"
			var f *Failure
			if errors.As(callErr, &f) {
				code = f.Code
			}
			if errors.Is(callErr, context.Canceled) || ctx.Err() == context.Canceled {
				code = "cancelled"
			}
			if errors.Is(callErr, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
				code = "request_timeout"
			}
			switch code {
			case "transport_failed", "timeout", "request_timeout", "cancelled", "temporarily_unavailable", "http_error", "redirect_rejected":
				result.TransportOutcome = code
			}
			if i == 0 {
				versionTransient = code == "transport_failed" || code == "timeout" || code == "request_timeout" || code == "temporarily_unavailable"
			}
			result.Diagnostics = []collection.Diagnostic{{Code: code}}
		} else {
			if i == 0 {
				actualVersion, actualBuild := "", ""
				for _, o := range obs {
					if o.Key == "vicidial.api.version" {
						actualVersion = o.Value.Text
					}
					if o.Key == "vicidial.api.build" {
						actualBuild = o.Value.Text
					}
				}
				compatible = compatibleRevision(actualVersion, actualBuild) && actualVersion == grant.ContractVersion && actualBuild == grant.ContractBuild
			}
			result.Outcome = "success"
			result.Observations = obs
			result.ObservationCount = len(obs)
			// The catalog is revalidated per function. Transport identity remains safe
			// metadata and never includes endpoint credentials or raw API payloads.
			g, err := s.AuthorizeAPI(ctx, id, rev)
			if err != nil {
				result.Outcome = "failed"
				result.Observations = nil
				result.ObservationCount = 0
				result.Diagnostics = []collection.Diagnostic{{Code: "authorization_rejected"}}
			} else {
				if op == Campaigns {
					campaignVisible = true
				}
				for j := range result.Observations {
					o := &result.Observations[j]
					o.SourceID = id
					o.SourceRevision = rev
					o.SubjectType = "cluster"
					o.CollectorID = result.CollectorID
					o.CollectorVersion = "1"
					o.CommandID = result.CommandID
					o.ObservedAt = result.StartedAt
					o.ReceivedAt = result.EndedAt
					o.Transport = "https"
					if g.Synthetic {
						o.Transport = "http_fixture"
					}
				}
			}
		}
		run.Results = append(run.Results, result)
	}
	run.EndedAt = time.Now().UTC()
	run.Summarize()
	save, done := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer done()
	if e = s.Repository.FinishSourceCollection(save, p, run, 180); e != nil {
		return run, collection.ErrPersistence
	}
	return run, nil
}
