// Package connections orchestrates explicit enrollment, never scheduling or health.
package connections

import (
	"context"
	"errors"
	"net/netip"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
	"sync"
	"time"
)

const Manage workspace.Permission = "connections.profile.manage"
const ApproveIdentity workspace.Permission = "connections.identity.approve"
const Verify workspace.Permission = "connections.verify"

var ErrConflict = errors.New("Enrollment changed. Reload and review the current endpoint and profile.")
var ErrCredential = errors.New("Approved credential is unavailable, revoked, changed or expired. Ask the local administrator to provision a reference, then review the profile.")
var ErrState = errors.New("This action is not permitted in the current enrollment state.")
var ErrInput = errors.New("Choose an active SSH endpoint, approved credential reference and a literal pinned IP address.")

// OperatorPolicy grants explicit connection permissions only to the persistent
// local operator. Inventory read access itself never grants these permissions.
type OperatorPolicy struct{}

func (OperatorPolicy) Scope(p workspace.Principal, permission workspace.Permission) (workspace.Scope, error) {
	if p.ID != workspace.OperatorID {
		return workspace.Scope{}, workspace.ErrDenied
	}
	switch permission {
	case Manage, ApproveIdentity, Verify, sshcli.ProfileUse, sshcli.ExecutePermission:
		return workspace.Scope{All: true}, nil
	}
	return workspace.Scope{}, workspace.ErrDenied
}

// Details contains public enrollment metadata only. Credential files stay external.
type Details struct {
	BaselineAuthorized                                                   bool
	StandardMonitoring                                                   bool
	Host, Address, Username, CredentialRef, CredentialDigest             string
	Port                                                                 uint16
	EndpointUpdatedAt                                                    time.Time
	CandidateKey, CandidateFingerprint, ApprovedKey, ApprovedFingerprint string
	ApprovedBy, Evidence, AuthorizedBy                                   string
	AuthorizedAt, ApprovedAt, InspectedAt, VerifiedAt, AttemptedAt       *time.Time
	LastCategory                                                         string
}

func (d Details) KeyAlgorithm() string {
	fields := strings.Fields(d.CandidateKey)
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

type Record struct {
	ID, CustomerID, EnvironmentID, AssetID, EndpointID, State string
	Revision                                                  int64
	Details                                                   Details
}

func (r Record) Target() sshcli.Target {
	return sshcli.Target{AssetID: r.AssetID, EndpointID: r.EndpointID, ProfileID: r.ID, ProfileVersion: r.Revision}
}
func (r Record) Profile(c sshcli.Credential) sshcli.Profile {
	return sshcli.Profile{Target: r.Target(), EndpointUpdatedAt: r.Details.EndpointUpdatedAt, CustomerID: r.CustomerID, EnvironmentID: r.EnvironmentID, Host: r.Details.Host, Address: r.Details.Address, Port: r.Details.Port, User: r.Details.Username, IdentityFile: c.IdentityFile, IdentitySHA256: c.IdentitySHA256, HostKey: r.Details.ApprovedKey, Fingerprint: r.Details.ApprovedFingerprint}
}

type Repository interface {
	Enrollment(context.Context, string, string) (Record, error)
	Enrollments(context.Context, string, string) ([]Record, error)
	CreateEnrollment(context.Context, workspace.Principal, Record) (Record, error)
	SaveEnrollment(context.Context, workspace.Principal, Record, int64, string) (Record, error)
}
type Credentials interface {
	List() ([]sshcli.Credential, error)
}
type Catalog string

func (c Catalog) List() ([]sshcli.Credential, error) { return sshcli.ReadCredentials(string(c)) }

type Service struct {
	Repository  Repository
	Inventory   sshcli.Inventory
	Credentials Credentials
	Policy      workspace.Policy
	executor    *sshcli.Executor
	// Failed identity checks remain blocked in process even if the database save fails.
	quarantined sync.Map
}

func New(r Repository, i sshcli.Inventory, c Credentials, p workspace.Policy) (*Service, error) {
	s := &Service{Repository: r, Inventory: i, Credentials: c, Policy: p}
	if g, ok := r.(DurableGuard); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := g.RecoverSSH(ctx); err != nil {
			return nil, err
		}
	}
	e, err := sshcli.New(s)
	s.executor = e
	return s, err
}
func (s *Service) allowed(p workspace.Principal, perm workspace.Permission, r Record) error {
	if s.Policy == nil {
		return workspace.ErrDenied
	}
	scope, err := s.Policy.Scope(p, perm)
	if err != nil || !scope.Allows(r.CustomerID, r.EnvironmentID) {
		return workspace.ErrDenied
	}
	return nil
}
func (s *Service) credential(ref string) (sshcli.Credential, error) {
	if s.Credentials == nil {
		return sshcli.Credential{}, ErrCredential
	}
	all, err := s.Credentials.List()
	if err != nil {
		return sshcli.Credential{}, ErrCredential
	}
	for _, c := range all {
		if c.ID == ref && c.Enabled && (c.ExpiresAt.IsZero() || c.ExpiresAt.After(time.Now())) {
			return c, nil
		}
	}
	return sshcli.Credential{}, ErrCredential
}
func (s *Service) CredentialReferences() []string {
	if s.Credentials == nil {
		return nil
	}
	list, err := s.Credentials.List()
	if err != nil {
		return nil
	}
	var refs []string
	for _, c := range list {
		if c.Enabled && (c.ExpiresAt.IsZero() || c.ExpiresAt.After(time.Now())) {
			refs = append(refs, c.ID)
		}
	}
	return refs
}
func (s *Service) live(ctx context.Context, r Record) (sshcli.Credential, error) {
	c, err := s.credential(r.Details.CredentialRef)
	if err != nil || sshcli.CredentialDigest(c) != r.Details.CredentialDigest {
		return c, ErrCredential
	}
	if err = sshcli.ValidateInventoryProfile(ctx, s.Inventory, r.Profile(c), r.Target()); err != nil {
		return c, ErrConflict
	}
	return c, nil
}
func (s *Service) List(ctx context.Context, p workspace.Principal, customer, env, asset string) ([]Record, error) {
	if !inventory.ValidID(customer) || !inventory.ValidID(env) || !inventory.ValidID(asset) {
		return nil, ErrInput
	}
	if err := s.allowed(p, Manage, Record{CustomerID: customer, EnvironmentID: env}); err != nil {
		return nil, err
	}
	list, err := s.Repository.Enrollments(ctx, env, asset)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if _, blocked := s.quarantined.Load(list[i].ID); blocked && list[i].State != "disabled" && list[i].State != "rejected" {
			list[i].State = "identity_changed"
		}
		if list[i].CustomerID != customer {
			return nil, workspace.ErrDenied
		}
		if _, e := s.live(ctx, list[i]); e != nil && list[i].State != "disabled" && list[i].State != "rejected" {
			if errors.Is(e, ErrCredential) {
				list[i].State = "credential_expired"
			} else {
				list[i].State = "identity_changed"
			}
		}
	}
	return list, nil
}
func (s *Service) Create(ctx context.Context, p workspace.Principal, customer, env, asset, endpoint, address, ref string) (Record, error) {
	r := Record{CustomerID: customer, EnvironmentID: env, AssetID: asset, EndpointID: endpoint, State: "draft", Revision: 1}
	if err := s.allowed(p, Manage, r); err != nil {
		return r, err
	}
	if !inventory.ValidID(customer) || !inventory.ValidID(env) || !inventory.ValidID(asset) || !inventory.ValidID(endpoint) {
		return r, ErrInput
	}
	c, err := s.credential(ref)
	if err != nil {
		return r, err
	}
	ep, err := s.Inventory.GetEndpoint(ctx, env, endpoint)
	if err != nil || ep.AssetID != asset {
		return r, ErrInput
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return r, ErrInput
	}
	if host, e := netip.ParseAddr(ep.Host); e == nil && host.Unmap() != ip.Unmap() {
		return r, ErrInput
	}
	r.Details = Details{Host: ep.Host, Port: uint16(ep.Port), Address: ip.Unmap().String(), Username: c.User, CredentialRef: ref, CredentialDigest: sshcli.CredentialDigest(c), EndpointUpdatedAt: ep.UpdatedAt}
	// Reuse the live NW-007 ownership check before persistence, with a temporary valid ID.
	test := r
	test.ID = workspace.OperatorID
	if _, err = s.live(ctx, test); err != nil {
		return r, err
	}
	return s.Repository.CreateEnrollment(ctx, p, r)
}
func (s *Service) Approve(ctx context.Context, p workspace.Principal, t sshcli.Target, permission workspace.Permission) (sshcli.Profile, error) {
	if permission != sshcli.ProfileUse && permission != sshcli.ExecutePermission {
		return sshcli.Profile{}, workspace.ErrDenied
	}
	r, err := s.Repository.Enrollment(ctx, t.EndpointID, t.ProfileID)
	if err != nil {
		return sshcli.Profile{}, workspace.ErrDenied
	}
	if _, blocked := s.quarantined.Load(t.ProfileID); blocked {
		return sshcli.Profile{}, ErrState
	}
	if s.guardAllowed(ctx, t) != nil {
		return sshcli.Profile{}, ErrState
	}
	if r.Target() != t || s.allowed(p, permission, r) != nil {
		return sshcli.Profile{}, workspace.ErrDenied
	}
	if r.State != "pending_host_key_verification" && r.State != "connection_verified" {
		return sshcli.Profile{}, ErrState
	}
	if permission == sshcli.ExecutePermission && (r.Details.ApprovedKey == "" || r.Details.ApprovedFingerprint == "") {
		return sshcli.Profile{}, ErrState
	}
	c, err := s.live(ctx, r)
	if err != nil {
		return sshcli.Profile{}, err
	}
	return r.Profile(c), nil
}

// Act requires a posted optimistic revision. Network calls occur only in the
// explicit inspect/verify actions, after persisted authorization is rechecked.
func (s *Service) Act(ctx context.Context, p workspace.Principal, endpoint, id string, revision int64, action, fingerprint, evidence string) (out Record, retErr error) {
	r, err := s.Repository.Enrollment(ctx, endpoint, id)
	if err != nil {
		return r, err
	}
	perm := Manage
	if action == "approve" {
		perm = ApproveIdentity
	}
	if action == "verify" {
		perm = Verify
	}
	if err = s.allowed(p, perm, r); err != nil {
		return r, err
	}
	if r.Revision != revision {
		return r, ErrConflict
	}
	now := time.Now().UTC()
	if action == "disable" || action == "reject" {
		r.State = "disabled"
		if action == "reject" {
			r.State = "rejected"
		}
		clearTrust(&r)
		return s.Repository.SaveEnrollment(ctx, p, r, revision, action)
	}
	if action == "review" {
		ep, e := s.Inventory.GetEndpoint(ctx, r.EnvironmentID, r.EndpointID)
		if e != nil {
			return r, ErrInput
		}
		c, e := s.credential(r.Details.CredentialRef)
		if e != nil {
			return r, e
		}
		// Explicitly review new endpoint values; a changed literal address must match
		// the old pinned address or be replaced by creating a new reviewed profile.
		r.Details.Host = ep.Host
		r.Details.Port = uint16(ep.Port)
		r.Details.EndpointUpdatedAt = ep.UpdatedAt
		r.Details.Username = c.User
		r.Details.CredentialDigest = sshcli.CredentialDigest(c)
		r.State = "pending_authorization"
		clearTrust(&r)
		r.Details.CandidateKey = ""
		r.Details.CandidateFingerprint = ""
		r.Details.InspectedAt = nil
		r.Details.AuthorizedBy = ""
		r.Details.AuthorizedAt = nil
		if _, e = s.live(ctx, r); e != nil {
			return r, e
		}
		saved, err := s.Repository.SaveEnrollment(ctx, p, r, revision, action)
		if err == nil {
			if e := s.endSSH(ctx, r.ID, ""); e != nil {
				return saved, e
			}
			s.quarantined.Delete(r.ID)
		}
		return saved, err
	}
	if _, err = s.live(ctx, r); err != nil {
		return r, err
	}
	token := ""
	retainGuard := false
	defer func() {
		if token != "" && !retainGuard {
			if e := s.endSSH(ctx, r.ID, token); e != nil {
				retErr = e
			}
		}
	}()
	switch action {
	case "baseline":
		if r.State != "connection_verified" || evidence != "baseline" {
			return r, ErrState
		}
		r.Details.BaselineAuthorized = true
	case "submit":
		if r.State != "draft" {
			return r, ErrState
		}
		r.State = "pending_authorization"
	case "authorize":
		if r.State != "pending_authorization" || (evidence != "authorized" && evidence != "baseline" && evidence != "standard") {
			return r, ErrState
		}
		r.State = "pending_host_key_verification"
		r.Details.BaselineAuthorized = evidence == "baseline" || evidence == "standard"
		r.Details.StandardMonitoring = evidence == "standard"
		r.Details.AuthorizedBy = p.ID
		r.Details.AuthorizedAt = &now
	case "inspect":
		ctx, token, err = s.beginSSH(ctx, p, r.Target())
		if err != nil {
			return r, err
		}
		candidates, e := s.executor.Inspect(ctx, p, r.Target())
		if e != nil {
			r.Details.AttemptedAt = &now
			r.Details.LastCategory = string(sshcli.Internal)
			var failure *sshcli.Failure
			if errors.As(e, &failure) {
				r.Details.LastCategory = string(failure.Category)
			}
			// Persist the bounded category and actor even when inspection fails.
			// The common live check and optimistic save still reject stale results.
			break
		}
		// Prefer the existing approved algorithm when available; never replace trust.
		candidate := candidates[0]
		preferred := "ssh-ed25519 "
		if fields := strings.Fields(r.Details.ApprovedKey); len(fields) > 0 {
			preferred = fields[0] + " "
		}
		for _, v := range candidates {
			if strings.HasPrefix(v.Key, preferred) {
				candidate = v
				break
			}
		}
		r.Details.CandidateKey = candidate.Key
		r.Details.CandidateFingerprint = candidate.Fingerprint
		r.Details.InspectedAt = &now
		if r.Details.ApprovedFingerprint != "" && r.Details.ApprovedFingerprint != candidate.Fingerprint {
			s.quarantined.Store(r.ID, true)
			retainGuard = true
			clearTrust(&r)
			r.State = "identity_changed"
			r.Details.LastCategory = string(sshcli.ChangedKey)
		}
	case "approve":
		if r.State != "pending_host_key_verification" || r.Details.CandidateKey == "" || len(strings.TrimSpace(evidence)) < 8 || len(evidence) > 1024 || strings.ContainsRune(evidence, 0) {
			return r, ErrState
		}
		fp, e := sshcli.Trust(r.Details.CandidateKey, fingerprint)
		if e != nil {
			return r, e
		}
		r.Details.ApprovedKey = r.Details.CandidateKey
		r.Details.ApprovedFingerprint = fp
		r.Details.ApprovedBy = p.ID
		r.Details.ApprovedAt = &now
		r.Details.Evidence = strings.TrimSpace(evidence)
	case "verify":
		if (r.State != "pending_host_key_verification" && r.State != "connection_verified") || r.Details.ApprovedKey == "" {
			return r, ErrState
		}
		ctx, token, err = s.beginSSH(ctx, p, r.Target())
		if err != nil {
			return r, err
		}
		result, e := s.executor.Execute(ctx, p, r.Target(), "lab.probe.v1")
		r.Details.AttemptedAt = &now
		r.Details.LastCategory = string(result.Category)
		if e == nil && result.ExitCode == 0 && string(result.Stdout) == "NOC_WORKBENCH_SSH_LAB_OK\n" {
			r.State = "connection_verified"
			r.Details.VerifiedAt = &now
			r.Details.LastCategory = "success"
		} else {
			r.State = "pending_host_key_verification"
			r.Details.VerifiedAt = nil
			var failure *sshcli.Failure
			if errors.As(e, &failure) {
				r.Details.LastCategory = string(failure.Category)
			} else {
				r.Details.LastCategory = string(sshcli.Internal)
			}
			if r.Details.LastCategory == string(sshcli.ChangedKey) || r.Details.LastCategory == string(sshcli.UnknownKey) {
				s.quarantined.Store(r.ID, true)
				retainGuard = true
				clearTrust(&r)
				r.State = "identity_changed"
			}
		}
	default:
		return r, ErrState
	}
	if _, err = s.live(ctx, r); err != nil {
		return r, err
	}
	saved, err := s.Repository.SaveEnrollment(ctx, p, r, revision, action)
	if err == nil {
		retainGuard = false
	}
	return saved, err
}
func clearTrust(r *Record) {
	r.Details.BaselineAuthorized = false
	r.Details.StandardMonitoring = false
	r.Details.ApprovedKey = ""
	r.Details.ApprovedFingerprint = ""
	r.Details.ApprovedBy = ""
	r.Details.ApprovedAt = nil
	r.Details.Evidence = ""
	r.Details.VerifiedAt = nil
}

// CurrentCredentials checks a bounded, already inventory-validated read snapshot
// against the live catalog and in-process quarantine. It performs no remote IO.
// It grants no execution authority; callers must independently validate endpoint
// ownership/revision and use the usual execution path for any collection.
func (s *Service) CurrentCredentials(p workspace.Principal, records []Record, at time.Time) map[string]bool {
	out := map[string]bool{}
	if len(records) > 2500 || s.Credentials == nil {
		return out
	}
	credentials, e := s.Credentials.List()
	if e != nil {
		return out
	}
	byRef := map[string]sshcli.Credential{}
	for _, c := range credentials {
		if c.Enabled && (c.ExpiresAt.IsZero() || at.Before(c.ExpiresAt)) {
			byRef[c.ID] = c
		}
	}
	for _, r := range records {
		if s.allowed(p, Manage, r) != nil || r.State != "connection_verified" {
			continue
		}
		if _, blocked := s.quarantined.Load(r.ID); blocked {
			continue
		}
		c, ok := byRef[r.Details.CredentialRef]
		if ok && sshcli.CredentialDigest(c) == r.Details.CredentialDigest {
			out[r.ID] = true
		}
	}
	return out
}
