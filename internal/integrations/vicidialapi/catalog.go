package vicidialapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"regexp"
	"syscall"
	"time"
)

// Reference is safe metadata returned by the application's current scoped
// authority. Possession of a catalog entry alone does not authorize execution.
type Reference struct {
	ID, IntegrationID string
	Revision          int64
	Enabled           bool
}

type ReferenceAuthority interface {
	AuthorizeAPIReference(context.Context, string, int64) (Reference, error)
}

// CatalogAuthority reads protected, administrator-provisioned credentials and
// endpoint approvals on every request, after current application authorization.
// The application repository must bind that authorization to its principal,
// customer/environment/cluster, explicit opt-in, revision and stop controls.
// This type never stores passwords in the application database.
type CatalogAuthority struct {
	Path       string
	References ReferenceAuthority
}

type catalogEntry struct {
	ID, IntegrationID, Endpoint, ApprovedIP, Campaign, User, Password string
	Revision                                                          int64
	Enabled, Synthetic                                                bool
	ExpiresAt                                                         time.Time
	LoggingReviewDigest, ContractVersion, ContractBuild               string
}

var referenceID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (a CatalogAuthority) AuthorizeAPI(ctx context.Context, id string, revision int64) (Grant, error) {
	if a.References == nil || ctx.Err() != nil {
		return Grant{}, fail("authorization_rejected")
	}
	r, err := a.References.AuthorizeAPIReference(ctx, id, revision)
	if err != nil || !r.Enabled || r.IntegrationID != id || r.Revision != revision || !referenceID.MatchString(r.ID) {
		return Grant{}, fail("authorization_rejected")
	}
	entries, err := readCatalog(a.Path)
	if err != nil {
		return Grant{}, err
	}
	for _, e := range entries {
		if e.ID != r.ID {
			continue
		}
		if !e.Enabled || e.IntegrationID != id || e.Revision != revision || e.ExpiresAt.IsZero() || !time.Now().Before(e.ExpiresAt) || ctx.Err() != nil {
			return Grant{}, fail("credential_unavailable")
		}
		ip, err := netip.ParseAddr(e.ApprovedIP)
		if err != nil {
			return Grant{}, fail("invalid_configuration")
		}
		g := Grant{IntegrationID: id, Revision: revision, Endpoint: e.Endpoint, Campaign: e.Campaign, Username: e.User, Password: e.Password, ApprovedIP: ip, Enabled: true, Synthetic: e.Synthetic, LoggingReviewDigest: e.LoggingReviewDigest, ContractVersion: e.ContractVersion, ContractBuild: e.ContractBuild}
		if _, err := validGrant(g, id, revision); err != nil {
			return Grant{}, err
		}
		return g, nil
	}
	return Grant{}, fail("credential_unavailable")
}

func readCatalog(path string) ([]catalogEntry, error) {
	// Nonblocking prevents a FIFO from hanging before fstat can reject it.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fail("credential_unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 65536 {
		return nil, fail("credential_unavailable")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || (owner.Uid != uint32(os.Geteuid()) && owner.Uid != 0) {
		return nil, fail("credential_unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 {
		return nil, fail("credential_unavailable")
	}
	var entries []catalogEntry
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&entries) != nil || d.Decode(new(any)) != io.EOF || len(entries) > 32 {
		return nil, fail("credential_unavailable")
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if !referenceID.MatchString(e.ID) || seen[e.ID] || e.IntegrationID == "" || e.Revision < 1 {
			return nil, fail("credential_unavailable")
		}
		seen[e.ID] = true
	}
	return entries, nil
}
