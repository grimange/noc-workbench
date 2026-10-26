package sshcli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"syscall"

	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

// Enrollment is an operator-reviewed, external, mode-0600 file. Its digest
// binds every approved value; it is not a signature or an automatic approval.
// Anyone able to replace this protected file is a trusted local administrator.
// Changing any profile value requires a fresh explicit approval and revision.
type Enrollment struct {
	Profile        Profile
	ApprovedDigest string
	ApprovedBy     string
	Evidence       string
	Enabled        bool
}

func ProfileDigest(p Profile) string { b, _ := json.Marshal(p); return digest(b) }

type Inventory interface {
	Customer(context.Context, string) (inventory.Customer, error)
	Environment(context.Context, string, string) (inventory.Environment, error)
	GetAsset(context.Context, string, string) (inventory.Asset, error)
	GetEndpoint(context.Context, string, string) (inventory.Endpoint, error)
}
type FileApproval struct {
	Path      string
	Inventory Inventory
	Policy    workspace.Policy
}

func ReadEnrollment(path string) (Enrollment, error) {
	var v Enrollment
	b, err := protectedRead(path, 65536)
	if err != nil {
		return v, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return v, fail(Unsupported)
	}
	if !v.Enabled || !inventory.ValidID(v.ApprovedBy) || len(v.Evidence) < 8 || len(v.Evidence) > 1024 || ProfileDigest(v.Profile) != v.ApprovedDigest {
		return v, fail(PermissionDenied)
	}
	return v, nil
}
func (f FileApproval) Approve(ctx context.Context, actor workspace.Principal, t Target, permission workspace.Permission) (Profile, error) {
	if f.Policy == nil || f.Inventory == nil || (permission != ProfileUse && permission != ExecutePermission) {
		return Profile{}, fail(PermissionDenied)
	}
	if lab, ok := f.Policy.(*LabPolicy); ok && lab == nil {
		return Profile{}, fail(PermissionDenied)
	}
	scope, err := f.Policy.Scope(actor, permission)
	if err != nil {
		return Profile{}, fail(PermissionDenied)
	}
	v, err := ReadEnrollment(f.Path)
	if err != nil {
		return Profile{}, err
	}
	p := v.Profile
	switch f.Policy.(type) {
	case LabPolicy, *LabPolicy:
		ip, er := netip.ParseAddr(p.Address)
		if er != nil || !ip.IsLoopback() || p.Host != p.Address {
			return Profile{}, fail(PermissionDenied)
		}
	}
	if validProfile(p, t) != nil || !scope.Allows(p.CustomerID, p.EnvironmentID) {
		return Profile{}, fail(PermissionDenied)
	}
	c, err := f.Inventory.Customer(ctx, p.CustomerID)
	if err != nil || c.Status != "active" || c.ID != p.CustomerID {
		return Profile{}, fail(PermissionDenied)
	}
	env, err := f.Inventory.Environment(ctx, p.CustomerID, p.EnvironmentID)
	if err != nil || env.Status != "active" || env.ID != p.EnvironmentID || env.CustomerID != c.ID {
		return Profile{}, fail(PermissionDenied)
	}
	a, err := f.Inventory.GetAsset(ctx, p.EnvironmentID, t.AssetID)
	if err != nil || a.Lifecycle != "active" || a.ID != t.AssetID || a.EnvironmentID != env.ID {
		return Profile{}, fail(PermissionDenied)
	}
	ep, err := f.Inventory.GetEndpoint(ctx, p.EnvironmentID, t.EndpointID)
	if err != nil || ep.ID != t.EndpointID || ep.AssetID != a.ID || ep.EnvironmentID != env.ID || ep.Protocol != "ssh" || ep.Status != "active" || !ep.UpdatedAt.Equal(p.EndpointUpdatedAt) || ep.Host != p.Host || ep.Port != int(p.Port) {
		return Profile{}, fail(PermissionDenied)
	}
	return p, nil
}

// LabPolicy is opt-in and loopback-only. It is not the web operator policy.
// General connection grants and enrollment UI remain deferred to NW-008.
type LabPolicy struct{}

func (LabPolicy) Scope(actor workspace.Principal, p workspace.Permission) (workspace.Scope, error) {
	if actor.ID != workspace.OperatorID || (p != ProfileUse && p != ExecutePermission) {
		return workspace.Scope{}, workspace.ErrDenied
	}
	return workspace.Scope{All: true}, nil
}

func protectedRead(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fail(Unsupported)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > limit {
		return nil, fail(Unsupported)
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || (owner.Uid != uint32(os.Geteuid()) && owner.Uid != 0) {
		return nil, fail(Unsupported)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, fail(Unsupported)
	}
	return b, nil
}
