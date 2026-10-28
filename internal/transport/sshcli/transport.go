// Package sshcli executes only reviewed commands through isolated OpenSSH.
// It has no HTTP entry point, scheduler, collector or health evaluator.
package sshcli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

type Category string

const (
	InvalidTarget        Category = "invalid_target"
	UnknownKey           Category = "unknown_host_key"
	ChangedKey           Category = "host_key_mismatch"
	AuthenticationFailed Category = "authentication_failed"
	PermissionDenied     Category = "permission_denied"
	DNSFailure           Category = "dns_failure"
	ConnectionRefused    Category = "connection_refused"
	ConnectionTimeout    Category = "connection_timeout"
	ExecutionTimeout     Category = "execution_timeout"
	CommandNotFound      Category = "command_not_found"
	CommandFailed        Category = "command_failed"
	OutputTruncated      Category = "output_truncated"
	Cancelled            Category = "cancelled"
	Unsupported          Category = "unsupported_configuration"
	Internal             Category = "internal_transport_error"
)

type Failure struct{ Category Category }

func (e *Failure) Error() string { return "SSH transport: " + string(e.Category) }
func fail(c Category) error      { return &Failure{c} }

type Target struct {
	AssetID, EndpointID, ProfileID string
	ProfileVersion                 int64
}

// Profile is a reviewed value, never an OpenSSH config file. Address is the
// independently approved resolved IP. Host changes require a new approval.
// No jump routes are supported in this slice.
type Profile struct {
	Target                       Target
	EndpointUpdatedAt            time.Time
	CustomerID, EnvironmentID    string
	Host, Address, User          string
	Port                         uint16
	IdentityFile, IdentitySHA256 string
	HostKey, Fingerprint         string
}

// Approval must recheck enrollment, active asset/endpoint ownership, exact
// profile revision and both permissions on EVERY call, including inspection.
// ProfileUse and ExecutePermission are independent of inventory read access.
const ProfileUse workspace.Permission = "connections.profile.use"
const ExecutePermission workspace.Permission = "connections.execute"

type Approval interface {
	Approve(context.Context, workspace.Principal, Target, workspace.Permission) (Profile, error)
}
type Result struct {
	AssetID, EndpointID, ProfileID, CommandID, ActorID string
	ProfileVersion                                     int64
	StartedAt, EndedAt                                 time.Time
	Duration                                           time.Duration
	ExitCode                                           int
	Stdout, Stderr                                     []byte // transient result only; never automatically logged
	Category                                           Category
}
type command struct {
	text    string
	timeout time.Duration
	limit   int
}

// Registry entries are source-controlled static shell text. No caller can add
// commands or interpolate remote values. Optional sources have explicit framing.
var registry = map[string]command{
	"linux.baseline.v1":     {baselineCommand, 18 * time.Second, 64 * 1024},
	"linux.services.v1":     {runtimeServicesCommand, 12 * time.Second, 4096},
	"vicidial.discovery.v1": {vicidialDiscoveryCommand, 5 * time.Second, 8192},
	"lab.probe.v1":          {"printf 'NOC_WORKBENCH_SSH_LAB_OK\\n'", 5 * time.Second, 64 * 1024},
	"linux.identity.v1":     {"export LC_ALL=C PATH=/usr/bin:/bin; hostname && uname -r && uname -m && { if [ -r /etc/os-release ]; then cat /etc/os-release; else printf 'NW_OS_RELEASE_UNAVAILABLE\\n'; fi; }", 5 * time.Second, 64 * 1024},
	"linux.uptime.v1":       {"export LC_ALL=C PATH=/usr/bin:/bin; if [ ! -e /proc/uptime ]; then printf 'NW_SOURCE_UNSUPPORTED\\n'; elif [ ! -r /proc/uptime ]; then exit 126; else cat /proc/uptime; fi", 5 * time.Second, 64 * 1024},
	"linux.load.v1":         {"export LC_ALL=C PATH=/usr/bin:/bin; if [ ! -e /proc/loadavg ]; then printf 'NW_SOURCE_UNSUPPORTED\\n'; elif [ ! -r /proc/loadavg ]; then exit 126; else cat /proc/loadavg && { printf '\\nCPU_COUNT='; getconf _NPROCESSORS_ONLN || :; }; fi", 5 * time.Second, 64 * 1024},
	"linux.memory.v1":       {"export LC_ALL=C PATH=/usr/bin:/bin; if [ ! -e /proc/meminfo ]; then printf 'NW_SOURCE_UNSUPPORTED\\n'; elif [ ! -r /proc/meminfo ]; then exit 126; else cat /proc/meminfo; fi", 5 * time.Second, 64 * 1024},
	"linux.filesystems.v1":  {"export LC_ALL=C PATH=/usr/bin:/bin; df -Pk", 5 * time.Second, 64 * 1024},
	"asterisk.identity.v1":  {"export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin; if ! command -v asterisk >/dev/null 2>&1; then printf 'NW_ASTERISK_NOT_INSTALLED\\n'; else { asterisk -rx 'core show version' 2>&1 || :; }; fi", 5 * time.Second, 64 * 1024},
	"asterisk.channels.v1":  {"export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin; if ! command -v asterisk >/dev/null 2>&1; then printf 'NW_ASTERISK_NOT_INSTALLED\\n'; else { asterisk -rx 'core show version' 2>&1 || :; } && printf '\\nNW_ASTERISK_DATA\\n' && { asterisk -rx 'core show channels count' 2>&1 || :; }; fi", 5 * time.Second, 64 * 1024},
	"asterisk.modules.v1":   {"export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin; if ! command -v asterisk >/dev/null 2>&1; then printf 'NW_ASTERISK_NOT_INSTALLED\\n'; else { asterisk -rx 'core show version' 2>&1 || :; } && printf '\\nNW_ASTERISK_DATA\\n' && { asterisk -rx 'module show like pjsip' 2>&1 || :; }; fi", 5 * time.Second, 64 * 1024},
	"asterisk.pjsip.v1":     {"export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin; if ! command -v asterisk >/dev/null 2>&1; then printf 'NW_ASTERISK_NOT_INSTALLED\\n'; else { asterisk -rx 'core show version' 2>&1 || :; } && printf '\\nNW_ASTERISK_DATA\\n' && { asterisk -rx 'pjsip show registrations' 2>&1 || :; }; fi", 5 * time.Second, 64 * 1024},
}
var userPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$`)

type Executor struct {
	approval   Approval
	executable string
	global     chan struct{}
	mu         sync.Mutex
	hosts      map[string]*hostGate
	lookup     func(context.Context, string) ([]net.IPAddr, error)
	limits     Limits
}
type hostGate struct {
	token chan struct{}
	refs  int
}

// Limits can reduce the initial budgets. Increasing execution capacity or
// command privileges requires a separately reviewed policy change.
type Limits struct {
	GlobalHosts, PerHost, OutputBytes int
	TotalTimeout, ConnectTimeout      time.Duration
}

func DefaultLimits() Limits                    { return Limits{5, 1, 64 * 1024, 5 * time.Second, 5 * time.Second} }
func New(approval Approval) (*Executor, error) { return NewWithLimits(approval, DefaultLimits()) }
func NewWithLimits(approval Approval, l Limits) (*Executor, error) {
	if approval == nil || l.GlobalHosts < 1 || l.GlobalHosts > 5 || l.PerHost != 1 || l.OutputBytes < 1 || l.OutputBytes > 64*1024 || l.TotalTimeout <= 0 || l.TotalTimeout > 20*time.Second || l.ConnectTimeout < time.Second || l.ConnectTimeout > 5*time.Second {
		return nil, fail(Unsupported)
	}
	return &Executor{approval: approval, executable: "/usr/bin/ssh", global: make(chan struct{}, l.GlobalHosts), hosts: make(map[string]*hostGate), lookup: net.DefaultResolver.LookupIPAddr, limits: l}, nil
}

// Fingerprint parses exactly one bare public host key, with no options,
// comments, certificates or additional material.
func Fingerprint(material string) (string, error) {
	if len(material) > 16384 {
		return "", fail(Unsupported)
	}
	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(material))
	if err != nil || comment != "" || len(options) != 0 || len(rest) != 0 {
		return "", fail(Unsupported)
	}
	if strings.TrimSpace(material) != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) {
		return "", fail(Unsupported)
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return "", fail(Unsupported)
	}
	return ssh.FingerprintSHA256(key), nil
}

// Trust verifies candidate key material against an independently obtained
// fingerprint. It neither scans hosts nor updates any personal known_hosts.
func Trust(material, independentFingerprint string) (string, error) {
	fp, err := Fingerprint(material)
	if err != nil {
		return "", err
	}
	if independentFingerprint == "" {
		return "", fail(UnknownKey)
	}
	if fp != independentFingerprint {
		return "", fail(ChangedKey)
	}
	return fp, nil
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func validProfile(p Profile, t Target) error {
	if p.Target != t || t.ProfileVersion < 1 || p.EndpointUpdatedAt.IsZero() || !inventory.ValidID(t.AssetID) || !inventory.ValidID(t.EndpointID) || !inventory.ValidID(t.ProfileID) || !inventory.ValidID(p.CustomerID) || !inventory.ValidID(p.EnvironmentID) {
		return fail(InvalidTarget)
	}
	if !inventory.ValidEndpointHost(p.Host) || !userPattern.MatchString(p.User) || p.Port == 0 {
		return fail(InvalidTarget)
	}
	ip, err := netip.ParseAddr(p.Address)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return fail(InvalidTarget)
	}
	if !filepath.IsAbs(p.IdentityFile) || strings.ContainsAny(p.IdentityFile, "%\n\r\x00") || len(p.IdentitySHA256) != 64 {
		return fail(Unsupported)
	}
	return nil
}
func (e *Executor) resolve(ctx context.Context, p Profile) error {
	if ip, err := netip.ParseAddr(p.Host); err == nil {
		if ip.Unmap().String() != p.Address {
			return fail(InvalidTarget)
		}
		return nil
	}
	addrs, err := e.lookup(ctx, p.Host)
	if err != nil {
		if ctx.Err() != nil {
			return contextFailure(ctx)
		}
		return fail(DNSFailure)
	}
	if len(addrs) == 0 {
		return fail(DNSFailure)
	}
	for _, ip := range addrs {
		if ip.IP.String() != p.Address {
			return fail(InvalidTarget)
		}
	}
	return nil
}
func (e *Executor) acquire(ctx context.Context, asset string) (func(), error) {
	e.mu.Lock()
	h := e.hosts[asset]
	if h == nil {
		h = &hostGate{token: make(chan struct{}, e.limits.PerHost)}
		e.hosts[asset] = h
	}
	h.refs++
	e.mu.Unlock()
	drop := func() {
		e.mu.Lock()
		h.refs--
		if h.refs == 0 {
			delete(e.hosts, asset)
		}
		e.mu.Unlock()
	}
	select {
	case h.token <- struct{}{}:
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
	select {
	case e.global <- struct{}{}:
	case <-ctx.Done():
		<-h.token
		drop()
		return nil, ctx.Err()
	}
	return func() { <-e.global; <-h.token; drop() }, nil
}

// WithExecutionCheck adds an application-owned authorization check at the
// post-capacity boundary. It supplements, and cannot replace, SSH approval.
type executionCheckKey struct{}

func WithExecutionCheck(ctx context.Context, check func(context.Context) error) context.Context {
	previous, _ := ctx.Value(executionCheckKey{}).(func(context.Context) error)
	return context.WithValue(ctx, executionCheckKey{}, func(c context.Context) error {
		if previous != nil {
			if err := previous(c); err != nil {
				return err
			}
		}
		return check(c)
	})
}

func (e *Executor) Execute(ctx context.Context, actor workspace.Principal, t Target, commandID string) (r Result, err error) {
	r = Result{AssetID: t.AssetID, EndpointID: t.EndpointID, ProfileID: t.ProfileID, ProfileVersion: t.ProfileVersion, ActorID: actor.ID, CommandID: commandID, StartedAt: time.Now().UTC(), ExitCode: -1}
	defer func() {
		r.EndedAt = time.Now().UTC()
		r.Duration = r.EndedAt.Sub(r.StartedAt)
		var f *Failure
		if errors.As(err, &f) {
			r.Category = f.Category
		}
	}()
	if ctx.Err() != nil {
		return r, contextFailure(ctx)
	}
	spec, ok := registry[commandID]
	if !ok {
		r.CommandID = ""
		return r, fail(Unsupported)
	}
	if !inventory.ValidID(actor.ID) {
		return r, fail(PermissionDenied)
	}
	// Capacity waiting is bounded too; approval is refreshed after waiting.
	ctx, cancel := context.WithTimeout(ctx, min(spec.timeout, e.limits.TotalTimeout))
	defer cancel()
	release, er := e.acquire(ctx, t.AssetID)
	if er != nil {
		return r, contextFailure(ctx)
	}
	defer release()
	if check, ok := ctx.Value(executionCheckKey{}).(func(context.Context) error); ok {
		if check(ctx) != nil {
			return r, fail(PermissionDenied)
		}
	}
	p, er := e.approval.Approve(ctx, actor, t, ProfileUse)
	if er != nil {
		if ctx.Err() != nil {
			return r, contextFailure(ctx)
		}
		return r, fail(PermissionDenied)
	}
	q, er := e.approval.Approve(ctx, actor, t, ExecutePermission)
	if er != nil || p != q {
		if ctx.Err() != nil {
			return r, contextFailure(ctx)
		}
		return r, fail(PermissionDenied)
	}
	if er = validProfile(p, t); er != nil {
		return r, er
	}
	if er = e.resolve(ctx, p); er != nil {
		return r, er
	}
	if _, er = Trust(p.HostKey, p.Fingerprint); er != nil {
		return r, er
	}
	// Snapshot the protected credential before starting a child. Replacement or
	// edits cannot silently change the reviewed identity during execution.
	key, er := protectedRead(p.IdentityFile, 1024*1024)
	if er != nil || digest(key) != p.IdentitySHA256 {
		return r, fail(Unsupported)
	}
	dir, er := os.MkdirTemp("", "nw-ssh-")
	if er != nil {
		return r, fail(Internal)
	}
	defer os.RemoveAll(dir)
	identity := filepath.Join(dir, "identity")
	known := filepath.Join(dir, "known_hosts")
	alias := "nw-" + digest([]byte(fmt.Sprintf("%+v", p)))
	if os.WriteFile(identity, key, 0600) != nil || os.WriteFile(known, []byte(alias+" "+strings.TrimSpace(p.HostKey)+"\n"), 0600) != nil {
		return r, fail(Internal)
	}
	args := []string{"-F", "/dev/null", "-T", "-n", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oRequestTTY=no", "-oForwardAgent=no", "-oForwardX11=no", "-oForwardX11Trusted=no", "-oTunnel=no", "-oAddKeysToAgent=no", "-oEnableSSHKeysign=no", "-oEscapeChar=none", "-oClearAllForwardings=yes", "-oExitOnForwardFailure=yes", "-oControlMaster=no", "-oControlPath=none", "-oControlPersist=no", "-oProxyCommand=none", "-oProxyJump=none", "-oPermitLocalCommand=no", "-oLocalCommand=none", "-oKnownHostsCommand=none", "-oCanonicalizeHostname=no", "-oVerifyHostKeyDNS=no", "-oUpdateHostKeys=no", "-oGlobalKnownHostsFile=/dev/null", "-oUserKnownHostsFile=" + known, "-oHostKeyAlias=" + alias, "-oIdentityAgent=none", "-oIdentitiesOnly=yes", "-oPasswordAuthentication=no", "-oKbdInteractiveAuthentication=no", "-oPreferredAuthentications=publickey", "-oConnectionAttempts=1", "-oConnectTimeout=" + strconv.Itoa(int((e.limits.ConnectTimeout+time.Second-1)/time.Second)), "-oServerAliveInterval=2", "-oServerAliveCountMax=1", "-i", identity, "-p", strconv.Itoa(int(p.Port)), "-l", p.User, "--", p.Address, spec.text}
	r.Stdout, r.Stderr, r.ExitCode, err = run(ctx, e.executable, args, min(spec.limit, e.limits.OutputBytes))
	return r, err
}
