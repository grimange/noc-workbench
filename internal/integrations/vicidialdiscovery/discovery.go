// Package vicidialdiscovery interprets minimized, revision-scoped installation
// evidence. It never contacts peers, changes inventory, or evaluates health.
package vicidialdiscovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"noc-workbench/internal/collection"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const Collector = "vicidial.discovery"
const Key = "vicidial.discovery.snapshot"
const Version = "1"
const Evaluator = "vicidial-discovery.v1"

func Specs() []collection.Spec {
	return []collection.Spec{{ID: Collector, Version: Version, CommandID: Collector + ".v1", Parse: Parse, Optional: true}}
}

// Snapshot contains only normalized facts, never configuration, credentials or
// addresses. The registry is installer configuration, not monitored peer state.
type Snapshot struct {
	ViciBox, Revision, AppVersion                   string
	Config, Web, Dialer, Apache, Asterisk, Database string
	Registry                                        string
	BoundDatabase                                   bool
	LocalRoles                                      []string
	DatabaseMode                                    string
	RegistryServers                                 int
	Peers                                           []string
	Replica                                         string
	PrimaryStreams                                  int
	ArchiveAlias                                    string
}

var release = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$`)
var revision = regexp.MustCompile(`^[0-9]{1,8}$`)
var packageVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9.+_~-]{0,63}$`)
var appVersion = regexp.MustCompile(`^2\.14-[0-9]{1,5}[a-z]?$`)

func oneOf(v string, choices ...string) bool {
	for _, c := range choices {
		if v == c {
			return true
		}
	}
	return false
}
func ip(v string) (netip.Addr, bool) {
	a, e := netip.ParseAddr(v)
	return a, e == nil && a.Is4() && !a.IsUnspecified() && !a.IsMulticast()
}

type registryRow struct {
	address    netip.Addr
	role, mode string
}

// Parse rejects incomplete, conflicting and oversized frames without retaining
// any raw input. Unsupported approved fields remain explicit uncertainty.
func Parse(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	bad := func() ([]collection.Observation, []collection.Diagnostic) {
		return nil, []collection.Diagnostic{{Code: "parse_error"}}
	}
	if len(b) == 0 || len(b) > 8192 || !strings.HasPrefix(string(b), "NW_VICIDIAL_DISCOVERY_1\n") {
		return bad()
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if lines[len(lines)-1] != "END" {
		return bad()
	}
	values := map[string]string{}
	var rows []registryRow
	seen := map[string]bool{}
	for _, line := range lines[1 : len(lines)-1] {
		k, v, ok := strings.Cut(line, "=")
		if !ok || len(v) > 96 {
			return bad()
		}
		if k == "registry_row" {
			parts := strings.Split(v, "|")
			if len(parts) != 3 || len(rows) >= 32 {
				return bad()
			}
			a, ok := ip(parts[0])
			if !ok || !oneOf(parts[1], "Database", "Web", "Telephony", "Archive") {
				return bad()
			}
			if parts[1] == "Database" {
				if !oneOf(parts[2], "Primary", "Replica", "Unknown") {
					return bad()
				}
			} else if parts[2] != "-" {
				return bad()
			}
			key := a.String() + "|" + parts[1]
			if seen[key] {
				return bad()
			}
			seen[key] = true
			rows = append(rows, registryRow{a, parts[1], parts[2]})
			continue
		}
		if _, ok := values[k]; ok {
			return bad()
		}
		switch k {
		case "vbox":
			if v != "unavailable" && !release.MatchString(v) {
				return bad()
			}
		case "svn":
			if v != "unavailable" && !revision.MatchString(v) {
				return bad()
			}
		case "app_version":
			if v != "unavailable" && !appVersion.MatchString(v) {
				return bad()
			}
		case "identity":
			if !oneOf(v, "matched", "unavailable") {
				return bad()
			}
		case "config":
			if !oneOf(v, "present", "missing", "unavailable") {
				return bad()
			}
		case "web", "dialer":
			if !oneOf(v, "present", "matched", "different", "missing", "unavailable") {
				return bad()
			}
		case "apache", "asterisk", "database":
			if !oneOf(v, "missing", "unavailable") && !packageVersion.MatchString(v) {
				return bad()
			}
		case "server_ip", "db_ip":
			if _, ok := ip(v); !ok && v != "unsupported" {
				return bad()
			}
		case "config_port", "observed_port":
			if v != "unsupported" {
				n, e := strconv.Atoi(v)
				if e != nil || n < 1 || n > 65535 {
					return bad()
				}
			}
		case "db_name":
			if !oneOf(v, "asterisk", "unsupported") {
				return bad()
			}
		case "registry":
			if !oneOf(v, "available", "unavailable") {
				return bad()
			}
		case "replica":
			if !oneOf(v, "running", "configured", "none", "unavailable") {
				return bad()
			}
		case "primary_streams":
			if v != "unavailable" {
				n, e := strconv.Atoi(v)
				if e != nil || n < 0 || n > 128 {
					return bad()
				}
			}
		case "archive_alias":
			if !oneOf(v, "configured", "missing", "unavailable") {
				return bad()
			}
		default:
			return bad()
		}
		values[k] = v
	}
	for _, k := range []string{"vbox", "svn", "app_version", "identity", "config", "web", "dialer", "apache", "asterisk", "database", "registry", "replica", "primary_streams", "archive_alias"} {
		if values[k] == "" {
			return bad()
		}
	}
	if values["registry"] != "available" && (len(rows) > 0 || values["observed_port"] != "") {
		return bad()
	}
	if values["config"] != "present" {
		for _, k := range []string{"server_ip", "db_ip", "config_port", "db_name"} {
			if values[k] != "" {
				return bad()
			}
		}
	}
	local, localOK := ip(values["server_ip"])
	db, dbOK := ip(values["db_ip"])
	s := Snapshot{ViciBox: values["vbox"], Revision: values["svn"], AppVersion: values["app_version"], Config: values["config"], Web: values["web"], Dialer: values["dialer"], Apache: values["apache"], Asterisk: values["asterisk"], Database: values["database"], Registry: values["registry"], Replica: values["replica"], PrimaryStreams: -1, ArchiveAlias: values["archive_alias"]}
	s.BoundDatabase = values["identity"] == "matched" && localOK && dbOK && (local == db || db.IsLoopback()) && values["db_name"] == "asterisk" && values["config_port"] != "" && values["config_port"] != "unsupported" && values["observed_port"] == values["config_port"] && s.Registry == "available"
	if values["primary_streams"] != "unavailable" {
		s.PrimaryStreams, _ = strconv.Atoi(values["primary_streams"])
	}
	addresses := map[netip.Addr]bool{}
	for _, row := range rows {
		addresses[row.address] = true
		if s.BoundDatabase && row.address == local {
			s.LocalRoles = append(s.LocalRoles, row.role)
			if row.role == "Database" {
				s.DatabaseMode = row.mode
			}
		}
	}
	if len(addresses) > 8 {
		return bad()
	}
	s.RegistryServers = len(addresses)
	for address := range addresses {
		if !s.BoundDatabase || address != local {
			h := sha256.Sum256([]byte(address.String()))
			s.Peers = append(s.Peers, hex.EncodeToString(h[:]))
		}
	}
	sort.Strings(s.LocalRoles)
	sort.Strings(s.Peers)
	if !validSnapshot(s) {
		return bad()
	}
	encoded, _ := json.Marshal(s)
	return []collection.Observation{{Key: Key, Unit: "text", Value: collection.Text(string(encoded))}}, nil
}

type Classification struct{ ID, State, Reason, Source string }
type Result struct {
	Installation, Deployment                                                                   Classification
	Roles                                                                                      []Classification
	Evaluator, AssetID, EvidenceID, CollectorVersion, Freshness, Revision, ViciBox, AppVersion string
	ObservedAt                                                                                 time.Time
	Peers, Diagnostics                                                                         []string
}

func Unknown() Result {
	r := Result{Evaluator: Evaluator, Installation: Classification{ID: "installation", State: "Unknown", Reason: "No usable authorized discovery evidence"}, Deployment: Classification{ID: "deployment", State: "Unknown", Reason: "Deployment configuration has not been verified"}}
	for _, id := range []string{"Web", "Asterisk / Telephony", "Database Primary", "Database Replica", "Archive"} {
		r.Roles = append(r.Roles, Classification{ID: id, State: "Unknown", Reason: "Role evidence unavailable"})
	}
	return r
}

// Evaluate is pure. The canonical evaluator supplies explicit time, freshness
// and current authority; no classification extends an observation timestamp.
func Evaluate(e collection.Evidence, at time.Time, fresh string, authorized bool) Result {
	r := Unknown()
	r.AssetID = e.AssetID
	r.EvidenceID = e.ID
	r.ObservedAt = e.ObservedAt
	r.CollectorVersion = e.CollectorVersion
	r.Freshness = fresh
	if !authorized || e.Key != Key || e.CollectorID != Collector || e.CollectorVersion != Version || e.Quality != "valid" || e.Value.Kind != "text" || e.ObservedAt.IsZero() || e.ObservedAt.After(at) || e.ReceivedAt.After(at) || e.ReceivedAt.Before(e.ObservedAt) {
		r.Diagnostics = append(r.Diagnostics, "Current SSH authority or evidence envelope unavailable")
		return r
	}
	var s Snapshot
	dec := json.NewDecoder(strings.NewReader(e.Value.Text))
	dec.DisallowUnknownFields()
	if len(e.Value.Text) > 4096 || dec.Decode(&s) != nil || dec.Decode(new(any)) != io.EOF || !validSnapshot(s) {
		r.Diagnostics = append(r.Diagnostics, "Invalid normalized discovery evidence")
		return r
	}
	r.Revision = s.Revision
	r.ViciBox = s.ViciBox
	r.AppVersion = s.AppVersion
	r.Peers = append([]string(nil), s.Peers...)
	supported := s.ViciBox == "12.0.2" && s.Revision == "4034" && s.AppVersion == "2.14-968a"
	conflict := s.Web == "different" || s.Dialer == "different"
	has := func(role string) bool {
		for _, v := range s.LocalRoles {
			if v == role {
				return true
			}
		}
		return false
	}
	r.Installation.Source = "deployed VICIdial application marker; local SVN source context; ViciBox version"
	if s.AppVersion != "unavailable" || s.Web == "matched" || s.Dialer == "matched" {
		r.Installation.State = "Candidate"
		r.Installation.Reason = "VICIdial application identified; revision compatibility or provenance incomplete"
		if supported && !conflict {
			r.Installation.State = "Confirmed"
			r.Installation.Reason = "Supported deployed VICIdial application marker and ViciBox installation metadata; SVN revision is source context"
		}
	} else if oneOf(s.Web, "present", "different") || oneOf(s.Dialer, "present", "different") || s.Config == "present" {
		r.Installation.State = "Candidate"
		r.Installation.Reason = "VICIdial-specific files present; supported provenance incomplete"
	} else if s.Web == "missing" && s.Dialer == "missing" && s.Config == "missing" && s.Revision == "unavailable" && s.ViciBox == "unavailable" {
		r.Installation.State = "Not detected"
		r.Installation.Reason = "All inspected VICIdial sources absent; other layouts remain unverified"
	}
	if !supported {
		r.Diagnostics = append(r.Diagnostics, "Unsupported or unavailable ViciBox/application/source revision; confirmation withheld")
	}
	if conflict {
		r.Diagnostics = append(r.Diagnostics, "Deployed application differs from the inspected source; conflicting provenance prevents confirmation")
	}
	if s.Config == "unavailable" {
		r.Diagnostics = append(r.Diagnostics, "/etc/astguiclient.conf unavailable to the approved SSH account")
	}
	if !s.BoundDatabase {
		r.Diagnostics = append(r.Diagnostics, "Installer role registry could not be bound to the configured local database, port and server identity")
	}
	available := func(v string) bool { return !oneOf(v, "missing", "unavailable") }
	role := func(i int, name string, candidate, component bool) {
		if candidate || has(name) {
			r.Roles[i].State = "Candidate"
			r.Roles[i].Reason = "Installation hint present; role-specific configured deployment remains unverified"
			r.Roles[i].Source = "installed application/component metadata"
		}
		if supported && !conflict && s.BoundDatabase && has(name) && component {
			r.Roles[i].State = "Confirmed"
			r.Roles[i].Reason = "Local configured installer role and corresponding installed component verified"
			r.Roles[i].Source = "bound asterisk.vicibox installer role registry and installed component"
		}
	}
	role(0, "Web", oneOf(s.Web, "present", "matched"), available(s.Apache) && oneOf(s.Web, "present", "matched"))
	role(1, "Telephony", oneOf(s.Dialer, "present", "matched") || available(s.Asterisk), available(s.Asterisk))
	if available(s.Database) {
		r.Diagnostics = append(r.Diagnostics, "Database present; presence alone does not establish Primary or Replica")
	}
	if s.BoundDatabase && has("Database") && oneOf(s.DatabaseMode, "Primary", "Replica") {
		i := 2
		if s.DatabaseMode == "Replica" {
			i = 3
		}
		r.Roles[i] = Classification{ID: r.Roles[i].ID, State: "Candidate", Reason: "Installer database role configured; runtime replication authority remains unverified", Source: "bound asterisk.vicibox database-only role discriminator"}
		topologyConflict := s.DatabaseMode == "Primary" && oneOf(s.Replica, "running", "configured")
		if topologyConflict {
			r.Roles[i].State = "Unknown"
			r.Roles[i].Reason = "Installer primary designation conflicts with configured replication"
			r.Diagnostics = append(r.Diagnostics, "Conflicting database topology evidence")
		} else if supported && !conflict && available(s.Database) && ((i == 2 && s.PrimaryStreams > 0 && s.Replica == "none") || (i == 3 && s.Replica == "running")) {
			r.Roles[i].State = "Confirmed"
			r.Roles[i].Reason = "Installer database role agrees with local read-only replication topology evidence"
			r.Roles[i].Source += "; local replication status"
		}
	}
	role(4, "Archive", s.ArchiveAlias == "configured", s.ArchiveAlias == "configured")
	replicationPeer := s.PrimaryStreams > 0 || oneOf(s.Replica, "running", "configured") || s.DatabaseMode == "Replica"
	if supported && !conflict && s.BoundDatabase && len(s.LocalRoles) > 0 {
		source := "complete bounded asterisk.vicibox installer registry bound to local deployment configuration"
		if s.RegistryServers > 1 && len(s.Peers) > 0 {
			r.Deployment = Classification{ID: "Cluster Member", State: "Confirmed", Reason: "Configured local installer member and distinct deployment peers; peer running state unverified", Source: source}
		} else if s.RegistryServers == 1 && len(s.Peers) == 0 && !replicationPeer && s.DatabaseMode == "Primary" && has("Web") && has("Telephony") && has("Database") {
			r.Deployment = Classification{ID: "Standalone", State: "Confirmed", Reason: "Installer configuration places all core roles on this single registered server; runtime completeness and manual additions remain unverified", Source: source}
		}
	}
	if replicationPeer && s.RegistryServers <= 1 {
		r.Diagnostics = append(r.Diagnostics, "Replication evidence implies additional database participants absent from the installer registry; deployment remains Unknown")
	}
	if fresh != "fresh" {
		r.Diagnostics = append(r.Diagnostics, "Historical installation evidence; freshness is "+fresh+". This does not establish running state")
	}
	r.Diagnostics = append(r.Diagnostics, "Installer configuration does not verify legacy/manual nodes or later operational drift; candidate peers require separate authorization")
	return r
}
func validSnapshot(s Snapshot) bool {
	if !(s.ViciBox == "unavailable" || release.MatchString(s.ViciBox)) || !(s.Revision == "unavailable" || revision.MatchString(s.Revision)) || !(s.AppVersion == "unavailable" || appVersion.MatchString(s.AppVersion)) {
		return false
	}
	if !oneOf(s.Config, "present", "missing", "unavailable") || !oneOf(s.Web, "present", "matched", "different", "missing", "unavailable") || !oneOf(s.Dialer, "present", "matched", "different", "missing", "unavailable") || !oneOf(s.Registry, "available", "unavailable") || !oneOf(s.Replica, "running", "configured", "none", "unavailable") || !oneOf(s.ArchiveAlias, "configured", "missing", "unavailable") {
		return false
	}
	for _, v := range []string{s.Apache, s.Asterisk, s.Database} {
		if !oneOf(v, "missing", "unavailable") && !packageVersion.MatchString(v) {
			return false
		}
	}
	if s.RegistryServers < 0 || s.RegistryServers > 8 || s.PrimaryStreams < -1 || s.PrimaryStreams > 128 || (s.Registry == "unavailable" && (s.RegistryServers != 0 || s.BoundDatabase)) || (s.BoundDatabase && s.Config != "present") || (!s.BoundDatabase && (len(s.LocalRoles) > 0 || s.DatabaseMode != "")) {
		return false
	}
	if len(s.LocalRoles) > 4 {
		return false
	}
	previous := ""
	databaseRole := false
	for _, v := range s.LocalRoles {
		if !oneOf(v, "Archive", "Database", "Telephony", "Web") || v <= previous {
			return false
		}
		previous = v
		if v == "Database" {
			databaseRole = true
		}
	}
	if databaseRole {
		if !oneOf(s.DatabaseMode, "Primary", "Replica", "Unknown") {
			return false
		}
	} else if s.DatabaseMode != "" {
		return false
	}
	n := s.RegistryServers
	if len(s.LocalRoles) > 0 {
		n--
	}
	if len(s.Peers) != n {
		return false
	}
	previous = ""
	for _, p := range s.Peers {
		if len(p) != 64 || p <= previous {
			return false
		}
		if _, e := hex.DecodeString(p); e != nil {
			return false
		}
		previous = p
	}
	return true
}
