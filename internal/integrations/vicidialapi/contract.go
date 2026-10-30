// Package vicidialapi implements a closed observational Non-Agent API contract.
// It does not own inventory, scheduling, credentials or operational health.
package vicidialapi

import (
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"noc-workbench/internal/collection"
)

const (
	ParserVersion     = "vicidial-api.v2"
	DocumentedVersion = "2.14-210"
	DocumentedBuild   = "260925-1400"
	InstalledVersion  = "2.14-211"
	InstalledBuild    = "261021-1827"
	MaxResponse       = 256 * 1024
	MaxRows           = 1000
)

type Operation string

const (
	Version   Operation = "version"
	Campaigns Operation = "campaigns_list"
	Agents    Operation = "logged_in_agents"
)

// compatibleRevision admits only independently inspected response contracts.
func compatibleRevision(version, build string) bool {
	return version == DocumentedVersion && build == DocumentedBuild || version == InstalledVersion && build == InstalledBuild
}

// ParseForContract adds the inspected revision's successful empty visible-row
// result. This is never a campaign-wide agent count. Callers must verify campaign
// visibility in the same collection attempt before requesting Agents.
func ParseForContract(op Operation, body []byte, campaign, version, build string) ([]collection.Observation, error) {
	if op != Version && !compatibleRevision(version, build) {
		return nil, fail("unsupported_revision")
	}
	observations, err := Parse(op, body, campaign)
	failure, classified := err.(*Failure)
	if op == Agents && version == InstalledVersion && build == InstalledBuild && classified && failure.Code == "insufficient_scope" {
		s := strings.TrimSpace(string(body))
		if regexp.MustCompile(`^ERROR: logged_in_agents NO LOGGED IN AGENTS: [A-Za-z0-9_-]{1,20}\|$`).MatchString(s) {
			return agentReadings(0, 0, 0), nil
		}
	}
	return observations, err
}

// Failure contains only an application-owned classification, never a URL,
// response body, credential, underlying network error or remote identifier.
type Failure struct{ Code string }

func (e *Failure) Error() string { return "VICIdial API: " + e.Code }
func fail(code string) error     { return &Failure{Code: code} }

func supported(op Operation) bool { return op == Version || op == Campaigns || op == Agents }

var campaignID = regexp.MustCompile(`^[A-Za-z0-9_-]{2,8}$`)
var versionLine = regexp.MustCompile(`^VERSION: ([0-9]{1,2}\.[0-9]{1,2}-[0-9]{1,4})\|BUILD: ([0-9]{6}-[0-9]{4})\|DATE: ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})\|EPOCH: ([0-9]{1,12})\|DST: [01]\|TZ: -?[0-9]{1,2}(?:\.[0-9]{1,2})?\|TZNOW: -?[0-9]{1,2}(?:\.[0-9]{1,2})?\|$`)

const campaignHeader = "campaign_id|campaign_name|active|user_group|dial_method|dial_level|lead_order|dial_statuses|dial_timeout|dial_prefix|manual_dial_prefix|three_way_dial_prefix"
const agentHeader = "user|campaign_id|session_id|status|lead_id|callerid|calls_today|full_name|user_group|user_level"

func reading(key string, v collection.Value) collection.Observation {
	unit := "count"
	if v.Kind == "text" {
		unit = "text"
	}
	return collection.Observation{Key: key, Value: v, Unit: unit, Quality: "valid", CollectorVersion: "1", Transport: "https"}
}

// Parse minimizes data immediately. Returned evidence never contains campaign
// names, agent/session identities, caller IDs, lead IDs or raw payloads.
// A campaign response with no viewable campaigns is ambiguous (permissions or
// absence), so it does not manufacture a configured_count of zero.
func Parse(op Operation, body []byte, campaign string) ([]collection.Observation, error) {
	if !supported(op) {
		return nil, fail("unsupported_function")
	}
	if op != Version && !campaignID.MatchString(campaign) {
		return nil, fail("invalid_scope")
	}
	if len(body) == 0 || len(body) > MaxResponse || !utf8.Valid(body) {
		return nil, fail("invalid_response")
	}
	for _, r := range string(body) {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return nil, fail("invalid_response")
		}
	}
	s := strings.TrimSpace(strings.ReplaceAll(string(body), "\r\n", "\n"))
	if strings.Contains(s, "\r") {
		return nil, fail("invalid_response")
	}
	if strings.HasPrefix(s, "ERROR:") {
		// Upstream emits this error after account visibility filtering. It
		// cannot prove that the approved campaign has no agents.
		if op == Agents && strings.HasPrefix(s, "ERROR: logged_in_agents NO LOGGED IN AGENTS: ") && !strings.Contains(s, "\n") {
			return nil, fail("insufficient_scope")
		}
		switch {
		case strings.Contains(s, "DOES NOT HAVE PERMISSION"), strings.Contains(s, "NO VIEWABLE CAMPAIGNS"):
			return nil, fail("permission_denied")
		case strings.Contains(s, "Login incorrect"), strings.Contains(s, "Invalid Username/Password"), strings.Contains(s, "USER NOT FOUND"), strings.Contains(s, "INVALID USER"):
			return nil, fail("authentication_failed")
		case strings.Contains(s, "INVALID FUNCTION"), strings.Contains(s, "Invalid Function"):
			return nil, fail("unsupported_function")
		default:
			return nil, fail("application_error")
		}
	}
	if op == Version {
		m := versionLine.FindStringSubmatch(s)
		if m == nil {
			return nil, fail("invalid_response")
		}
		if _, err := time.Parse("2006-01-02 15:04:05", m[3]); err != nil {
			return nil, fail("invalid_response")
		}
		return []collection.Observation{reading("vicidial.api.version", collection.Text(m[1])), reading("vicidial.api.build", collection.Text(m[2]))}, nil
	}
	lines := strings.Split(s, "\n")
	if len(lines) < 2 || len(lines) > MaxRows+1 {
		return nil, fail("invalid_response")
	}
	if op == Campaigns {
		// One explicitly approved campaign per request, never an unscoped list.
		if lines[0] != campaignHeader || len(lines) != 2 {
			return nil, fail("unsupported_response")
		}
		f := strings.Split(lines[1], "|")
		if len(f) != 12 || f[0] != campaign || (f[2] != "Y" && f[2] != "N") {
			return nil, fail("invalid_response")
		}
		active := uint64(0)
		if f[2] == "Y" {
			active = 1
		}
		return []collection.Observation{reading("vicidial.campaigns.configured_count", collection.Integer(1)), reading("vicidial.campaigns.active_count", collection.Integer(active))}, nil
	}
	if lines[0] != agentHeader {
		return nil, fail("unsupported_response")
	}
	seen := make(map[string]bool, len(lines)-1)
	var total, inCall, paused uint64
	for _, line := range lines[1:] {
		f := strings.Split(line, "|")
		if len(f) != 10 || f[0] == "" || len(f[0]) > 20 || f[1] != campaign || seen[f[0]] {
			return nil, fail("invalid_response")
		}
		seen[f[0]] = true
		switch f[3] {
		case "INCALL":
			inCall++
		case "PAUSED":
			paused++
		case "READY", "QUEUE", "CLOSER", "MQUEUE":
		default:
			return nil, fail("unsupported_status")
		}
		total++
	}
	return agentReadings(total, inCall, paused), nil
}

// Agent counts describe rows visible to this API account, never a proven
// campaign-wide total. Hidden agents cannot be reconstructed from this API.
func agentReadings(total, inCall, paused uint64) []collection.Observation {
	return []collection.Observation{
		reading("vicidial.agents.visible_logged_in_count", collection.Integer(total)),
		reading("vicidial.agents.visible_in_call_count", collection.Integer(inCall)),
		reading("vicidial.agents.visible_paused_count", collection.Integer(paused)),
	}
}
