package asterisk

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"noc-workbench/internal/collection"
)

const RegistrationCollector = "asterisk.registrations"
const RegistrationKey = "asterisk.registration.snapshot"

// Sources are fixed CLI families, not names accepted from an HTTP request.
var RegistrationSources = []string{"sip_peers", "sip_registry", "pjsip_endpoints", "pjsip_contacts", "pjsip_registrations"}
var RegistrationCommands = []string{"sip show peers", "sip show registry", "pjsip show endpoints", "pjsip show contacts", "pjsip show registrations"}

// RegistrationRow deliberately excludes authentication objects, caller IDs,
// command-line arguments and URI parameters. Presence and reachability are
// independent. A PJSIP CLI contact does not establish dynamic registration.
type RegistrationRow struct {
	ID           string   `json:"id"`
	Technology   string   `json:"technology"`
	Endpoint     string   `json:"endpoint,omitempty"`
	AOR          string   `json:"aor,omitempty"`
	Address      string   `json:"address,omitempty"`
	Registration string   `json:"registration"`
	Reachability string   `json:"reachability"`
	RTT          *float64 `json:"rtt_ms,omitempty"`
}
type RegistrationSnapshot struct {
	Version string            `json:"version"`
	Status  string            `json:"status"`
	Count   int               `json:"count"`
	Pages   int               `json:"pages"`
	Rows    []RegistrationRow `json:"rows,omitempty"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.@+~!%:-]{1,128}$`)
var sipFooter = regexp.MustCompile(`^([0-9]+) sip peers \[.*\]$`)
var registryFooter = regexp.MustCompile(`^([0-9]+) SIP registrations\.$`)
var rttPattern = regexp.MustCompile(`^OK \(([0-9]+(?:\.[0-9]+)?) ms\)$`)
var sipStatus = regexp.MustCompile(`\s([0-9]{1,5})\s+(OK \([0-9]+(?:\.[0-9]+)? ms\)|UNREACHABLE|UNKNOWN|Unmonitored|LAGGED \([0-9]+(?:\.[0-9]+)? ms\))(?:\s|$)`)
var numberPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?$`)

func safeIdentity(s string) (string, error) {
	if !identifier.MatchString(s) {
		return "", errors.New("identity")
	}
	return s, nil
}

// A display address retains only a host/contact locator. Userinfo passwords,
// URI parameters, headers and query strings are never persisted.
func safeAddress(s string) (string, error) {
	s = strings.Trim(s, "<>")
	s = strings.SplitN(strings.SplitN(strings.SplitN(s, ";", 2)[0], "?", 2)[0], "&", 2)[0]
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "sips:"), "sip:")
	if s == "" || len(s) > 255 {
		return "", errors.New("address")
	}
	for _, r := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:[]", r) {
			return "", errors.New("address")
		}
	}
	return s, nil
}

// Registrations uses a bounded, delimiter-framed bundle. Failed families emit
// diagnostics without replacing their previous successful snapshot. Successful
// manifests and pages share a run ID; removed rows cannot survive a new manifest.
func Registrations(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	if len(b) == 0 || len(b) > 65536 || !utf8.Valid(b) {
		return bad("parse_error")
	}
	for _, r := range string(b) {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return bad("parse_error")
		}
	}
	parts := strings.Split(string(b), "\nNW_REGISTRATIONS_")
	v, code := frame([]byte(parts[0]), false)
	if code != "" {
		return bad(code)
	}
	if len(parts) != 7 || strings.TrimSpace(parts[6]) != "END" {
		return bad("parse_error")
	}
	var obs []collection.Observation
	var diagnostics []collection.Diagnostic
	for i, source := range RegistrationSources {
		prefix := source + "\n"
		if !strings.HasPrefix(parts[i+1], prefix) {
			return bad("parse_error")
		}
		payload := strings.TrimSpace(strings.TrimPrefix(parts[i+1], prefix))
		data, c := frame([]byte(parts[0]+"\nNW_ASTERISK_DATA\n"+payload), true)
		snap := RegistrationSnapshot{Version: v, Status: "supported"}
		var rows []RegistrationRow
		if c == "unsupported_command" {
			snap.Status = "unsupported"
		} else if c != "" {
			diagnostics = append(diagnostics, collection.Diagnostic{Code: source + "_" + c})
			continue
		} else {
			var err error
			rows, err = parseRegistrationFamily(source, data)
			if err != nil {
				diagnostics = append(diagnostics, collection.Diagnostic{Code: source + "_parse_error"})
				continue
			}
		}
		snap.Count = len(rows)
		var pages [][]RegistrationRow
		for _, row := range rows {
			if len(pages) == 0 {
				pages = append(pages, nil)
			}
			n := len(pages) - 1
			trial := append(append([]RegistrationRow(nil), pages[n]...), row)
			encoded, err := json.Marshal(trial)
			if err != nil {
				return bad("parse_error")
			}
			if len(encoded) > 3900 {
				single, err := json.Marshal([]RegistrationRow{row})
				if err != nil || len(single) > 3900 {
					return bad("parse_error")
				}
				pages = append(pages, []RegistrationRow{row})
			} else {
				pages[n] = trial
			}
		}
		snap.Pages = len(pages)
		encoded, err := json.Marshal(snap)
		if err != nil {
			return bad("parse_error")
		}
		obs = append(obs, collection.Observation{Key: RegistrationKey, Resource: source, Unit: "text", Value: collection.Text(string(encoded))})
		for p, rows := range pages {
			encoded, err = json.Marshal(rows)
			if err != nil {
				return bad("parse_error")
			}
			obs = append(obs, collection.Observation{Key: RegistrationKey, Resource: fmt.Sprintf("%s/%03d", source, p+1), Unit: "text", Value: collection.Text(string(encoded))})
		}
	}
	return obs, diagnostics
}

func parseRegistrationFamily(source, data string) ([]RegistrationRow, error) {
	if data == "No objects found." && strings.HasPrefix(source, "pjsip_") {
		return []RegistrationRow{}, nil
	}
	lines := strings.Split(data, "\n")
	var rows []RegistrationRow
	seen := map[string]bool{}
	add := func(row RegistrationRow) error {
		if len(rows) >= 256 || seen[row.ID] {
			return errors.New("record limit or duplicate")
		}
		seen[row.ID] = true
		rows = append(rows, row)
		return nil
	}
	fail := func() ([]RegistrationRow, error) { return nil, errors.New("malformed registration output") }
	header := false
	footer := -1
	endpoint := ""
	aor := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Trim(line, "=- ") == "" {
			continue
		}
		f := strings.Fields(line)
		if footer >= 0 {
			return fail()
		}
		if m := objectSummary.FindStringSubmatch(line); m != nil {
			if !strings.HasPrefix(source, "pjsip_") {
				return fail()
			}
			footer, _ = strconv.Atoi(m[1])
			continue
		}
		if m := sipFooter.FindStringSubmatch(line); m != nil {
			if source != "sip_peers" {
				return fail()
			}
			footer, _ = strconv.Atoi(m[1])
			continue
		}
		if m := registryFooter.FindStringSubmatch(line); m != nil {
			if source != "sip_registry" {
				return fail()
			}
			footer, _ = strconv.Atoi(m[1])
			continue
		}
		if footer >= 0 {
			return fail()
		}
		switch source {
		case "sip_peers":
			if strings.HasPrefix(line, "Name/username") && strings.Contains(line, "Status") {
				header = true
				continue
			}
			if !header || len(f) < 4 || sipStatus.FindStringSubmatch(line) == nil {
				return fail()
			}
			id, err := safeIdentity(strings.SplitN(f[0], "/", 2)[0])
			if err != nil {
				return fail()
			}
			row := RegistrationRow{ID: id, Endpoint: id, Technology: "SIP", Registration: "Unknown", Reachability: "Unknown"}
			if f[1] != "(Unspecified)" && f[1] != "(none)" {
				row.Address, err = safeAddress(f[1])
				if err != nil {
					return fail()
				}
			}
			dynamic := f[2] == "D"
			if dynamic {
				row.Registration = "Dynamic binding not observed"
				if row.Address != "" {
					row.Registration = "Dynamic binding observed"
				}
			} else {
				row.Registration = "Static peer; registration unknown"
			}
			status := sipStatus.FindStringSubmatch(line)[2]
			if strings.HasPrefix(status, "UNREACHABLE") {
				row.Reachability = "Unreachable"
			} else {
				start := strings.Index(status, "OK (")
				if start >= 0 {
					end := strings.Index(status[start:], ")")
					if end < 0 {
						return fail()
					}
					m := rttPattern.FindStringSubmatch(status[start : start+end+1])
					if m == nil {
						return fail()
					}
					n, _ := strconv.ParseFloat(m[1], 64)
					row.RTT = &n
					row.Reachability = "Reachable"
				}
			}
			if err = add(row); err != nil {
				return fail()
			}
		case "sip_registry":
			if strings.HasPrefix(line, "Host") && strings.Contains(line, "State") {
				header = true
				continue
			}
			if !header || len(f) < 5 {
				return fail()
			}
			host, err := safeAddress(f[0])
			if err != nil {
				return fail()
			}
			// chan_sip columns: Host, dnsmgr, Username, Refresh, State, Reg.Time.
			id, err := safeIdentity(f[2])
			if err != nil {
				return fail()
			}
			state := strings.Join(f[4:], " ")
			state = reportedSIPState(state)
			if state == "" {
				return fail()
			}
			if err = add(RegistrationRow{ID: id + "@" + host, Technology: "SIP", Address: host, Registration: state, Reachability: "Unknown"}); err != nil {
				return fail()
			}
		case "pjsip_endpoints":
			if strings.HasPrefix(line, "Endpoint:") && strings.Contains(line, "<Endpoint/") {
				header = true
				continue
			}
			if !header {
				return fail()
			}
			if strings.Contains(line, "<") && (strings.HasPrefix(line, "Aor: <") || strings.HasPrefix(line, "Contact: <") || strings.HasPrefix(line, "InAuth: <") || strings.HasPrefix(line, "OutAuth: <") || strings.HasPrefix(line, "Transport: <") || strings.HasPrefix(line, "Identify: <") || strings.HasPrefix(line, "Match: <") || strings.HasPrefix(line, "Channel: <") || strings.HasPrefix(line, "Exten: <") || strings.HasPrefix(line, "I/OAuth: <")) {
				continue
			}
			if !header {
				return fail()
			}
			if strings.HasPrefix(line, "Endpoint:") {
				if len(f) < 3 {
					return fail()
				}
				id, err := safeIdentity(strings.SplitN(f[1], "/", 2)[0])
				if err != nil {
					return fail()
				}
				endpoint = id
				aor = ""
				if err = add(RegistrationRow{ID: id, Endpoint: id, Technology: "PJSIP", Registration: "No contact observed", Reachability: "Unknown"}); err != nil {
					return fail()
				}
			} else if strings.HasPrefix(line, "Aor:") {
				if endpoint == "" || len(f) < 2 {
					return fail()
				}
				var err error
				aor, err = safeIdentity(f[1])
				if err != nil {
					return fail()
				}
				if rows[len(rows)-1].AOR == "" {
					rows[len(rows)-1].AOR = aor
				} else {
					rows[len(rows)-1].AOR += ", " + aor
				}
			} else if strings.HasPrefix(line, "Contact:") {
				if endpoint == "" || len(f) != 5 {
					return fail()
				}
				if _, err := parseRegistrationFamily("pjsip_contacts", "Contact: <Aor/ContactUri> <Hash> <Status> <RTT(ms)>\n"+line+"\nObjects found: 1"); err != nil {
					return fail()
				}
				rows[len(rows)-1].Registration = "Contact present; registration unknown"
			} else if strings.HasPrefix(line, "InAuth:") || strings.HasPrefix(line, "OutAuth:") || strings.HasPrefix(line, "Transport:") || strings.HasPrefix(line, "Identify:") || strings.HasPrefix(line, "Match:") || strings.HasPrefix(line, "Channel:") || strings.HasPrefix(line, "Exten:") || strings.HasPrefix(line, "I/OAuth:") {
				continue
			} else {
				return fail()
			}
		case "pjsip_contacts":
			if strings.HasPrefix(line, "Contact:") && strings.Contains(line, "<Aor/") {
				header = true
				continue
			}
			if !header || len(f) != 5 || f[0] != "Contact:" {
				return fail()
			}
			slash := strings.Index(f[1], "/")
			if slash < 1 {
				return fail()
			}
			aor, err := safeIdentity(f[1][:slash])
			if err != nil {
				return fail()
			}
			address, err := safeAddress(f[1][slash+1:])
			if err != nil {
				return fail()
			}
			hash, err := safeIdentity(f[2])
			if err != nil {
				return fail()
			}
			row := RegistrationRow{ID: aor + "/" + hash, AOR: aor, Technology: "PJSIP", Address: address, Registration: "Contact present; registration unknown", Reachability: "Unknown"}
			switch f[3] {
			case "Avail":
				row.Reachability = "Reachable"
			case "Unavail":
				row.Reachability = "Unreachable"
			case "Unknown", "NonQual":
			default:
				return fail()
			}
			if numberPattern.MatchString(f[4]) {
				n, _ := strconv.ParseFloat(f[4], 64)
				if row.Reachability == "Reachable" {
					row.RTT = &n
				}
			} else if strings.ToLower(f[4]) != "nan" {
				return fail()
			}
			if err = add(row); err != nil {
				return fail()
			}
		case "pjsip_registrations":
			if strings.HasPrefix(line, "<Registration/ServerURI") && strings.Contains(line, "<Status") {
				header = true
				continue
			}
			if !header || len(f) < 3 {
				return fail()
			}
			slash := strings.Index(f[0], "/")
			if slash < 1 {
				return fail()
			}
			id, err := safeIdentity(f[0][:slash])
			if err != nil {
				return fail()
			}
			addr, err := safeAddress(f[0][slash+1:])
			if err != nil {
				return fail()
			}
			state := f[2]
			switch state {
			case "Registered", "Unregistered", "Rejected", "Stopped":
			default:
				return fail()
			}
			if err = add(RegistrationRow{ID: id, Technology: "PJSIP", Address: addr, Registration: state, Reachability: "Unknown"}); err != nil {
				return fail()
			}
		default:
			return fail()
		}
	}
	if !header || footer != len(rows) {
		return fail()
	}
	return rows, nil
}
func reportedSIPState(s string) string {
	for _, v := range []string{"Registered", "Unregistered", "Rejected", "Request Sent", "Auth. Sent", "Timeout", "No Authentication", "Failed"} {
		if s == v || strings.HasPrefix(s, v+" ") {
			return v
		}
	}
	return ""
}

// DecodeRegistration joins only pages from the manifest's immutable run. A newer
// empty snapshot therefore cannot display contacts left over from an old run.
func DecodeRegistration(manifest collection.Evidence, evidence []collection.Evidence) (RegistrationSnapshot, error) {
	var s RegistrationSnapshot
	if manifest.Key != RegistrationKey || manifest.Value.Kind != "text" || json.Unmarshal([]byte(manifest.Value.Text), &s) != nil || s.Pages < 0 || s.Pages > 256 || s.Count < 0 || s.Count > 256 || (s.Status != "supported" && s.Status != "unsupported") {
		return s, errors.New("invalid manifest")
	}
	for i := 1; i <= s.Pages; i++ {
		found := false
		for _, e := range evidence {
			if e.Key == RegistrationKey && e.RunID == manifest.RunID && e.Resource == fmt.Sprintf("%s/%03d", manifest.Resource, i) {
				var rows []RegistrationRow
				if json.Unmarshal([]byte(e.Value.Text), &rows) != nil {
					return s, errors.New("invalid page")
				}
				s.Rows = append(s.Rows, rows...)
				found = true
				break
			}
		}
		if !found {
			return s, errors.New("missing page")
		}
	}
	if len(s.Rows) != s.Count {
		return s, errors.New("incomplete snapshot")
	}
	return s, nil
}
