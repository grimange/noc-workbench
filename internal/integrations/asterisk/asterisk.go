// Package asterisk implements optional, bounded Asterisk 18/20 CLI observations.
// It owns parsing only; enrollment, SSH execution and evidence storage are shared.
package asterisk

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"noc-workbench/internal/collection"
)

func Specs() []collection.Spec {
	return []collection.Spec{
		{ID: "asterisk.media", Version: "1", CommandID: "asterisk.media.v1", AlternateCommandIDs: []string{"asterisk.media.helper.v1"}, Parse: MediaCLI, Optional: true},
		{ID: "asterisk.activity", Version: "1", CommandID: "asterisk.activity.v1", AlternateCommandIDs: []string{"asterisk.activity.helper.v1"}, Parse: Activity, Optional: true},
		{ID: RegistrationCollector, Version: "1", CommandID: "asterisk.registrations.v1", AlternateCommandIDs: []string{"asterisk.registrations.helper.v1"}, Parse: Registrations, Optional: true},
		{ID: "asterisk.identity", Version: "1", CommandID: "asterisk.identity.v1", AlternateCommandIDs: []string{"asterisk.identity.helper.v1"}, Parse: Identity, Optional: true},
		{ID: "asterisk.channels", Version: "1", CommandID: "asterisk.channels.v1", Parse: Channels, Optional: true},
		{ID: "asterisk.modules", Version: "1", CommandID: "asterisk.modules.v1", Parse: Modules, Optional: true},
		{ID: "asterisk.pjsip", Version: "1", CommandID: "asterisk.pjsip.v1", Parse: PJSIP, Optional: true},
	}
}
func bad(code string) ([]collection.Observation, []collection.Diagnostic) {
	return nil, []collection.Diagnostic{{Code: code}}
}
func fact(key string, v collection.Value) collection.Observation {
	unit := "count"
	if v.Kind == "text" {
		unit = "text"
	}
	return collection.Observation{Key: key, Value: v, Unit: unit}
}

var version = regexp.MustCompile(`^Asterisk ((?:18|20)\.[0-9]+\.[0-9]+(?:[-+~][A-Za-z0-9.+~_-]{1,64})?)(?:\s|$)`)
var otherVersion = regexp.MustCompile(`^Asterisk [0-9]+\.`)

// frame validates bounded UTF-8 and classifies only unambiguous CLI diagnostics.
// No CLI output, including caller or endpoint identities, enters diagnostics.
func frame(b []byte, data bool) (string, string) {
	if len(b) == 0 || len(b) > 64*1024 || !utf8.Valid(b) {
		return "", "parse_error"
	}
	for _, r := range string(b) {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return "", "parse_error"
		}
	}
	text := strings.TrimSpace(string(b))
	lower := strings.ToLower(text)
	switch {
	case text == "NW_ASTERISK_NOT_INSTALLED":
		return "", "not_installed"
	case strings.Contains(lower, "permission denied"), strings.Contains(lower, "don't have permissions to run"), strings.Contains(lower, "not allowed to run"), strings.Contains(lower, "not permitted to run"):
		return "", "permission_denied"
	case strings.Contains(lower, "unable to connect to remote asterisk"):
		return "", "cli_unavailable"
	case strings.Contains(lower, "no such command"):
		return "", "unsupported_command"
	}
	parts := strings.SplitN(text, "\nNW_ASTERISK_DATA\n", 2)
	m := version.FindStringSubmatch(parts[0])
	if m == nil {
		if otherVersion.MatchString(parts[0]) {
			return "", "unsupported_version"
		}
		return "", "parse_error"
	}
	if !data {
		return m[1], ""
	}
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return "", "parse_error"
	}
	return strings.TrimSpace(parts[1]), ""
}
func Identity(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	v, c := frame(b, false)
	if c != "" {
		return bad(c)
	}
	return []collection.Observation{fact("asterisk.version", collection.Text(v)), fact("asterisk.cli.available", collection.Integer(1))}, nil
}

var channelLine = regexp.MustCompile(`^([0-9]+) active (channels?|calls?)$`)
var processedLine = regexp.MustCompile(`^[0-9]+ calls? processed$`)

func Channels(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	v, c := frame(b, true)
	if c != "" {
		return bad(c)
	}
	seen := false
	var channels uint64
	calls := false
	processed := false
	for _, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		m := channelLine.FindStringSubmatch(line)
		if m != nil {
			n, e := strconv.ParseUint(m[1], 10, 63)
			if e != nil {
				return bad("parse_error")
			}
			if strings.HasPrefix(m[2], "channel") {
				if seen {
					return bad("parse_error")
				}
				seen = true
				channels = n
			} else {
				if calls {
					return bad("parse_error")
				}
				calls = true
			}
			continue
		}
		if processedLine.MatchString(line) && !processed {
			processed = true
			continue
		}
		return bad("parse_error")
	}
	if !seen || !calls || !processed {
		return bad("parse_error")
	}
	// Active channel totals are deliberately not normalized as customer calls.
	return []collection.Observation{fact("asterisk.channels.active", collection.Integer(channels))}, nil
}

var moduleSummary = regexp.MustCompile(`^([0-9]+) modules? loaded$`)

func Modules(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	v, c := frame(b, true)
	if c != "" {
		return bad(c)
	}
	lines := strings.Split(v, "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "Module") {
		return bad("parse_error")
	}
	count := uint64(0)
	pjsip := uint64(0)
	driver := uint64(0)
	seen := map[string]bool{}
	for i, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if m := moduleSummary.FindStringSubmatch(line); m != nil {
			n, e := strconv.ParseUint(m[1], 10, 63)
			if e != nil || n != count || i != len(lines)-2 {
				return bad("parse_error")
			}
			return []collection.Observation{fact("asterisk.modules.pjsip.available", collection.Integer(pjsip)), fact("asterisk.modules.chan_pjsip.available", collection.Integer(driver))}, nil
		}
		f := strings.Fields(line)
		if len(f) < 5 || !strings.HasSuffix(f[0], ".so") || seen[f[0]] {
			return bad("parse_error")
		}
		seen[f[0]] = true
		count++
		if count > 256 {
			return bad("record_limit")
		}
		if f[0] == "res_pjsip.so" {
			pjsip = 1
		}
		if f[0] == "chan_pjsip.so" {
			driver = 1
		}
	}
	return bad("parse_error")
}

var objectSummary = regexp.MustCompile(`^Objects found: ([0-9]+)$`)

func PJSIP(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	v, c := frame(b, true)
	if c != "" {
		return bad(c)
	}
	if v == "No objects found." {
		return []collection.Observation{fact("asterisk.pjsip.registrations.count", collection.Integer(0))}, nil
	}
	lines := strings.Split(v, "\n")
	header := regexp.MustCompile(`^<Registration/ServerURI[^>]*>\s+<Auth[^>]*>\s+<Status[^>]*>$`)
	row := regexp.MustCompile(`^\S+/sip[s]?:\S+\s+\S+\s+(Registered|Unregistered|Rejected|Stopped)(?: \(exp\. [0-9]+s\))?$`)
	if len(lines) < 3 || !header.MatchString(strings.TrimSpace(lines[0])) {
		return bad("parse_error")
	}
	footer := objectSummary.FindStringSubmatch(strings.TrimSpace(lines[len(lines)-1]))
	if footer == nil {
		return bad("parse_error")
	}
	n, err := strconv.ParseUint(footer[1], 10, 63)
	if err != nil || n > 4096 {
		return bad("record_limit")
	}
	var rows uint64
	for _, line := range lines[1 : len(lines)-1] {
		line = strings.TrimSpace(line)
		if line == "" || strings.Trim(line, "=") == "" {
			continue
		}
		if !row.MatchString(line) {
			return bad("parse_error")
		}
		rows++
	}
	if rows != n || n == 0 {
		return bad("parse_error")
	}
	return []collection.Observation{fact("asterisk.pjsip.registrations.count", collection.Integer(n))}, nil
}
