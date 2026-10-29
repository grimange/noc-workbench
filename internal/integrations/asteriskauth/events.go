// Package asteriskauth normalizes versioned Asterisk log events. Raw log content
// remains transient; only explicit operational fields cross persistence boundaries.
package asteriskauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const Collector = "asterisk.auth"
const Key = "asterisk.auth.batch"
const Version = "1"
const ChunkSize = 24576

type Cursor struct {
	Identity   string `json:"identity"`
	Offset     int64  `json:"offset"`
	Generation int64  `json:"generation"`
	Anchor     string `json:"anchor"`
	Gap        bool   `json:"gap"`
	Discard    bool   `json:"discard"`
}
type Event struct {
	Position   int64     `json:"position"`
	At         time.Time `json:"at"`
	Type       string    `json:"type"`
	Account    string    `json:"account"`
	IP         string    `json:"ip"`
	Port       int       `json:"port"`
	Technology string    `json:"technology"`
	Severity   string    `json:"severity"`
	Reason     string    `json:"reason"`
}
type Batch struct {
	Source      string    `json:"source"`
	Before      Cursor    `json:"before"`
	After       Cursor    `json:"after"`
	Status      string    `json:"status"`
	Security    bool      `json:"security"`
	Events      []Event   `json:"events"`
	Bytes       int64     `json:"bytes"`
	Rejected    int       `json:"rejected"`
	InspectedAt time.Time `json:"inspected_at"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.+\-]{1,128}$`)
var securityField = regexp.MustCompile(`(?:^|,)([A-Za-z]+)="([^"\r\n]*)"`)
var secTime = regexp.MustCompile(`^([0-9]{10})-([0-9]{1,6})$`)
var logPrefix = regexp.MustCompile(`^\[([^\]]{1,40})\]\s+(?:NOTICE|WARNING|SECURITY|ERROR|DEBUG|VERBOSE|DTMF)\[[0-9]+\](?:\[[^\]]*\])?:?\s+(.*)$`)
var sipFailure = regexp.MustCompile(`^chan_sip\.c:[0-9]+(?: [a-z_]+:)? Registration from '([^'\r\n]*)' failed for '([^'\r\n]{1,128})' - (Wrong password|No matching peer found|Username/auth name mismatch)$`)
var sipAccount = regexp.MustCompile(`<sip[s]?:([A-Za-z0-9_.+\-]{1,128})@`)
var pjsipFailure = regexp.MustCompile(`^res_pjsip/pjsip_distributor\.c:[0-9]+(?: [a-z_]+:)? Request '[A-Z]+' from '[^'\r\n]*' failed for '([^'\r\n]{1,128})' \(callid: [^\r\n]*\) - (Failed to authenticate|No matching endpoint found)$`)

// ParseLine recognizes failures explicitly; ChallengeSent, SuccessfulAuth and
// RequestBadFormat do not establish authentication failure. Unknown fields
// (including hashes) are never copied.
func ParseLine(line string, zone string, now time.Time) (*Event, string) {
	if len(line) > 16384 || !utf8.ValidString(line) {
		return nil, "malformed_line"
	}
	prefix := logPrefix.FindStringSubmatch(line)
	if prefix == nil {
		if strings.TrimSpace(line) == "" {
			return nil, ""
		}
		return nil, "unsupported_format"
	}
	body := prefix[2]
	if i := strings.Index(body, `SecurityEvent="`); i >= 0 && (i == 0 || strings.HasPrefix(body, "res_security_log.c:")) {
		fields := map[string]string{}
		for _, m := range securityField.FindAllStringSubmatch(body[i:], -1) {
			if _, exists := fields[m[1]]; exists {
				return nil, "malformed_line"
			}
			fields[m[1]] = m[2]
		}
		kind := fields["SecurityEvent"]
		switch kind {
		case "ChallengeSent", "SuccessfulAuth", "RequestBadFormat":
			return nil, ""
		case "InvalidPassword", "InvalidAccountID", "ChallengeResponseFailed":
		default:
			return nil, "unsupported_event"
		}
		if fields["EventVersion"] != "1" {
			return nil, "unsupported_event_version"
		}
		at, err := eventTime(fields["EventTV"])
		if err != nil || at.After(now.Add(5*time.Minute)) {
			return nil, "invalid_timestamp"
		}
		e := &Event{At: at, Type: kind, Severity: "authentication_failure", Reason: kind}
		if identifier.MatchString(fields["AccountID"]) && fields["AccountID"] != "unknown" {
			e.Account = fields["AccountID"]
		}
		switch fields["Service"] {
		case "SIP":
			e.Technology = "SIP"
		case "PJSIP":
			e.Technology = "PJSIP"
		}
		parts := strings.Split(fields["RemoteAddress"], "/")
		if len(parts) == 4 && (parts[0] == "IPV4" || parts[0] == "IPV6") {
			e.IP, e.Port = address(parts[2], parts[3])
		}
		return e, ""
	}
	var e Event
	var remote string
	if m := sipFailure.FindStringSubmatch(body); m != nil {
		e.Type = "SIPRegistrationRejected"
		e.Technology = "SIP"
		e.Reason = m[3]
		remote = m[2]
		// The To URI is the requested identity, not proof of an authenticated account.
		if a := sipAccount.FindStringSubmatch(m[1]); a != nil {
			e.Account = a[1]
		}
	} else if m := pjsipFailure.FindStringSubmatch(body); m != nil {
		e.Type = "PJSIPAuthenticationRejected"
		e.Technology = "PJSIP"
		e.Reason = m[2]
		remote = m[1]
		// Do not promote From display/URI into a verified endpoint identity.
	} else {
		return nil, ""
	} // Ordinary Asterisk messages are irrelevant, not failures.
	var err error
	e.At, err = time.Parse("2006-01-02 15:04:05 -0700", prefix[1]+" "+zone)
	if err != nil || e.At.After(now.Add(5*time.Minute)) {
		return nil, "invalid_timestamp"
	}
	e.At = e.At.UTC()
	e.Severity = "authentication_failure"
	if host, port, err := net.SplitHostPort(remote); err == nil {
		e.IP, e.Port = address(host, port)
	} else {
		e.IP, e.Port = address(remote, "")
	}
	return &e, ""
}
func address(host, port string) (string, int) {
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil || ip.Zone() != "" {
		return "", 0
	}
	n, _ := strconv.Atoi(port)
	if n < 0 || n > 65535 {
		n = 0
	}
	return ip.Unmap().String(), n
}
func eventTime(v string) (time.Time, error) {
	if m := secTime.FindStringSubmatch(v); m != nil {
		s, _ := strconv.ParseInt(m[1], 10, 64)
		us, _ := strconv.ParseInt(m[2], 10, 64)
		return time.Unix(s, us*1000).UTC(), nil
	}
	t, e := time.Parse(time.RFC3339Nano, v)
	return t.UTC(), e
}
func Decode(b []byte) (Batch, error) {
	var v Batch
	if len(b) > 128*1024 {
		return v, errors.New("batch_limit")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	e := d.Decode(&v)
	if e == nil {
		var extra any
		if d.Decode(&extra) != io.EOF {
			e = errors.New("trailing_data")
		}
	}
	return v, e
}
