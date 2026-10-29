package asteriskauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func securityLine(kind, account, remote string) string {
	return `[2026-10-28 12:00:00] SECURITY[123] res_security_log.c: SecurityEvent="` + kind + `",EventTV="1793188790-123456",Severity="Error",Service="PJSIP",EventVersion="1",AccountID="` + account + `",RemoteAddress="` + remote + `",ReceivedHash="secret-digest",ExpectedResponse="secret-response"`
}
func TestSupportedEvents(t *testing.T) {
	for _, kind := range []string{"InvalidPassword", "InvalidAccountID", "ChallengeResponseFailed"} {
		t.Run(kind, func(t *testing.T) {
			e, code := ParseLine(securityLine(kind, "phone100", "IPV4/UDP/192.0.2.4/5060"), "+0000", testNow)
			if e == nil || code != "" || e.Type != kind || e.Account != "phone100" || e.IP != "192.0.2.4" || e.Port != 5060 {
				t.Fatalf("%+v %s", e, code)
			}
			b, _ := json.Marshal(e)
			if strings.Contains(string(b), "secret") {
				t.Fatal("secret persisted")
			}
		})
	}
	for _, kind := range []string{"ChallengeSent", "SuccessfulAuth", "RequestBadFormat"} {
		if e, code := ParseLine(securityLine(kind, "phone100", "IPV4/UDP/192.0.2.4/5060"), "+0000", testNow); e != nil || code != "" {
			t.Fatal("normal authentication counted")
		}
	}
	e, _ := ParseLine(securityLine("InvalidPassword", "unknown", "IPV6/UDP/2001:db8::1/5061"), "+0000", testNow)
	if e.Account != "" || e.IP != "2001:db8::1" || e.Port != 5061 {
		t.Fatal(e)
	}
	e, _ = ParseLine(securityLine("InvalidPassword", "", "unknown"), "+0000", testNow)
	if e.Account != "" || e.IP != "" || e.Port != 0 {
		t.Fatal(e)
	}
}

func TestAsterisk18MillisecondLogPrefix(t *testing.T) {
	line := strings.Replace(securityLine("InvalidPassword", "phone100", "IPV4/UDP/192.0.2.4/5060"), "12:00:00]", "12:00:00.123]", 1)
	e, code := ParseLine(line, "-0400", testNow)
	if e == nil || code != "" || e.Account != "phone100" || e.At.Unix() != 1793188790 {
		t.Fatalf("%+v %s", e, code)
	}
	line = "[2026-10-28 07:59:59.123] NOTICE[123]: chan_sip.c:27167 handle_request_register: Registration from '<sip:100@example.invalid>' failed for '192.0.2.5:5060' - Wrong password"
	e, code = ParseLine(line, "-0400", testNow)
	if e == nil || code != "" || !e.At.Equal(time.Date(2026, 10, 28, 11, 59, 59, 123000000, time.UTC)) {
		t.Fatalf("%+v %s", e, code)
	}
}
func TestMessageWarnings(t *testing.T) {
	cases := []struct {
		line, kind, account, ip string
		port                    int
	}{
		{"[2026-10-28 12:00:00] NOTICE[123]: chan_sip.c:27167 handle_request_register: Registration from '<sip:100@example.invalid>' failed for '192.0.2.5:5060' - Wrong password", "SIPRegistrationRejected", "100", "192.0.2.5", 5060},
		{"[2026-10-28 12:00:00] WARNING[123] res_pjsip/pjsip_distributor.c:676 log_failed_request: Request 'REGISTER' from '<sip:100@example.invalid>' failed for '[2001:db8::2]:5061' (callid: synthetic) - Failed to authenticate", "PJSIPAuthenticationRejected", "", "2001:db8::2", 5061},
	}
	for _, c := range cases {
		e, code := ParseLine(c.line, "+0000", testNow)
		if e == nil || code != "" || e.Type != c.kind || e.Account != c.account || e.IP != c.ip || e.Port != c.port {
			t.Fatalf("%+v %s", e, code)
		}
	}
	if e, _ := ParseLine("[2026-10-28 12:00:00] NOTICE[1] chan_sip.c:123 Authentication challenge sent", "+0000", testNow); e != nil {
		t.Fatal(e)
	}
	if e, code := ParseLine(strings.Replace(cases[0].line, "2026-10-28", "Oct 28", 1), "+0000", testNow); e != nil || code != "invalid_timestamp" {
		t.Fatal(e, code)
	}
}
func wireData(data string, offset, size int64, skip, gap bool) []byte {
	b, _ := json.Marshal(wire{Status: "read", Source: "security", Identity: "1:2", Generation: 1, Offset: offset, Size: size, Data: base64.StdEncoding.EncodeToString([]byte(data)), Prefix: base64.StdEncoding.EncodeToString(make([]byte, min(offset, 64))), Skip: skip, Gap: gap, Security: true, Timezone: "+0000"})
	return b
}
func TestNormalizationContinuationAndRedaction(t *testing.T) {
	line := securityLine("InvalidPassword", "100", "IPV4/UDP/192.0.2.1/5060") + "\n"
	b, e := Normalize(wireData(line+"partial-secret", 0, int64(len(line)+14), false, false), nil, testNow)
	if e != nil || len(b.Events) != 1 || b.After.Offset != int64(len(line)) || b.Status != "incomplete_line" || !ValidBatch(b) {
		t.Fatalf("%+v %v", b, e)
	}
	encoded, _ := json.Marshal(b)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("raw/partial secret stored")
	}
	obs, _ := ParseBatch(encoded)
	for _, o := range obs {
		if strings.Contains(o.Value.Text, "secret") {
			t.Fatal(o)
		}
	}
	empty, e := Normalize(wireData("", 0, 0, false, false), nil, testNow)
	if e != nil || empty.Status != "current" || len(empty.Events) != 0 {
		t.Fatal(empty, e)
	}
	large := strings.Repeat("x", ChunkSize)
	b, e = Normalize(wireData(large, 0, ChunkSize, false, false), nil, testNow)
	if e != nil || !b.After.Discard || !b.After.Gap || b.After.Offset != ChunkSize {
		t.Fatal(b, e)
	}
	b, e = Normalize(wireData("badline\n", 0, 8, false, false), nil, testNow)
	if e != nil || b.Status != "unsupported_format" {
		t.Fatal(b, e)
	}
	for _, status := range []string{"missing_source", "permission_denied", "no_configured_source", "unsupported_configuration"} {
		raw, _ := json.Marshal(wire{Status: status})
		b, e = Normalize(raw, nil, testNow)
		if e != nil || b.Status != status || !ValidBatch(b) {
			t.Fatal(b, e)
		}
	}
	if _, e = Decode([]byte(`{"raw":"secret"}`)); e == nil {
		t.Fatal("unknown sensitive field accepted")
	}
}

func TestRotatedPartialTailMakesProgress(t *testing.T) {
	raw := wireData("unfinished-secret", 0, 17, false, false)
	var w wire
	json.Unmarshal(raw, &w)
	w.Rotated = true
	raw, _ = json.Marshal(w)
	b, e := Normalize(raw, nil, testNow)
	if e != nil || b.After.Offset != 17 || !b.After.Gap || b.After.Discard || !ValidBatch(b) {
		t.Fatal(b, e)
	}
	encoded, _ := json.Marshal(b)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("partial retained")
	}
}

func TestMixedOrdinaryLevelsAndAuthentication(t *testing.T) {
	line := "[2026-10-28 12:00:00] ERROR[123]: ordinary unrelated diagnostic\n" + securityLine("InvalidPassword", "100", "IPV4/UDP/192.0.2.1/5060") + "\n[2026-10-28 12:00:00] NOTICE[123]: ordinary notice\n"
	b, e := Normalize(wireData(line, 0, int64(len(line)), false, false), nil, testNow)
	if e != nil || b.Status != "current" || len(b.Events) != 1 {
		t.Fatal(b, e)
	}
	b, e = Normalize(wireData("", 0, 0, false, true), nil, testNow)
	if e != nil || b.Status != "current_with_gap" || !b.After.Gap {
		t.Fatal(b, e)
	}
}

func TestUnsupportedYearlessFallbackNeverClaimsEmptyCoverage(t *testing.T) {
	for _, line := range []string{"", "[Oct 28 12:00:00] NOTICE[1]: unrelated message\n"} {
		raw := wireData(line, 0, int64(len(line)), false, false)
		var w wire
		json.Unmarshal(raw, &w)
		w.Source = "messages"
		w.Security = false
		raw, _ = json.Marshal(w)
		b, e := Normalize(raw, nil, testNow)
		if e != nil || b.Status != "unsupported_format" {
			t.Fatal(b, e)
		}
	}
}
