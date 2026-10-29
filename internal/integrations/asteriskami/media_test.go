package asteriskami

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func mediaFixture() Frame {
	return Frame{"event": {"RTCPReceived"}, "uniqueid": {"1710000000.1"}, "linkedid": {"1710000000.0"}, "ssrc": {"0x12345678"}, "pt": {"200(SR)"}, "reportcount": {"2"}, "sentpackets": {"45"}, "rtt": {"0.125"}, "report0lsr": {"42"}, "report0sourcessrc": {"0xabcdef01"}, "report0fractionlost": {"64"}, "report0cumulativelost": {"7"}, "report0iajitter": {"80"}, "report1sourcessrc": {"0xabcdef02"}, "report1fractionlost": {"0"}, "report1cumulativelost": {"0"}, "report1iajitter": {"0"}}
}

func TestMediaSemantics(t *testing.T) {
	m, ok := ParseMedia(mediaFixture())
	if !ok || m.Incomplete || len(m.Blocks) != 2 {
		t.Fatal(m, ok)
	}
	if *m.RTTMilliseconds != 125 || *m.SenderPackets != 45 || *m.Blocks[0].LossPercent() != 25 || *m.Blocks[0].CumulativeLost != 7 || *m.Blocks[0].JitterMilliseconds(8000) != 10 || m.Blocks[0].JitterMilliseconds(0) != nil {
		t.Fatal(m)
	}
	if *m.Blocks[1].LossPercent() != 0 || *m.Blocks[1].JitterTimestampUnits != 0 {
		t.Fatal("reported zero lost")
	}
	f := mediaFixture()
	f["event"] = []string{"RTCPSent"}
	m, _ = ParseMedia(f)
	if m.RTTMilliseconds != nil || m.Perspective != "local receiver report about remote transmission" {
		t.Fatal(m)
	}
}

func TestMediaMalformedAndMissing(t *testing.T) {
	for _, value := range []string{"", "-1", "256", "NaN", "1.5", "+1", " 0"} {
		f := mediaFixture()
		f["report0fractionlost"] = []string{value}
		m, ok := ParseMedia(f)
		if !ok || !m.Incomplete || m.Blocks[0].LossPercent() != nil || m.Blocks[1].LossPercent() == nil {
			t.Fatalf("%q: %+v", value, m)
		}
	}
	for _, value := range []string{"NaN", "Inf", "-0.1", "1e308"} {
		f := mediaFixture()
		f["rtt"] = []string{value}
		m, ok := ParseMedia(f)
		if !ok || m.RTTMilliseconds != nil || !m.Incomplete {
			t.Fatal(value, m)
		}
	}
	f := mediaFixture()
	f["report0sourcessrc"] = []string{"ambiguous"}
	m, ok := ParseMedia(f)
	if !ok || !m.Incomplete || len(m.Blocks) != 1 || m.Blocks[0].Index != 1 {
		t.Fatal(m)
	}
	for _, key := range []string{"ssrc", "pt", "reportcount"} {
		f := mediaFixture()
		f[key] = append(f[key], f[key][0])
		if _, ok := ParseMedia(f); ok {
			t.Fatal("repeated", key)
		}
	}
	f = mediaFixture()
	f["reportcount"] = []string{"32"}
	if _, ok := ParseMedia(f); ok {
		t.Fatal("unbounded report count")
	}
	f = mediaFixture()
	f["reportcount"] = []string{"0"}
	f["pt"] = []string{"201(RR)"}
	delete(f, "rtt")
	delete(f, "uniqueid")
	m, ok = ParseMedia(f)
	if !ok || m.SenderPackets != nil || m.RTTMilliseconds != nil || m.Uniqueid != "" || len(m.Blocks) != 0 {
		t.Fatal(m)
	}
}

func TestMediaPrivacy(t *testing.T) {
	f := mediaFixture()
	f["calleridnum"] = []string{"SECRET"}
	f["authorization"] = []string{"SECRET"}
	f["channel"] = []string{"SECRET"}
	f["codec"] = []string{"SECRET"}
	m, _ := ParseMedia(f)
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("sensitive field retained")
	}
	// Media normalization remains minimized before persistence.
	if v, ok := Normalize(f, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); !ok || v.Media == nil {
		t.Fatal("media normalization missing")
	}
}

func TestMediaPersistenceBoundaryAndRTTProvenance(t *testing.T) {
	f := mediaFixture()
	e, ok := Normalize(f, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	e.Sequence = 1
	if !ok || !ValidEvent(e) {
		t.Fatal("normalized media rejected")
	}
	for _, lsr := range []string{"", "0", "bad"} {
		f := mediaFixture()
		f["report0lsr"] = []string{lsr}
		m, _ := ParseMedia(f)
		if m.RTTMilliseconds != nil {
			t.Fatal("stored RTT treated as current", lsr)
		}
	}
	f = mediaFixture()
	f["reportcount"] = []string{"0"}
	m, _ := ParseMedia(f)
	if m.RTTMilliseconds != nil {
		t.Fatal("no report RTT")
	}
	f = mediaFixture()
	delete(f, "report1sourcessrc")
	m, _ = ParseMedia(f)
	if !m.Incomplete || len(m.Blocks) != 1 {
		t.Fatal("actual Asterisk18 partial report array")
	}
	for _, v := range []struct {
		raw    string
		signed int32
	}{{"16777215", -1}, {"8388608", -8388608}, {"8388607", 8388607}} {
		f := mediaFixture()
		f["report0cumulativelost"] = []string{v.raw}
		m, _ := ParseMedia(f)
		if *m.Blocks[0].SignedCumulativeLost() != v.signed {
			t.Fatal(v)
		}
	}
}

func TestMediaAllReportBlocksThroughWireDecoder(t *testing.T) {
	var wire strings.Builder
	wire.WriteString("Event: RTCPReceived\r\nSSRC: 0x12345678\r\nPT: 201(RR)\r\nReportCount: 31\r\n")
	for i := 0; i < 31; i++ {
		fmt.Fprintf(&wire, "Report%dSourceSSRC: 0x12345678\r\nReport%dFractionLost: 0\r\nReport%dCumulativeLost: 0\r\nReport%dHighestSequence: 1\r\nReport%dSequenceNumberCycles: 0\r\nReport%dIAJitter: 80\r\nReport%dLSR: 1\r\nReport%dDLSR: 0.000000\r\n", i, i, i, i, i, i, i, i)
	}
	wire.WriteString("\r\n")
	f, e := NewDecoder(strings.NewReader(wire.String())).Read()
	if e != nil {
		t.Fatal(e)
	}
	event, ok := Normalize(f, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	event.Sequence = 1
	if !ok || !ValidEvent(event) || len(event.Media.Blocks) != 31 {
		t.Fatal("wire block limit", event)
	}
}
