package asteriskami

// RTCP normalization follows Asterisk 18 main/rtp_engine.c. Reporting event
// admission requires its explicit monitoring capability.
import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"
)

// MediaReport contains operational fields only. Pointer measurements distinguish
// absent/invalid data from a reported zero. No codec clock is inferred.
type MediaReport struct {
	Uniqueid, Linkedid, SSRC, PacketType, Perspective string
	SenderPackets                                     *uint32
	RTTMilliseconds                                   *float64
	Blocks                                            []MediaBlock
	Incomplete                                        bool
}

type MediaBlock struct {
	Index                int
	SourceSSRC           string
	FractionLost         *uint32 // unsigned 8-bit fraction of 256, over the report interval
	CumulativeLost       *uint32 // raw 24-bit field; SignedCumulativeLost decodes RFC 3550
	LastSenderReport     *uint32 // compact NTP reference; RTT is fresh only with nonzero block 0 LSR
	JitterTimestampUnits *uint32
}

var mediaSSRC = regexp.MustCompile(`^0x[0-9a-fA-F]{8}$`)

func mediaUint(s string, bits int) *uint32 {
	if s == "" {
		return nil
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil
		}
	}
	n, err := strconv.ParseUint(s, 10, bits)
	if err != nil {
		return nil
	}
	v := uint32(n)
	return &v
}

func (b MediaBlock) SignedCumulativeLost() *int32 {
	if b.CumulativeLost == nil {
		return nil
	}
	v := int32(*b.CumulativeLost)
	if v&0x800000 != 0 {
		v -= 1 << 24
	}
	return &v
}

func (b MediaBlock) LossPercent() *float64 {
	if b.FractionLost == nil {
		return nil
	}
	v := float64(*b.FractionLost) * 100 / 256
	return &v
}

// The caller must supply an independently verified RTP timestamp clock rate,
// never an audio sample rate guessed from a channel or codec name.
func (b MediaBlock) JitterMilliseconds(verifiedClockHz uint32) *float64 {
	if b.JitterTimestampUnits == nil || verifiedClockHz == 0 {
		return nil
	}
	v := float64(*b.JitterTimestampUnits) * 1000 / float64(verifiedClockHz)
	return &v
}

func ParseMedia(f Frame) (MediaReport, bool) {
	m := MediaReport{Uniqueid: cleanID(f.One("Uniqueid")), Linkedid: cleanID(f.One("Linkedid"))}
	switch f.One("Event") {
	case "RTCPReceived":
		m.Perspective = "remote receiver report about Asterisk transmission"
	case "RTCPSent":
		m.Perspective = "local receiver report about remote transmission"
	default:
		return m, false
	}
	m.SSRC = f.One("SSRC")
	if !mediaSSRC.MatchString(m.SSRC) {
		return MediaReport{}, false
	}
	m.PacketType = known(f.One("PT"), "200(SR)", "201(RR)")
	count := mediaUint(f.One("ReportCount"), 5)
	if m.PacketType == "" || count == nil {
		return MediaReport{}, false
	}
	if m.PacketType == "200(SR)" {
		m.SenderPackets = mediaUint(f.One("SentPackets"), 32)
	}
	for i := 0; i < int(*count); i++ {
		prefix := fmt.Sprintf("Report%d", i)
		b := MediaBlock{Index: i, SourceSSRC: f.One(prefix + "SourceSSRC")}
		if !mediaSSRC.MatchString(b.SourceSSRC) {
			m.Incomplete = true
			continue
		}
		b.FractionLost = mediaUint(f.One(prefix+"FractionLost"), 8)
		b.CumulativeLost = mediaUint(f.One(prefix+"CumulativeLost"), 24)
		b.LastSenderReport = mediaUint(f.One(prefix+"LSR"), 32)
		b.JitterTimestampUnits = mediaUint(f.One(prefix+"IAJitter"), 32)
		if b.FractionLost == nil || b.CumulativeLost == nil || b.JitterTimestampUnits == nil {
			m.Incomplete = true
		}
		m.Blocks = append(m.Blocks, b)
	}
	if f.One("Event") == "RTCPReceived" && len(m.Blocks) > 0 && m.Blocks[0].Index == 0 && m.Blocks[0].LastSenderReport != nil && *m.Blocks[0].LastSenderReport != 0 && f.One("RTT") != "" {
		v, err := strconv.ParseFloat(f.One("RTT"), 64)
		if err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= math.MaxFloat64/1000 {
			v *= 1000
			m.RTTMilliseconds = &v
		} else {
			m.Incomplete = true
		}
	}
	return m, true
}

// Valid rejects forged normalized values at the persistence boundary.
func (m MediaReport) Valid() bool {
	if m.Uniqueid != cleanID(m.Uniqueid) || m.Linkedid != cleanID(m.Linkedid) || !mediaSSRC.MatchString(m.SSRC) || known(m.PacketType, "200(SR)", "201(RR)") == "" || len(m.Blocks) > 31 {
		return false
	}
	if m.Perspective != "remote receiver report about Asterisk transmission" && m.Perspective != "local receiver report about remote transmission" {
		return false
	}
	if m.PacketType == "201(RR)" && m.SenderPackets != nil {
		return false
	}
	if m.RTTMilliseconds != nil && (math.IsNaN(*m.RTTMilliseconds) || math.IsInf(*m.RTTMilliseconds, 0) || *m.RTTMilliseconds < 0 || m.Perspective != "remote receiver report about Asterisk transmission") {
		return false
	}
	if m.RTTMilliseconds != nil && (len(m.Blocks) == 0 || m.Blocks[0].Index != 0 || m.Blocks[0].LastSenderReport == nil || *m.Blocks[0].LastSenderReport == 0) {
		return false
	}
	last := -1
	for _, b := range m.Blocks {
		if b.Index <= last || b.Index > 30 || !mediaSSRC.MatchString(b.SourceSSRC) || b.FractionLost != nil && *b.FractionLost > 255 || b.CumulativeLost != nil && *b.CumulativeLost > 0xffffff {
			return false
		}
		last = b.Index
	}
	return true
}

// MediaRecord preserves receipt time; a channel snapshot cannot reconstruct a
// missing RTCP sample. Runtime is assigned only by the trusted state repository.
type MediaRecord struct {
	Report                    MediaReport
	Session, Runtime          string
	Sequence                  int64
	ProfileRevision           int64
	At                        time.Time
	SourceAt                  *time.Time
	Gap                       bool
	Channel, Endpoint, Status string
}

func (m MediaReport) RTTDisplay() string {
	if m.RTTMilliseconds == nil {
		return "Unavailable"
	}
	return fmt.Sprintf("%.3f ms", *m.RTTMilliseconds)
}
func (b MediaBlock) LossDisplay() string {
	v := b.LossPercent()
	if v == nil {
		return "Unavailable"
	}
	return fmt.Sprintf("%.2f%% interval", *v)
}
