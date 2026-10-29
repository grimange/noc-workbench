package asteriskami

import (
	"math"
	"net"
	"net/netip"
	"net/url"
	activity "noc-workbench/internal/integrations/asteriskactivity"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const ParserVersion = "1"

type Event struct {
	Activity                                        activity.Event
	Name, Technology, Endpoint, AOR, Address, State string
	RTT                                             *float64
	SourceAt                                        *time.Time
	ReceivedAt                                      time.Time
	Sequence                                        int64
}

var identity = regexp.MustCompile(`^[A-Za-z0-9_.+\-]{1,128}$`)

func cleanID(s string) string {
	if identity.MatchString(s) {
		return s
	}
	return ""
}
func known(s string, values ...string) string {
	for _, v := range values {
		if v == s {
			return s
		}
	}
	return ""
}
func address(s string) string {
	if len(s) > 1024 {
		return ""
	}
	if strings.HasPrefix(s, "sip:") || strings.HasPrefix(s, "sips:") {
		u, e := url.Parse(s)
		if e != nil {
			return ""
		}
		s = u.Opaque
		if i := strings.LastIndex(s, "@"); i >= 0 {
			s = s[i+1:]
		}
		s = strings.SplitN(s, ";", 2)[0]
		s = strings.SplitN(s, "?", 2)[0]
	}
	if ip, e := netip.ParseAddr(strings.Trim(s, "[]")); e == nil && ip.Zone() == "" {
		return ip.String()
	}
	h, p, e := net.SplitHostPort(s)
	if e != nil {
		return ""
	}
	ip, e := netip.ParseAddr(h)
	port, e2 := strconv.ParseUint(p, 10, 16)
	if e != nil || e2 != nil || port == 0 || ip.Zone() != "" {
		return ""
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}
func Normalize(f Frame, received time.Time) (Event, bool) {
	e := Event{Name: f.One("Event"), ReceivedAt: received.UTC()}
	switch e.Name {
	case "FullyBooted":
		e.State = "Fully booted"
	case "Shutdown":
		e.State = "Shutdown reported"
	case "PeerStatus":
		peer := f.One("Peer")
		tech, id, ok := strings.Cut(peer, "/")
		if ok {
			e.Technology = known(tech, "SIP", "PJSIP", "IAX2")
			if e.Technology != "" {
				e.Endpoint = cleanID(id)
			}
		}
		e.State = known(f.One("PeerStatus"), "Registered", "Unregistered", "Reachable", "Unreachable", "Lagged", "Unknown", "Rejected")
		e.Address = address(f.One("Address"))
	case "ContactStatus":
		e.Technology = "PJSIP"
		e.Endpoint = cleanID(f.One("EndpointName"))
		e.AOR = cleanID(f.One("AOR"))
		e.Address = address(f.One("URI"))
		e.State = known(f.One("ContactStatus"), "Reachable", "Unreachable", "Unknown", "NonQualified", "Removed", "Updated", "Created")
		// RoundtripUsec is documented in microseconds, stored/displayed in ms.
		if n, err := strconv.ParseUint(f.One("RoundtripUsec"), 10, 32); err == nil {
			v := float64(n) / 1000
			e.RTT = &v
		}
	case "Registry":
		e.Technology = known(f.One("ChannelType"), "SIP", "PJSIP", "IAX2")
		e.Endpoint = cleanID(f.One("Username"))
		e.State = known(f.One("Status"), "Registered", "Unregistered", "Rejected", "Request Sent", "Auth. Sent", "Timeout", "No Authentication")
		e.Address = address(f.One("Domain"))
	default:
		if !activity.IsEvent(e.Name) {
			return Event{}, false
		}
		e.Activity = activity.Normalize(f.One)
		if strings.HasPrefix(e.Name, "Meetme") {
			e.Activity.Conference = activity.ID(f.One("Meetme"))
		}
	}
	if v := f.One("Timestamp"); v != "" {
		seconds, err := strconv.ParseFloat(v, 64)
		if err == nil && seconds >= 946684800 && seconds < 4102444800 {
			t := time.Unix(0, int64(seconds*1e9)).UTC()
			e.SourceAt = &t
		}
	}
	return e, true
}
func ValidEvent(e Event) bool {
	if !e.Activity.Valid() {
		return false
	}
	if e.ReceivedAt.IsZero() || e.Sequence < 1 || e.Endpoint != cleanID(e.Endpoint) || e.AOR != cleanID(e.AOR) || e.Address != address(e.Address) {
		return false
	}
	f := Frame{"event": {e.Name}}
	if _, ok := Normalize(f, e.ReceivedAt); !ok {
		return false
	}
	if e.Technology != "" && known(e.Technology, "SIP", "PJSIP", "IAX2") == "" {
		return false
	}
	if e.RTT != nil && (math.IsNaN(*e.RTT) || math.IsInf(*e.RTT, 0) || *e.RTT < 0 || *e.RTT > 4294967.295) {
		return false
	}
	return known(e.State, "", "Fully booted", "Shutdown reported", "Registered", "Unregistered", "Reachable", "Unreachable", "Lagged", "Unknown", "Rejected", "NonQualified", "Removed", "Updated", "Created", "Request Sent", "Auth. Sent", "Timeout", "No Authentication") == e.State
}
