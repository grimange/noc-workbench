// Package asteriskactivity reconstructs operational channel relationships. It
// deliberately has no call-control or caller/dialplan data model.
package asteriskactivity

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

const Collector = "asterisk.activity"
const Key = "asterisk.activity.snapshot"
const Limit = 256

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.+\-]{1,128}$`)
var leg = regexp.MustCompile(`^(SIP|PJSIP)/([A-Za-z0-9_.+\-]{1,128})-([a-fA-F0-9]{8})$`)
var runtimeID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func Runtime(s string) bool { return runtimeID.MatchString(s) }
func ID(s string) string {
	if identifier.MatchString(s) {
		return s
	}
	return ""
}
func ChannelName(s string) (name, technology, endpoint string) {
	if m := leg.FindStringSubmatch(s); m != nil {
		return s, m[1], m[2]
	}
	// Local resources can contain dialed numbers and dialplan contexts. Other
	// driver resources are not established endpoint identities either.
	if strings.HasPrefix(s, "Local/") || s == "Local (resource omitted)" {
		return "Local (resource omitted)", "Local", ""
	}
	return "Unknown channel", "", ""
}
func StateName(s string) string {
	switch s {
	case "Down", "Rsrvd", "OffHook", "Dialing", "Ring", "Ringing", "Up", "Busy", "Dialing Offhook", "Pre-ring", "Unknown":
		return s
	}
	return "Unknown"
}

type Channel struct {
	ID              string    `json:"id"`
	Linked          string    `json:"linked,omitempty"`
	Name            string    `json:"name"`
	Technology      string    `json:"technology"`
	Endpoint        string    `json:"endpoint,omitempty"`
	Association     string    `json:"association"`
	State           string    `json:"state"`
	DurationSeconds int64     `json:"duration_seconds"`
	Bridge          string    `json:"bridge,omitempty"`
	First           time.Time `json:"first"`
	Updated         time.Time `json:"updated"`
	Source          string    `json:"source"`
}
type Bridge struct {
	ID      string    `json:"id"`
	Count   int       `json:"count"`
	Updated time.Time `json:"updated"`
}
type Conference struct {
	ID              string          `json:"id"`
	Type            string          `json:"type"`
	Count           int             `json:"count"`
	Bridge          string          `json:"bridge,omitempty"`
	Members         map[string]bool `json:"members,omitempty"`
	MembersComplete bool            `json:"members_complete"`
	Updated         time.Time       `json:"updated"`
}
type Event struct {
	Channel    string `json:"channel,omitempty"`
	Uniqueid   string `json:"uniqueid,omitempty"`
	Linkedid   string `json:"linkedid,omitempty"`
	Bridge     string `json:"bridge,omitempty"`
	Conference string `json:"conference,omitempty"`
	State      string `json:"state,omitempty"`
}

func IsEvent(n string) bool {
	switch n {
	case "Newchannel", "Newstate", "Hangup", "BridgeCreate", "BridgeDestroy", "BridgeEnter", "BridgeLeave", "MeetmeJoin", "MeetmeLeave", "ConfbridgeStart", "ConfbridgeEnd", "ConfbridgeJoin", "ConfbridgeLeave":
		return true
	}
	return false
}
func Normalize(get func(string) string) Event {
	n, _, _ := ChannelName(get("Channel"))
	return Event{Channel: n, Uniqueid: ID(get("Uniqueid")), Linkedid: ID(get("Linkedid")), Bridge: ID(get("BridgeUniqueid")), Conference: ID(get("Conference")), State: StateName(get("ChannelStateDesc"))}
}
func (e Event) Valid() bool {
	n, _, _ := ChannelName(e.Channel)
	return e.Uniqueid == ID(e.Uniqueid) && e.Linkedid == ID(e.Linkedid) && e.Bridge == ID(e.Bridge) && e.Conference == ID(e.Conference) && (e.Channel == "" || e.Channel == n || e.Channel == "Local (resource omitted)") && (e.State == "" || StateName(e.State) == e.State)
}

type Snapshot struct {
	Runtime     string       `json:"runtime"`
	Version     string       `json:"version"`
	Channels    []Channel    `json:"channels"`
	Bridges     []Bridge     `json:"bridges"`
	Conferences []Conference `json:"conferences"`
	Meetme      string       `json:"meetme"`
	Confbridge  string       `json:"confbridge"`
}
type State struct {
	Snapshot
	Session    string    `json:"session"`
	Baseline   time.Time `json:"baseline"`
	Started    time.Time `json:"started"`
	Generation int64     `json:"generation"`
	Complete   bool      `json:"complete"`
	Reason     string    `json:"reason"`
	// Tombstones and per-object clocks prevent delayed events from resurrecting
	// ended lifecycles. They are scoped to a remote runtime, bounded and durable.
	Ended  map[string]time.Time `json:"ended"`
	Clocks map[string]time.Time `json:"clocks"`
}
type View struct {
	State
	Current bool
	Query   string
	Recent  []History
}
type History struct {
	Name string
	Event
	At       time.Time
	SourceAt *time.Time
	Session  string
}

func (s *State) Invalidate(reason string) { s.Complete = false; s.Reason = reason }
func (s *State) Reconcile(v Snapshot, session string, start, end time.Time) {
	generation := s.Generation + 1
	ended, clocks := s.Ended, s.Clocks
	// A complete baseline supersedes earlier clocks and terminal identities.
	// Older queued nonterminal events are rejected by Started below.
	ended, clocks = nil, nil
	old := s.Channels
	if s.Runtime != v.Runtime {
		ended = nil
		clocks = nil
		old = nil
	}
	*s = State{Snapshot: v, Session: session, Started: start, Baseline: end, Generation: generation, Complete: true, Ended: ended, Clocks: clocks}
	if s.Ended == nil {
		s.Ended = map[string]time.Time{}
	}
	if s.Clocks == nil {
		s.Clocks = map[string]time.Time{}
	}
	for i := range s.Channels {
		c := &s.Channels[i]
		c.Updated = end
		c.Source = "CLI snapshot"
		c.First = end
		for _, p := range old {
			if p.ID == c.ID {
				c.First = p.First
				if c.Linked == "" {
					c.Linked = p.Linked
				}
				break
			}
		}
		if _, dead := s.Ended["c/"+c.ID]; dead {
			s.Invalidate("Snapshot conflicts with a terminated channel identity")
		}
	}
	for i := range s.Bridges {
		s.Bridges[i].Updated = end
	}
	for i := range s.Conferences {
		s.Conferences[i].Updated = end
	}
}
func (s *State) Apply(name string, e Event, occurred, received time.Time) {
	if !IsEvent(name) || !e.Valid() {
		return
	}
	if s.Clocks == nil {
		s.Clocks = map[string]time.Time{}
	}
	if s.Ended == nil {
		s.Ended = map[string]time.Time{}
	}
	if len(s.Clocks) > 4096 || len(s.Ended) > 4096 {
		s.Invalidate("Lifecycle identity limit; fresh snapshot required")
		return
	}
	at := occurred
	if at.IsZero() {
		at = received
	}
	key := "c/" + e.Uniqueid
	if name == "BridgeEnter" || name == "BridgeLeave" {
		// State and bridge membership are independent fields. A delayed bridge
		// event must not be discarded merely because a newer Newstate arrived.
		key = "membership/" + e.Uniqueid
		if _, dead := s.Ended["c/"+e.Uniqueid]; dead {
			return
		}
	}
	if strings.HasPrefix(name, "Bridge") && name != "BridgeEnter" && name != "BridgeLeave" {
		key = "b/" + e.Bridge
	}
	kind := "ConfBridge"
	if strings.HasPrefix(name, "Meetme") {
		kind = "MeetMe"
	}
	if strings.HasPrefix(name, "Confbridge") || strings.HasPrefix(name, "Meetme") {
		key = kind + "/" + e.Conference
		if e.Conference == "" {
			s.Invalidate("Conference identity unavailable")
			return
		}
		if name == "MeetmeJoin" || name == "MeetmeLeave" || name == "ConfbridgeJoin" || name == "ConfbridgeLeave" {
			if e.Uniqueid == "" {
				s.Invalidate("Conference participant identity unavailable")
				return
			}
			key += "/" + e.Uniqueid
		}
	}
	if strings.HasSuffix(key, "/") {
		s.Invalidate("Event identity unavailable")
		return
	}
	if t := s.Clocks[key]; at.Before(t) && name != "Hangup" && name != "BridgeDestroy" {
		return
	}
	terminal := name == "Hangup" || name == "BridgeDestroy" || name == "ConfbridgeEnd"
	if end, dead := s.Ended[kind+"/"+e.Conference]; e.Conference != "" && dead && !at.After(end) {
		return
	}
	if end, dead := s.Ended[key]; dead {
		if (name == "ConfbridgeStart" || name == "MeetmeJoin" || name == "ConfbridgeJoin") && at.After(end) {
			delete(s.Ended, key)
		} else if !terminal {
			return
		}
	}
	// Older queued events cannot replace a newer successful baseline. Terminal
	// evidence is retained as a tombstone even when it predates that baseline.
	if received.Before(s.Started) {
		return
	}
	if name == "MeetmeJoin" || name == "ConfbridgeJoin" {
		if t, ok := s.Clocks[key]; ok && at.Equal(t) {
			return
		}
	}
	s.Clocks[key] = at
	if terminal {
		s.Ended[key] = at
	}
	if name == "MeetmeLeave" || name == "ConfbridgeLeave" {
		s.Ended[key] = at
	}
	switch name {
	case "Newchannel", "Newstate", "BridgeEnter", "BridgeLeave", "Hangup":
		i := -1
		for j := range s.Channels {
			if s.Channels[j].ID == e.Uniqueid {
				i = j
				break
			}
		}
		if name == "Hangup" {
			if i >= 0 {
				s.Channels = append(s.Channels[:i], s.Channels[i+1:]...)
			}
			for j := range s.Conferences {
				if s.Conferences[j].Members[e.Uniqueid] {
					s.Invalidate("Channel ended before conference leave evidence; reconciliation required")
				}
			}
			break
		}
		if i < 0 {
			if name != "Newchannel" {
				s.Invalidate("Event refers to a channel absent from the baseline")
				return
			}
			if len(s.Channels) >= Limit {
				s.Invalidate("Channel limit reached")
				return
			}
			n, t, p := ChannelName(e.Channel)
			s.Channels = append(s.Channels, Channel{ID: e.Uniqueid, Name: n, Technology: t, Endpoint: p, Association: Association(p), First: received})
			i = len(s.Channels) - 1
		}
		c := &s.Channels[i]
		if !c.Updated.IsZero() && received.After(c.Updated) {
			c.DurationSeconds += int64(received.Sub(c.Updated).Seconds())
		}
		c.Updated = received
		c.Source = "AMI " + name
		if e.Linkedid != "" {
			c.Linked = e.Linkedid
		}
		if name == "Newchannel" || name == "Newstate" {
			c.State = e.State
		}
		if name == "BridgeEnter" {
			found := false
			for j := range s.Bridges {
				if e.Bridge != "" && s.Bridges[j].ID == e.Bridge {
					found = true
					s.Bridges[j].Updated = received
				}
			}
			if !found {
				s.Invalidate("Bridge entry lacks an observed bridge baseline")
			}
			c.Bridge = e.Bridge
		}
		if name == "BridgeLeave" && c.Bridge == e.Bridge {
			c.Bridge = ""
		}
	case "BridgeCreate", "BridgeDestroy":
		i := -1
		for j := range s.Bridges {
			if s.Bridges[j].ID == e.Bridge {
				i = j
				break
			}
		}
		if name == "BridgeDestroy" {
			if i >= 0 {
				s.Bridges = append(s.Bridges[:i], s.Bridges[i+1:]...)
			}
			for j := range s.Channels {
				if s.Channels[j].Bridge == e.Bridge {
					s.Channels[j].Bridge = ""
				}
			}
		} else if i < 0 {
			if len(s.Bridges) >= Limit {
				s.Invalidate("Bridge limit reached")
				return
			}
			s.Bridges = append(s.Bridges, Bridge{ID: e.Bridge, Updated: received})
		}
	default:
		i := -1
		for j := range s.Conferences {
			if s.Conferences[j].ID == e.Conference && s.Conferences[j].Type == kind {
				i = j
				break
			}
		}
		if name == "ConfbridgeEnd" {
			if i >= 0 {
				s.Conferences = append(s.Conferences[:i], s.Conferences[i+1:]...)
			}
			return
		}
		join := name == "MeetmeJoin" || name == "ConfbridgeJoin"
		if i < 0 {
			if !join && name != "ConfbridgeStart" {
				s.Invalidate("Conference leave without baseline")
				return
			}
			if len(s.Conferences) >= Limit {
				s.Invalidate("Conference limit reached")
				return
			}
			s.Conferences = append(s.Conferences, Conference{ID: e.Conference, Type: kind, Members: map[string]bool{}, MembersComplete: true})
			i = len(s.Conferences) - 1
		}
		c := &s.Conferences[i]
		if c.Members == nil {
			c.Members = map[string]bool{}
		}
		c.Updated = received
		if e.Bridge != "" {
			c.Bridge = e.Bridge
		}
		if join {
			if e.Uniqueid == "" {
				s.Invalidate("Conference participant identity unavailable")
				return
			}
			if !c.Members[e.Uniqueid] {
				if len(c.Members) >= Limit || c.Count >= Limit {
					s.Invalidate("Conference participant limit reached")
					return
				}
				if !c.MembersComplete {
					s.Invalidate("Conference membership changed from count-only baseline; reconciliation required")
				}
				c.Members[e.Uniqueid] = true
				c.Count++
			}
		}
		if name == "MeetmeLeave" || name == "ConfbridgeLeave" {
			if c.Members[e.Uniqueid] {
				delete(c.Members, e.Uniqueid)
				if c.Count > 0 {
					c.Count--
				}
			} else {
				s.Invalidate("Unobserved conference participant left; snapshot required")
			}
			if kind == "MeetMe" && c.MembersComplete && c.Count == 0 {
				s.Conferences = append(s.Conferences[:i], s.Conferences[i+1:]...)
			}
		}
	}
	for i := range s.Bridges {
		n := 0
		for _, c := range s.Channels {
			if c.Bridge == s.Bridges[i].ID {
				n++
			}
		}
		s.Bridges[i].Count = n
	}
}
func Association(endpoint string) string {
	if endpoint == "" {
		return "Unknown association"
	}
	return "Channel resource; account ownership unverified"
}
func Decode(b []byte, v any) error {
	if len(b) > 1024*1024 {
		return errors.New("activity limit")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing activity data")
	}
	return nil
}
func (s *State) Sort() {
	sort.Slice(s.Channels, func(i, j int) bool { return s.Channels[i].ID < s.Channels[j].ID })
	sort.Slice(s.Conferences, func(i, j int) bool {
		return s.Conferences[i].Type+s.Conferences[i].ID < s.Conferences[j].Type+s.Conferences[j].ID
	})
}

func (v View) MeetmeCount() int {
	n := 0
	for _, c := range v.Conferences {
		if c.Type == "MeetMe" {
			n++
		}
	}
	return n
}
func (v View) ConfbridgeCount() int {
	n := 0
	for _, c := range v.Conferences {
		if c.Type == "ConfBridge" {
			n++
		}
	}
	return n
}
