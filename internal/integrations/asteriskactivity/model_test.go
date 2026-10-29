package asteriskactivity

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

var epoch = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func baseline() State {
	var s State
	s.Reconcile(Snapshot{Runtime: strings.Repeat("a", 64), Meetme: "supported", Confbridge: "supported"}, "session", epoch, epoch)
	return s
}
func ev(id string) Event {
	return Event{Uniqueid: id, Linkedid: "related", Channel: "PJSIP/phone-00000001", State: "Ringing"}
}
func TestLifecycleDuplicatesOrderingAndRuntime(t *testing.T) {
	s := baseline()
	e := ev("1.1")
	at := epoch.Add(time.Second)
	s.Apply("Newchannel", e, at, at)
	s.Apply("Newchannel", e, at, at)
	if len(s.Channels) != 1 || s.Channels[0].Linked == s.Channels[0].ID || s.Channels[0].Endpoint != "phone" {
		t.Fatal(s)
	}
	e.State = "Up"
	s.Apply("Newstate", e, at.Add(time.Second), at.Add(time.Second))
	e.State = "Down"
	s.Apply("Newstate", e, at, at)
	if s.Channels[0].State != "Up" {
		t.Fatal("older state overwrote")
	}
	s.Apply("Hangup", e, at.Add(2*time.Second), at.Add(2*time.Second))
	s.Apply("Newchannel", e, at, at)
	if len(s.Channels) != 0 {
		t.Fatal("resurrected")
	}
	s.Reconcile(Snapshot{Runtime: strings.Repeat("b", 64), Channels: []Channel{{ID: e.Uniqueid}}}, "next", at.Add(3*time.Second), at.Add(4*time.Second))
	if len(s.Channels) != 1 || !s.Complete {
		t.Fatal("runtime not reset")
	}
}
func TestBridgeMembershipAndLinkedid(t *testing.T) {
	s := baseline()
	at := epoch.Add(time.Second)
	for _, id := range []string{"1.1", "1.2"} {
		s.Apply("Newchannel", ev(id), at, at)
	}
	if s.Channels[0].Bridge != "" || s.Channels[1].Bridge != "" {
		t.Fatal("linkedid invented bridge")
	}
	e := Event{Bridge: "bridge"}
	s.Apply("BridgeCreate", e, at, at)
	for _, id := range []string{"1.1", "1.2"} {
		e.Uniqueid = id
		s.Apply("BridgeEnter", e, at, at)
	}
	if len(s.Bridges) != 1 || s.Bridges[0].Count != 2 {
		t.Fatal(s)
	}
	s.Apply("BridgeLeave", e, at.Add(time.Second), at.Add(time.Second))
	if s.Bridges[0].Count != 1 {
		t.Fatal(s)
	}
	s.Apply("BridgeDestroy", e, at.Add(2*time.Second), at.Add(2*time.Second))
	if len(s.Bridges) != 0 || s.Channels[0].Bridge != "" {
		t.Fatal(s)
	}
}
func TestConferenceMembersAndDuplicates(t *testing.T) {
	for _, family := range []string{"Meetme", "Confbridge"} {
		t.Run(family, func(t *testing.T) {
			s := baseline()
			at := epoch.Add(time.Second)
			e := ev("1.1")
			e.Conference = "room"
			if family == "Confbridge" {
				s.Apply("ConfbridgeStart", e, at, at)
			}
			s.Apply(family+"Join", e, at, at)
			s.Apply(family+"Join", e, at, at)
			e.Uniqueid = "1.2"
			s.Apply(family+"Join", e, at, at)
			if len(s.Conferences) != 1 || s.Conferences[0].Count != 2 {
				t.Fatal(s)
			}
			s.Apply(family+"Leave", e, at.Add(time.Second), at.Add(time.Second))
			s.Apply(family+"Leave", e, at.Add(time.Second), at.Add(time.Second))
			if s.Conferences[0].Count != 1 || !s.Complete {
				t.Fatal(s)
			}
			e.Uniqueid = "1.1"
			s.Apply(family+"Leave", e, at.Add(2*time.Second), at.Add(2*time.Second))
			if family == "Meetme" && len(s.Conferences) != 0 {
				t.Fatal("empty MeetMe remained active", s)
			}
		})
	}
}
func TestReconciliationZeroFailureAndDelayedEvents(t *testing.T) {
	s := baseline()
	at := epoch.Add(time.Second)
	s.Apply("Newchannel", ev("1.1"), at, at)
	saved := s
	s.Invalidate("disconnect")
	if s.Complete || len(s.Channels) != 1 {
		t.Fatal(s)
	}
	s = saved
	s.Reconcile(Snapshot{Runtime: s.Runtime, Meetme: "supported", Confbridge: "unsupported"}, "next", at.Add(time.Second), at.Add(2*time.Second))
	s.Apply("Newchannel", ev("1.1"), at, at)
	if !s.Complete || len(s.Channels) != 0 || s.Confbridge != "unsupported" {
		t.Fatal(s)
	}
	s.Apply("Newstate", ev("unknown"), at.Add(3*time.Second), at.Add(3*time.Second))
	if s.Complete {
		t.Fatal("unknown lifecycle current")
	}
}
func TestMinimizedNamesAndStrictDecode(t *testing.T) {
	for _, tc := range []struct{ raw, tech, endpoint string }{{"SIP/trunk-00000001", "SIP", "trunk"}, {"PJSIP/phone-00000001", "PJSIP", "phone"}, {"Local/secret-number@secret-context-00000001;1", "Local", ""}, {"DAHDI/secret-number", "", ""}} {
		n, tech, ep := ChannelName(tc.raw)
		if tech != tc.tech || ep != tc.endpoint || strings.Contains(n, "secret") {
			t.Fatal(n, tech, ep)
		}
	}
	e := Normalize(func(k string) string {
		return map[string]string{"Channel": "Local/secret@secret-1;1", "Uniqueid": "1.1", "CallerIDNum": "secret"}[k]
	})
	b, _ := json.Marshal(e)
	if !e.Valid() || strings.Contains(string(b), "secret") {
		t.Fatal(string(b))
	}
	var v Event
	if Decode([]byte(`{} {}`), &v) == nil || Decode([]byte(`{"CallerIDNum":"secret"}`), &v) == nil {
		t.Fatal("unrestricted JSON")
	}
}
func TestRemoteClockSkewDoesNotDropHangup(t *testing.T) {
	s := baseline()
	e := ev("1.1")
	s.Channels = []Channel{{ID: e.Uniqueid}}
	s.Apply("Hangup", e, epoch.Add(-30*time.Second), epoch.Add(10*time.Second))
	if len(s.Channels) != 0 {
		t.Fatal("remote clock compared with local snapshot boundary")
	}
}

func TestIndependentDelayedMembershipAndTerminalEvidence(t *testing.T) {
	s := baseline()
	e := ev("1.1")
	s.Apply("Newchannel", e, epoch.Add(time.Second), epoch.Add(time.Second))
	s.Apply("BridgeCreate", Event{Bridge: "bridge"}, epoch.Add(time.Second), epoch.Add(time.Second))
	e.State = "Up"
	s.Apply("Newstate", e, epoch.Add(3*time.Second), epoch.Add(3*time.Second))
	e.Bridge = "bridge"
	s.Apply("BridgeEnter", e, epoch.Add(2*time.Second), epoch.Add(4*time.Second))
	if !s.Complete || s.Channels[0].Bridge != "bridge" || s.Bridges[0].Count != 1 {
		t.Fatal("newer state discarded independent bridge membership", s)
	}
	s.Apply("Hangup", e, epoch.Add(2*time.Second), epoch.Add(5*time.Second))
	s.Apply("BridgeEnter", e, epoch.Add(4*time.Second), epoch.Add(6*time.Second))
	if !s.Complete || len(s.Channels) != 0 || s.Bridges[0].Count != 0 {
		t.Fatal("terminal evidence discarded or lifecycle resurrected", s)
	}
}
func TestBridgeLimitInvalidates(t *testing.T) {
	s := baseline()
	for i := 0; i < Limit; i++ {
		s.Bridges = append(s.Bridges, Bridge{ID: fmt.Sprint(i)})
	}
	s.Apply("BridgeCreate", Event{Bridge: "new"}, epoch, epoch)
	if s.Complete || len(s.Bridges) != Limit {
		t.Fatal("overflow silently accepted")
	}
}
func TestConferenceRoomReuse(t *testing.T) {
	s := baseline()
	e := Event{Conference: "room"}
	s.Apply("ConfbridgeStart", e, epoch, epoch)
	s.Apply("ConfbridgeEnd", e, epoch.Add(time.Second), epoch.Add(time.Second))
	s.Apply("ConfbridgeStart", e, epoch.Add(2*time.Second), epoch.Add(2*time.Second))
	if len(s.Conferences) != 1 || !s.Complete {
		t.Fatal("room identity treated as permanent tombstone", s)
	}
}

func TestConferenceParticipantLimitAndRejoin(t *testing.T) {
	s := baseline()
	e := Event{Conference: "room", Uniqueid: "member"}
	s.Apply("ConfbridgeJoin", e, epoch, epoch)
	s.Apply("ConfbridgeLeave", e, epoch.Add(time.Second), epoch.Add(time.Second))
	s.Apply("ConfbridgeJoin", e, epoch.Add(2*time.Second), epoch.Add(2*time.Second))
	if !s.Complete || s.Conferences[0].Count != 1 {
		t.Fatal("rejoin did not restore membership", s)
	}
	for i := 0; i < Limit; i++ {
		e.Uniqueid = fmt.Sprint(i)
		s.Apply("ConfbridgeJoin", e, epoch.Add(3*time.Second), epoch.Add(3*time.Second))
	}
	if s.Complete || s.Conferences[0].Count != Limit || len(s.Conferences[0].Members) != Limit {
		t.Fatal("unbounded participants", s)
	}
}
