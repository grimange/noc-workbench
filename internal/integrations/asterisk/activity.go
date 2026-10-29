package asterisk

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"noc-workbench/internal/collection"
	activity "noc-workbench/internal/integrations/asteriskactivity"
)

// Activity accepts only the complete fixed bundle. Empty concise output is
// valid only inside its successful command delimiters, never on transport error.
func Activity(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	if len(b) > 65536 {
		return bad("record_limit")
	}
	parts := strings.Split(string(b), "\nNW_ACTIVITY_")
	v, code := frame([]byte(parts[0]), false)
	if code != "" {
		return bad(code)
	}
	if len(parts) != 8 || strings.TrimSpace(parts[7]) != "END" {
		return bad("parse_error")
	}
	names := []string{"runtime", "channels", "bridges", "meetme", "confbridge", "runtime_end"}
	data := map[string]string{}
	for i, n := range names {
		prefix := n + "\n"
		if !strings.HasPrefix(parts[i+1], prefix) {
			return bad("parse_error")
		}
		data[n] = strings.TrimSpace(strings.TrimPrefix(parts[i+1], prefix))
	}
	runtime := strings.Fields(data["runtime"])
	end := strings.Fields(data["runtime_end"])
	if len(runtime) != 2 || len(end) != 2 || runtime[0] != end[0] || runtime[1] != "-" || end[1] != "-" || !activity.Runtime(runtime[0]) {
		return bad("runtime_changed")
	}
	snap := activity.Snapshot{Runtime: runtime[0], Version: v, Meetme: "supported", Confbridge: "supported"}
	fail := func() ([]collection.Observation, []collection.Diagnostic) { return bad("parse_error") }
	seen := map[string]bool{}
	if data["channels"] != "" {
		for _, line := range strings.Split(data["channels"], "\n") {
			f := strings.Split(line, "!")
			if len(f) != 14 {
				return fail()
			}
			id := activity.ID(f[13])
			if id == "" || seen[id] || len(snap.Channels) >= activity.Limit {
				return fail()
			}
			seen[id] = true
			name, tech, endpoint := activity.ChannelName(f[0])
			state := activity.StateName(f[4])
			bridge := activity.ID(f[12])
			if bridge != f[12] {
				return fail()
			}
			// CLI fields 1-3 and 5-11 contain dialplan/caller data and are discarded.
			duration, err := strconv.ParseInt(f[11], 10, 64)
			if err != nil || duration < 0 || duration > 315360000 {
				return fail()
			}
			snap.Channels = append(snap.Channels, activity.Channel{DurationSeconds: duration, ID: id, Name: name, Technology: tech, Endpoint: endpoint, Association: activity.Association(endpoint), State: state, Bridge: bridge})
		}
	}
	lines := strings.Split(data["bridges"], "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "Bridge-ID") {
		return fail()
	}
	seen = map[string]bool{}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 5 || activity.ID(f[0]) == "" || seen[f[0]] || len(snap.Bridges) >= activity.Limit {
			return fail()
		}
		n, e := strconv.Atoi(f[1])
		if e != nil || n < 0 || n > activity.Limit {
			return fail()
		}
		seen[f[0]] = true
		snap.Bridges = append(snap.Bridges, activity.Bridge{ID: f[0], Count: n})
	}
	for _, kind := range []string{"meetme", "confbridge"} {
		text := data[kind]
		lower := strings.ToLower(text)
		if strings.Contains(lower, "no such command") {
			if kind == "meetme" {
				snap.Meetme = "unsupported"
			} else {
				snap.Confbridge = "unsupported"
			}
			continue
		}
		if strings.Contains(lower, "permission denied") || strings.Contains(lower, "unable to connect") {
			return fail()
		}
		seen = map[string]bool{}
		lines := strings.Split(text, "\n")
		if kind == "meetme" && (text == "No active MeetMe conferences." || text == "") {
			continue
		}
		if kind == "confbridge" {
			if len(lines) < 2 || !strings.HasPrefix(lines[0], "Conference Bridge Name") || strings.Trim(lines[1], "= ") != "" {
				return fail()
			}
			lines = lines[2:]
		}
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			f := strings.Fields(line)
			if kind == "meetme" {
				f = strings.Split(line, "!")
				if len(f) != 6 {
					return fail()
				}
			} else if len(f) != 6 && len(f) != 5 {
				return fail()
			}
			id := activity.ID(f[0])
			if id == "" || seen[id] || len(snap.Conferences) >= activity.Limit {
				return fail()
			}
			seen[id] = true
			n, e := strconv.Atoi(f[1])
			if e != nil || n < 0 || n > activity.Limit {
				return fail()
			}
			label := "ConfBridge"
			if kind == "meetme" {
				label = "MeetMe"
			}
			snap.Conferences = append(snap.Conferences, activity.Conference{ID: id, Type: label, Count: n, MembersComplete: n == 0})
		}
	}
	return EncodeActivity(snap)
}

func EncodeActivity(s activity.Snapshot) ([]collection.Observation, []collection.Diagnostic) {
	var obs []collection.Observation
	add := func(resource string, v any) bool {
		b, e := json.Marshal(v)
		if e != nil || len(b) > 4096 {
			return false
		}
		obs = append(obs, collection.Observation{Key: activity.Key, Resource: resource, Unit: "text", Value: collection.Text(string(b))})
		return true
	}
	manifest := s
	manifest.Channels = nil
	manifest.Bridges = nil
	manifest.Conferences = nil
	if !add("manifest", manifest) {
		return bad("record_limit")
	}
	for i, c := range s.Channels {
		if !add(fmt.Sprintf("channel/%03d", i), c) {
			return bad("record_limit")
		}
	}
	for i, c := range s.Bridges {
		if !add(fmt.Sprintf("bridge/%03d", i), c) {
			return bad("record_limit")
		}
	}
	for i, c := range s.Conferences {
		if !add(fmt.Sprintf("conference/%03d", i), c) {
			return bad("record_limit")
		}
	}
	return obs, nil
}
func DecodeActivity(obs []collection.Observation) (activity.Snapshot, error) {
	var s activity.Snapshot
	seen := map[string]bool{}
	var channels []activity.Channel
	var bridges []activity.Bridge
	var conferences []activity.Conference
	identities := map[string]bool{}
	for _, o := range obs {
		if o.Key != activity.Key || o.Value.Kind != "text" || seen[o.Resource] {
			return s, errors.New("invalid activity observation")
		}
		seen[o.Resource] = true
		switch {
		case o.Resource == "manifest":
			if activity.Decode([]byte(o.Value.Text), &s) != nil || len(s.Channels)+len(s.Bridges)+len(s.Conferences) != 0 {
				return s, errors.New("manifest")
			}
		case strings.HasPrefix(o.Resource, "channel/"):
			var c activity.Channel
			if activity.Decode([]byte(o.Value.Text), &c) != nil || c.ID == "" || activity.ID(c.ID) != c.ID {
				return s, errors.New("channel")
			}
			n, t, p := activity.ChannelName(c.Name)
			if c.Linked != "" || c.Source != "" || !c.First.IsZero() || !c.Updated.IsZero() || c.DurationSeconds < 0 || c.DurationSeconds > 315360000 || n != c.Name || t != c.Technology || p != c.Endpoint || c.State != activity.StateName(c.State) || activity.ID(c.Bridge) != c.Bridge || c.Association != activity.Association(c.Endpoint) {
				return s, errors.New("channel fields")
			}
			if identities["c/"+c.ID] {
				return s, errors.New("duplicate channel")
			}
			identities["c/"+c.ID] = true
			channels = append(channels, c)
		case strings.HasPrefix(o.Resource, "bridge/"):
			var c activity.Bridge
			if activity.Decode([]byte(o.Value.Text), &c) != nil || activity.ID(c.ID) == "" || c.Count < 0 || c.Count > activity.Limit || !c.Updated.IsZero() {
				return s, errors.New("bridge")
			}
			if identities["b/"+c.ID] {
				return s, errors.New("duplicate bridge")
			}
			identities["b/"+c.ID] = true
			bridges = append(bridges, c)
		case strings.HasPrefix(o.Resource, "conference/"):
			var c activity.Conference
			if activity.Decode([]byte(o.Value.Text), &c) != nil || activity.ID(c.ID) == "" || c.Count < 0 || c.Count > activity.Limit || (c.Type != "MeetMe" && c.Type != "ConfBridge") {
				return s, errors.New("conference")
			}
			if identities[c.Type+"/"+c.ID] || len(c.Members) > 0 || c.Bridge != "" || !c.Updated.IsZero() || c.MembersComplete != (c.Count == 0) {
				return s, errors.New("invalid conference")
			}
			identities[c.Type+"/"+c.ID] = true
			conferences = append(conferences, c)
		default:
			return s, errors.New("resource")
		}
	}
	s.Channels, s.Bridges, s.Conferences = channels, bridges, conferences
	if !seen["manifest"] || !activity.Runtime(s.Runtime) || (s.Meetme != "supported" && s.Meetme != "unsupported") || (s.Confbridge != "supported" && s.Confbridge != "unsupported") || len(s.Channels) > activity.Limit || len(s.Bridges) > activity.Limit || len(s.Conferences) > activity.Limit {
		return s, errors.New("incomplete snapshot")
	}
	return s, nil
}
