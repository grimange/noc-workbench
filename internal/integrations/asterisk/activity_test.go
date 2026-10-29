package asterisk

import (
	"encoding/json"
	activity "noc-workbench/internal/integrations/asteriskactivity"
	"strings"
	"testing"
)

func activityBundle(ch, br, meet, conf string) []byte {
	return []byte("Asterisk 18.26.4-vici\nNW_ACTIVITY_runtime\n" + strings.Repeat("a", 64) + "  -\nNW_ACTIVITY_channels\n" + ch + "\nNW_ACTIVITY_bridges\nBridge-ID                            Chans Type            Technology      Duration\n" + br + "\nNW_ACTIVITY_meetme\n" + meet + "\nNW_ACTIVITY_confbridge\n" + conf + "\nNW_ACTIVITY_runtime_end\n" + strings.Repeat("a", 64) + "  -\nNW_ACTIVITY_END\n")
}

const confHeader = "Conference Bridge Name           Users  Marked Locked Muted\n================================ ====== ====== ====== ====="

func TestActivityActual18EmptyAndPopulated(t *testing.T) {
	for _, full := range []bool{false, true} {
		ch, br, meet, conf := "", "", "", confHeader
		if full {
			ch = "PJSIP/phone-00000001!private-context!private-number!1!Up!Dial!private-appdata!private-caller!private-account!private-peer!3!10!bridge1!1.1\nLocal/private-number@context-00000001;1!c!e!1!Ring!Dial!private!private!a!p!3!1!!1.2"
			br = "bridge1 1 basic simple_bridge 00:00:10"
			meet = "room1!2!1!00:00:10!1!0"
			conf += "\nroom2 3 0 unlocked unmuted"
		}
		obs, ds := Activity(activityBundle(ch, br, meet, conf))
		if len(ds) != 0 {
			t.Fatal(ds)
		}
		s, e := DecodeActivity(obs)
		if e != nil {
			t.Fatal(e)
		}
		if full {
			if len(s.Channels) != 2 || len(s.Conferences) != 2 || s.Channels[0].Endpoint != "phone" || s.Channels[1].Technology != "Local" {
				t.Fatal(s)
			}
		} else if len(s.Channels)+len(s.Conferences)+len(s.Bridges) != 0 {
			t.Fatal(s)
		}
		b, _ := json.Marshal(obs)
		if strings.Contains(string(b), "private") {
			t.Fatal("personal data retained")
		}
	}
}
func TestActivityIncompleteUnsupportedAndMalformed(t *testing.T) {
	valid := activityBundle("", "", "", confHeader)
	for _, b := range [][]byte{nil, valid[:len(valid)-25], activityBundle("bad", "", "", confHeader), activityBundle("", "bad", "", confHeader), activityBundle("", "", "bad", confHeader), activityBundle("", "", "", "permission denied"), []byte(strings.Replace(string(valid), strings.Repeat("a", 64), strings.Repeat("b", 64), 1))} {
		if obs, ds := Activity(b); len(obs) != 0 || len(ds) == 0 {
			t.Fatal("incomplete accepted", string(b))
		}
	}
	obs, ds := Activity(activityBundle("", "", "No such command 'meetme list concise'", "No such command 'confbridge list'"))
	s, e := DecodeActivity(obs)
	if len(ds) > 0 || e != nil || s.Meetme != "unsupported" || s.Confbridge != "unsupported" {
		t.Fatal(s, e, ds)
	}
	obs, _ = Activity(valid)
	manifest := activity.Snapshot{Runtime: strings.Repeat("a", 64), Channels: []activity.Channel{{ID: "injected"}}, Meetme: "supported", Confbridge: "supported"}
	b, _ := json.Marshal(manifest)
	obs[0].Value.Text = string(b)
	if _, e = DecodeActivity(obs); e == nil {
		t.Fatal("embedded rows accepted")
	}
}
