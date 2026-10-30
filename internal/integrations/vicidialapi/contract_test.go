package vicidialapi

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const versionFixture = "VERSION: 2.14-210|BUILD: 260925-1400|DATE: 2026-10-27 08:00:00|EPOCH: 1793088000|DST: 0|TZ: 0|TZNOW: 0|\n"
const campaignFixture = campaignHeader + "\nSYNTH01|Synthetic campaign|Y|SYNTH|MANUAL|1|DOWN|NEW|60|9||\n"
const agentFixture = agentHeader + "\nagent01|SYNTH01|1001|INCALL|123|synthetic-caller|0|Synthetic Agent|SYNTH|1\nagent02|SYNTH01|1002|PAUSED|0||0|Synthetic Agent Two|SYNTH|1\n"

func code(err error) string {
	var f *Failure
	if errors.As(err, &f) {
		return f.Code
	}
	if err == nil {
		return ""
	}
	return "unexpected"
}
func TestParsers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		op         Operation
		body, want string
		count      int
	}{
		{"version", Version, versionFixture, "", 2},
		{"campaign", Campaigns, campaignFixture, "", 2},
		{"agents", Agents, agentFixture, "", 3},
		{"empty agents", Agents, "ERROR: logged_in_agents NO LOGGED IN AGENTS: synthetic|\n", "insufficient_scope", 0},
		{"empty campaign ambiguous", Campaigns, "ERROR: campaigns_list THIS USER HAS NO VIEWABLE CAMPAIGNS: synthetic|", "permission_denied", 0},
		{"permission", Agents, "ERROR: auth USER DOES NOT HAVE PERMISSION TO USE THIS FUNCTION: synthetic|", "permission_denied", 0},
		{"HTTP200 error", Version, "ERROR: Invalid Username/Password: synthetic|", "authentication_failed", 0},
		{"unknown error", Version, "ERROR: unexpected with secret", "application_error", 0},
		{"missing", Version, "", "invalid_response", 0},
		{"malformed version", Version, "VERSION: nonsense", "invalid_response", 0},
		{"unknown columns", Agents, strings.Replace(agentFixture, "user|", "extra|user|", 1), "unsupported_response", 0},
		{"wrong campaign", Agents, strings.ReplaceAll(agentFixture, "SYNTH01", "OTHER01"), "invalid_response", 0},
		{"duplicate agent", Agents, agentFixture + strings.Split(agentFixture, "\n")[1] + "\n", "invalid_response", 0},
		{"unsupported status", Agents, strings.ReplaceAll(agentFixture, "INCALL", "NEWSTATUS"), "unsupported_status", 0},
		{"oversize", Version, strings.Repeat("x", MaxResponse+1), "invalid_response", 0},
		{"invalid encoding", Version, string([]byte{255}), "invalid_response", 0},
		{"control", Version, versionFixture + "\x00", "invalid_response", 0},
		{"write operation", Operation("add_lead"), versionFixture, "unsupported_function", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs, err := Parse(tc.op, []byte(tc.body), "SYNTH01")
			if code(err) != tc.want || len(obs) != tc.count {
				t.Fatalf("count=%d error=%v", len(obs), err)
			}
			again, next := Parse(tc.op, []byte(tc.body), "SYNTH01")
			if !reflect.DeepEqual(obs, again) || code(err) != code(next) {
				t.Fatal("not deterministic")
			}
			for _, o := range obs {
				if strings.Contains(o.Value.Text, "Synthetic") || o.Resource != "" {
					t.Fatal("sensitive data retained")
				}
			}
		})
	}
}
func TestAggregateSemantics(t *testing.T) {
	obs, err := Parse(Agents, []byte(agentFixture), "SYNTH01")
	if err != nil || obs[0].Value.Integer != 2 || obs[1].Value.Integer != 1 || obs[2].Value.Integer != 1 {
		t.Fatal(obs, err)
	}
	if _, err := Parse(Agents, []byte(agentFixture), "SYNTH01|OTHER"); code(err) != "invalid_scope" {
		t.Fatal(err)
	}
	if _, err := Parse(Campaigns, []byte(strings.Replace(campaignFixture, "|Y|", "|0|", 1)), "SYNTH01"); code(err) != "invalid_response" {
		t.Fatal(err)
	}
	if _, err := Parse(Agents, []byte(agentHeader+"\n"+strings.Repeat(strings.Split(agentFixture, "\n")[1]+"\n", MaxRows+1)), "SYNTH01"); code(err) != "invalid_response" {
		t.Fatal(err)
	}
}

func TestInstalledRevisionContract(t *testing.T) {
	empty := "ERROR: logged_in_agents NO LOGGED IN AGENTS: synthetic|\n"
	for _, tc := range []struct {
		version, build, body, want string
		count                      int
	}{
		{InstalledVersion, InstalledBuild, empty, "", 3},
		{DocumentedVersion, DocumentedBuild, empty, "insufficient_scope", 0},
		{InstalledVersion, DocumentedBuild, empty, "unsupported_revision", 0},
		{"2.14-212", InstalledBuild, empty, "unsupported_revision", 0},
		{InstalledVersion, InstalledBuild, empty + "extra", "application_error", 0},
		{InstalledVersion, InstalledBuild, strings.Replace(empty, "synthetic|", "synthetic|other", 1), "insufficient_scope", 0},
		{InstalledVersion, InstalledBuild, empty + "\x00", "invalid_response", 0},
		{InstalledVersion, InstalledBuild, empty + "\v", "invalid_response", 0},
		{InstalledVersion, InstalledBuild, empty + "\f", "invalid_response", 0},
		{InstalledVersion, InstalledBuild, strings.Repeat(" ", MaxResponse) + empty, "invalid_response", 0},
		{InstalledVersion, InstalledBuild, "ERROR: logged_in_agents USER DOES NOT HAVE PERMISSION TO USE THIS FUNCTION: synthetic|", "permission_denied", 0},
		{InstalledVersion, InstalledBuild, "ERROR: Login incorrect, please try again", "authentication_failed", 0},
	} {
		obs, err := ParseForContract(Agents, []byte(tc.body), "SYNTH01", tc.version, tc.build)
		if code(err) != tc.want || len(obs) != tc.count {
			t.Fatalf("%s/%s count%d error%v", tc.version, tc.build, len(obs), err)
		}
		for _, o := range obs {
			if !strings.Contains(o.Key, "visible_") || o.Value.Integer != 0 {
				t.Fatal("invented campaign-wide or nonzero count")
			}
		}
	}
	for _, op := range []Operation{Version, Campaigns, Agents} {
		body := map[Operation]string{Version: strings.ReplaceAll(strings.ReplaceAll(versionFixture, DocumentedVersion, InstalledVersion), DocumentedBuild, InstalledBuild), Campaigns: campaignFixture, Agents: agentFixture}[op]
		if _, err := ParseForContract(op, []byte(body), "SYNTH01", InstalledVersion, InstalledBuild); err != nil {
			t.Fatal(op, err)
		}
	}
}
