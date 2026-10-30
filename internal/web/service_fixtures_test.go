package web

import (
	"bytes"
	ast "noc-workbench/internal/integrations/asterisk"
	activity "noc-workbench/internal/integrations/asteriskactivity"
	ami "noc-workbench/internal/integrations/asteriskami"
	auth "noc-workbench/internal/integrations/asteriskauth"
	"noc-workbench/internal/integrations/mariadb"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These render-only fixtures never use a repository, collector or live target.
func TestServiceOperationalFixtures(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	base := pageData{Server: serverData{Asterisk: asteriskRegistrationData{Authorized: true, MediaAuthorized: true, AMI: ami.View{Authorized: true, Current: true, State: "Connected"}, Activity: activity.View{Current: true, State: activity.State{Baseline: at, Snapshot: activity.Snapshot{Meetme: "supported", Confbridge: "supported"}}}, Auth: auth.View{Current: true, CheckedAt: at}}, MariaDB: mariaDBData{Authorized: true, Current: true, Readiness: "Ready", State: "Current", Role: "Unknown", Replication: "No local replica channels configured", Sample: &mariadb.Sample{At: at, Snapshot: mariadb.Snapshot{Version: "10.11.example", Metrics: map[string]uint64{"Threads_connected": 12, "Threads_running": 1, "max_connections": 2000}, Replication: "ready"}}}}}
	css, e := os.ReadFile("static/app.css")
	if e != nil {
		t.Fatal(e)
	}
	js, e := os.ReadFile("static/console.js")
	if e != nil {
		t.Fatal(e)
	}
	appJS, e := os.ReadFile("static/app.js")
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"empty", "problems", "stale"} {
		d := base
		switch name {
		case "problems":
			d.Server.Asterisk.Families = []registrationFamily{{Name: "pjsip contacts", Current: true, Snapshot: ast.RegistrationSnapshot{Status: "supported", Rows: []ast.RegistrationRow{{ID: "endpoint-1001", Technology: "PJSIP", Reachability: "Unreachable"}}}}, {Name: "sip registry", Current: true, Snapshot: ast.RegistrationSnapshot{Status: "supported", Rows: []ast.RegistrationRow{{ID: "trunk-example", Technology: "SIP", Registration: "Rejected"}}}}}
			d.Server.Asterisk.Auth = auth.View{Current: true, Failures5: 6, Groups: []auth.Group{{Account: "1001", IP: "192.0.2.8", Repeated: true, Count: 6, Last: at, First: at}, {Account: "1002", IP: "192.0.2.9", Type: "InvalidPassword", Count: 1, Last: at, First: at}, {Type: "InvalidPassword", Count: 1, Last: at, First: at}, {Type: "InvalidPassword", Count: 1, Last: at, First: at}}}
			d.Server.Asterisk.ChannelCount = 1
			d.Server.Asterisk.Activity.Channels = []activity.Channel{{ID: "channel-1", Name: "PJSIP/1001-00000001", Technology: "PJSIP", Endpoint: "1001", State: "Up", First: at, Updated: at, Bridge: "bridge-1", Association: "Verified endpoint definition"}}
			d.Server.Asterisk.Activity.Conferences = []activity.Conference{{ID: "room-1", Type: "ConfBridge", Count: 1, Updated: at}}
			fraction, jitter := uint32(64), uint32(80)
			rtt := float64(12)
			d.Server.Asterisk.Media = []ami.MediaRecord{{Channel: "PJSIP/1001-00000001", Endpoint: "1001", Session: "fixture-session", Sequence: 1, Status: "Current", At: at, Report: ami.MediaReport{Perspective: "remote receiver report about Asterisk transmission", SSRC: "0x00000001", RTTMilliseconds: &rtt, Blocks: []ami.MediaBlock{{FractionLost: &fraction, JitterTimestampUnits: &jitter}}}}}
			second := d.Server.Asterisk.Media[0]
			second.Sequence = 2
			d.Server.Asterisk.Media = append(d.Server.Asterisk.Media, second)
			sample := *base.Server.MariaDB.Sample
			lag := uint64(0)
			delay := uint64(7)
			sample.Snapshot.Channels = []mariadb.Channel{{Name: "healthy", IO: "Yes", SQL: "Yes", Lag: &lag}, {Name: "io-failed", IO: "No", SQL: "Yes"}, {Name: "sql-failed", IO: "Yes", SQL: "No"}, {Name: "delayed", IO: "Yes", SQL: "Yes", Lag: &delay}}
			d.Server.MariaDB.Sample = &sample
			d.Server.MariaDB.Role = "Replica"
			d.Server.MariaDB.Replication = "Configured replica channels"
		case "stale":
			d.Server.Asterisk.AMI.Current = false
			d.Server.Asterisk.AMI.State = "Disconnected"
			d.Server.Asterisk.Activity.Current = false
			d.Server.Asterisk.Auth.Current = false
			d.Server.MariaDB.Current = false
			d.Server.MariaDB.Readiness = "Stale / unavailable"
			d.Server.MariaDB.State = "Historical"
			d.Server.MariaDB.Replication = "Unknown"
		}
		var body bytes.Buffer
		for _, part := range []string{"asterisk-registrations", "mariadb"} {
			if e := pages.ExecuteTemplate(&body, part, d); e != nil {
				t.Fatal(e)
			}
		}
		s := body.String()
		if name == "problems" {
			for _, want := range []string{"Peer/contact unreachable", "Outbound registration Rejected", "Repeated authentication failures", "I/O failure", "SQL/applier failure", "Delayed", "25.00% interval", "80 RTP timestamp units", "12.000 ms"} {
				if !strings.Contains(s, want) {
					t.Errorf("missing fixture %q", want)
				}
			}
		}
		if name == "stale" && strings.Contains(s, `class="database-capacity"`) {
			t.Fatal("stale capacity shown current")
		}
		if dir := os.Getenv("NOC_SERVICE_FIXTURE_DIR"); dir != "" {
			html := `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Synthetic service fixture</title><style>` + string(css) + `</style><main data-console-events="/fixture-events" style="padding:16px;max-width:1200px;margin:auto"><p id="console-live-status" role="status"></p><button data-refresh-display>Refresh Display</button>` + s + `</main><script>window.EventSource=class{addEventListener(){}close(){}};const fixtureHTML=document.documentElement.outerHTML;window.fetch=async()=>({ok:true,text:async()=>fixtureHTML});</script><script>` + string(appJS) + `</script><script>` + string(js) + `</script></html>`
			if e := os.WriteFile(filepath.Join(dir, name+".html"), []byte(html), 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
}
