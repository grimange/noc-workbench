package web

import (
	"bytes"
	ast "noc-workbench/internal/integrations/asterisk"
	activity "noc-workbench/internal/integrations/asteriskactivity"
	ami "noc-workbench/internal/integrations/asteriskami"
	auth "noc-workbench/internal/integrations/asteriskauth"
	"noc-workbench/internal/integrations/mariadb"
	"strings"
	"testing"
)

func TestServiceOverviewEvidenceSemantics(t *testing.T) {
	d := asteriskRegistrationData{AMI: ami.View{Current: true, State: "connected"}, Activity: activity.View{Current: true}, Auth: auth.View{Current: true}, ChannelCount: 3}
	d.Families = []registrationFamily{{Name: "pjsip endpoints", Current: true, Snapshot: ast.RegistrationSnapshot{Status: "supported", Rows: []ast.RegistrationRow{{ID: "no-contact", Registration: "No contact observed"}}}}, {Name: "pjsip contacts", Current: true, Snapshot: ast.RegistrationSnapshot{Status: "supported", Rows: []ast.RegistrationRow{{ID: "endpoint", Reachability: "Unreachable"}}}}, {Name: "sip registry", Current: true, Snapshot: ast.RegistrationSnapshot{Status: "supported", Rows: []ast.RegistrationRow{{ID: "trunk", Registration: "Rejected"}}}}}
	d.Auth.Groups = []auth.Group{{Account: "endpoint", IP: "192.0.2.7", Repeated: true}}
	o := d.Overview()
	if len(o.Indicators) != 4 || o.Indicators[1].Value != "2 observed issues" || o.Indicators[2].Value != "3" || len(o.Issues) != 3 {
		t.Fatalf("overview %+v", o)
	}
	d.Auth.Current = false
	d.Activity.Current = false
	for i := range d.Families {
		d.Families[i].Current = false
	}
	o = d.Overview()
	if o.Indicators[1].Value != "Unavailable" || o.Indicators[2].Value != "Unverified" || o.Indicators[3].Value != "Unavailable" || strings.Contains(strings.Join(o.Issues, " "), "Repeated") {
		t.Fatalf("historical presented current %+v", o)
	}
}
func TestDatabaseOverviewCapacityAndReplication(t *testing.T) {
	lag := uint64(0)
	d := mariaDBData{Current: true, Readiness: "Ready", Replication: "Configured channels", Role: "Replica", Sample: &mariadb.Sample{Snapshot: mariadb.Snapshot{Metrics: map[string]uint64{"Threads_connected": 5, "max_connections": 100, "Threads_running": 0}, Channels: []mariadb.Channel{{Name: "healthy", IO: "Yes", SQL: "Yes", Lag: &lag}, {Name: "broken", IO: "No", SQL: "Yes"}}}}}
	o := d.Overview()
	if o.Indicators[1].Value != "5 / 100 (5.0%)" || o.Indicators[2].Value != "0" || len(o.Issues) != 1 || !strings.Contains(o.Issues[0], "Unavailable (NULL)") || d.Capacity() == nil || *d.Capacity() != 5 {
		t.Fatalf("overview %+v", o)
	}
	delete(d.Sample.Snapshot.Metrics, "Threads_running")
	if d.Overview().Indicators[2].Value != "Unavailable" {
		t.Fatal("missing metric became zero")
	}
	d.Current = false
	if d.Capacity() != nil || d.Overview().Indicators[1].Value != "Unavailable" || len(d.Overview().Issues) != 0 {
		t.Fatal("historical promoted")
	}
}
func TestServiceTemplatesConciseEmptyAndDrilldown(t *testing.T) {
	d := pageData{Server: serverData{Asterisk: asteriskRegistrationData{AMI: ami.View{State: "connected", Current: true}, Activity: activity.View{Current: true}, Auth: auth.View{Current: true}}, MariaDB: mariaDBData{Current: true, Role: "Unknown", Replication: "No local replica channels configured", Sample: &mariadb.Sample{Snapshot: mariadb.Snapshot{Replication: "ready"}}}}}
	for _, name := range []string{"asterisk-registrations", "mariadb"} {
		var b bytes.Buffer
		if e := pages.ExecuteTemplate(&b, name, d); e != nil {
			t.Fatal(e)
		}
		s := b.String()
		if strings.Count(s, "<dt>") != 4 {
			t.Fatal(name, "expected four indicators")
		}
		if name == "asterisk-registrations" {
			if !strings.Contains(s, "No active channels") || strings.Contains(s, "Search channels") || strings.Contains(s, "<th>Last report (PHT)</th>") {
				t.Fatal("empty activity/media table")
			}
			if !strings.Contains(s, `<details id="ami-administration"><summary>Advanced AMI connection settings`) {
				t.Fatal("administration not collapsed")
			}
		}
		if name == "mariadb" && (strings.Contains(s, `id="database-replication"`) || !strings.Contains(s, "No local replica channels configured") || !strings.Contains(s, "Monitoring query latency")) {
			t.Fatal("empty replication or latency", s)
		}
	}
}

func TestServiceOverviewBoundedIssuesAndUnknownAttribution(t *testing.T) {
	d := asteriskRegistrationData{AMI: ami.View{Current: true}, Activity: activity.View{Current: true}, Auth: auth.View{Current: true, Groups: []auth.Group{{Repeated: true}}}}
	if !strings.Contains(strings.Join(d.Overview().Issues, " "), "observed source IP Unknown") {
		t.Fatal("unknown source guessed or blank")
	}
	rows := make([]ast.RegistrationRow, 100)
	for i := range rows {
		rows[i] = ast.RegistrationRow{ID: "endpoint", Reachability: "Unreachable"}
	}
	d.Families = []registrationFamily{{Name: "pjsip contacts", Current: true, Snapshot: ast.RegistrationSnapshot{Status: "supported", Rows: rows}}}
	o := d.Overview()
	if len(o.Issues) != 4 || o.MoreIssues != 97 || o.Indicators[1].Value != "100 observed issues" {
		t.Fatalf("unbounded/incorrect issue summary %+v", o)
	}
	for _, tc := range []struct {
		authorized, connected bool
		want                  string
	}{{false, false, "Media statistics unavailable"}, {true, false, "AMI reporting interrupted"}, {true, true, "No RTCP reports retained"}} {
		d.MediaAuthorized = tc.authorized
		d.AMI.Current = tc.connected
		if !strings.Contains(d.MediaSummary(), tc.want) {
			t.Fatal(d.MediaSummary())
		}
	}
}
