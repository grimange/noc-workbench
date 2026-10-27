package vicidialdiscovery

import (
	"encoding/json"
	"noc-workbench/internal/collection"
	"reflect"
	"strings"
	"testing"
	"time"
)

const allInOne = `NW_VICIDIAL_DISCOVERY_1
vbox=12.0.2
svn=4034
app_version=2.14-968a
identity=matched
web=matched
dialer=matched
apache=2.4.66
asterisk=18.26.4
database=10.11.15
config=present
server_ip=192.0.2.10
db_ip=192.0.2.10
config_port=3306
db_name=asterisk
observed_port=3306
registry=available
registry_row=192.0.2.10|Web|-
registry_row=192.0.2.10|Telephony|-
registry_row=192.0.2.10|Database|Primary
replica=none
primary_streams=0
archive_alias=missing
END
`

func evidence(t *testing.T, raw string) collection.Evidence {
	t.Helper()
	obs, d := Parse([]byte(raw))
	if len(obs) != 1 || len(d) != 0 {
		t.Fatalf("parse failed: %v", d)
	}
	o := obs[0]
	o.AssetID = "synthetic-asset"
	o.SubjectType = "asset"
	o.CollectorID = Collector
	o.CollectorVersion = Version
	o.Quality = "valid"
	o.ObservedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	o.ReceivedAt = o.ObservedAt.Add(time.Second)
	return collection.Evidence{ID: "synthetic-observation", RunID: "synthetic-run", Observation: o}
}
func TestClassifications(t *testing.T) {
	removeConfig := func(state string) string {
		raw := strings.ReplaceAll(allInOne, "config=present", "config="+state)
		for _, line := range []string{"server_ip=192.0.2.10", "db_ip=192.0.2.10", "config_port=3306", "db_name=asterisk"} {
			raw = strings.ReplaceAll(raw, line+"\n", "")
		}
		return raw
	}
	noRegistry := func() string {
		raw := allInOne
		for _, line := range []string{"registry_row=192.0.2.10|Web|-", "registry_row=192.0.2.10|Telephony|-", "registry_row=192.0.2.10|Database|Primary", "observed_port=3306"} {
			raw = strings.ReplaceAll(raw, line+"\n", "")
		}
		return strings.ReplaceAll(raw, "registry=available", "registry=unavailable")
	}
	for _, tc := range []struct{ name, raw, install, topology, web, tel, primary, replica, archive string }{
		{"standalone", allInOne, "Confirmed", "Standalone", "Confirmed", "Confirmed", "Candidate", "Unknown", "Unknown"},
		{"cluster", strings.ReplaceAll(allInOne, "END\n", "registry_row=192.0.2.11|Telephony|-\nEND\n"), "Confirmed", "Cluster Member", "Confirmed", "Confirmed", "Candidate", "Unknown", "Unknown"},
		{"web-only", strings.ReplaceAll(strings.ReplaceAll(allInOne, "registry_row=192.0.2.10|Telephony|-\n", ""), "dialer=matched", "dialer=missing"), "Confirmed", "deployment", "Confirmed", "Candidate", "Candidate", "Unknown", "Unknown"},
		{"telephony-only", strings.ReplaceAll(strings.ReplaceAll(allInOne, "registry_row=192.0.2.10|Web|-\n", ""), "web=matched", "web=missing"), "Confirmed", "deployment", "Unknown", "Confirmed", "Candidate", "Unknown", "Unknown"},
		{"missing-config", removeConfig("missing"), "Confirmed", "deployment", "Candidate", "Candidate", "Unknown", "Unknown", "Unknown"},
		{"permission-denied", removeConfig("unavailable"), "Confirmed", "deployment", "Candidate", "Candidate", "Unknown", "Unknown", "Unknown"},
		{"unsupported", strings.ReplaceAll(allInOne, "vbox=12.0.2", "vbox=13.0.0"), "Candidate", "deployment", "Candidate", "Candidate", "Candidate", "Unknown", "Unknown"},
		{"contradictory", strings.ReplaceAll(allInOne, "dialer=matched", "dialer=different"), "Candidate", "deployment", "Candidate", "Candidate", "Candidate", "Unknown", "Unknown"},
		{"remote-db-unbound", strings.ReplaceAll(allInOne, "db_ip=192.0.2.10", "db_ip=192.0.2.20"), "Confirmed", "deployment", "Candidate", "Candidate", "Unknown", "Unknown", "Unknown"},
		{"db-unknown-topology", strings.ReplaceAll(allInOne, "|Database|Primary", "|Database|Unknown"), "Confirmed", "deployment", "Confirmed", "Confirmed", "Unknown", "Unknown", "Unknown"},
		{"alias-only", strings.ReplaceAll(allInOne, "archive_alias=missing", "archive_alias=configured"), "Confirmed", "Standalone", "Confirmed", "Confirmed", "Candidate", "Unknown", "Candidate"},
		{"identity-unverified", strings.ReplaceAll(allInOne, "identity=matched", "identity=unavailable"), "Confirmed", "deployment", "Candidate", "Candidate", "Unknown", "Unknown", "Unknown"},
		{"replica-configured-only", strings.ReplaceAll(allInOne, "|Database|Primary", "|Database|Replica"), "Confirmed", "deployment", "Confirmed", "Confirmed", "Unknown", "Candidate", "Unknown"},
		{"wrong-port", strings.ReplaceAll(allInOne, "observed_port=3306", "observed_port=3307"), "Confirmed", "deployment", "Candidate", "Candidate", "Unknown", "Unknown", "Unknown"},
		{"unsupported-hostname", strings.ReplaceAll(allInOne, "db_ip=192.0.2.10", "db_ip=unsupported"), "Confirmed", "deployment", "Candidate", "Candidate", "Unknown", "Unknown", "Unknown"},
		{"components-no-topology", noRegistry(), "Confirmed", "deployment", "Candidate", "Candidate", "Unknown", "Unknown", "Unknown"},
		{"primary", strings.ReplaceAll(allInOne, "primary_streams=0", "primary_streams=1"), "Confirmed", "deployment", "Confirmed", "Confirmed", "Confirmed", "Unknown", "Unknown"},
		{"replica", strings.ReplaceAll(strings.ReplaceAll(allInOne, "|Database|Primary", "|Database|Replica"), "replica=none", "replica=running"), "Confirmed", "deployment", "Confirmed", "Confirmed", "Unknown", "Confirmed", "Unknown"},
		{"database-conflict", strings.ReplaceAll(allInOne, "replica=none", "replica=running"), "Confirmed", "deployment", "Confirmed", "Confirmed", "Unknown", "Unknown", "Unknown"},
		{"archive", strings.ReplaceAll(strings.ReplaceAll(allInOne, "archive_alias=missing", "archive_alias=configured"), "END\n", "registry_row=192.0.2.10|Archive|-\nEND\n"), "Confirmed", "Standalone", "Confirmed", "Confirmed", "Candidate", "Unknown", "Confirmed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := evidence(t, tc.raw)
			r := Evaluate(e, e.ReceivedAt, "fresh", true)
			got := []string{r.Installation.State, r.Deployment.ID}
			want := []string{tc.install, tc.topology}
			for _, v := range r.Roles {
				got = append(got, v.State)
			}
			want = append(want, tc.web, tc.tel, tc.primary, tc.replica, tc.archive)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v want %v: %+v", got, want, r)
			}
			if !reflect.DeepEqual(r, Evaluate(e, e.ReceivedAt, "fresh", true)) {
				t.Fatal("nondeterminism")
			}
		})
	}
}
func TestGenericLinuxAndUnavailableAreDifferent(t *testing.T) {
	raw := "NW_VICIDIAL_DISCOVERY_1\nvbox=unavailable\nsvn=unavailable\napp_version=unavailable\nidentity=unavailable\nweb=missing\ndialer=missing\napache=missing\nasterisk=missing\ndatabase=missing\nconfig=missing\nregistry=unavailable\nreplica=unavailable\nprimary_streams=unavailable\narchive_alias=missing\nEND\n"
	e := evidence(t, raw)
	if r := Evaluate(e, e.ReceivedAt, "fresh", true); r.Installation.State != "Not detected" {
		t.Fatal(r)
	}
	e = evidence(t, strings.ReplaceAll(raw, "web=missing", "web=unavailable"))
	if r := Evaluate(e, e.ReceivedAt, "fresh", true); r.Installation.State != "Unknown" {
		t.Fatal(r)
	}
}
func TestHistoricalAndTrust(t *testing.T) {
	e := evidence(t, allInOne)
	r := Evaluate(e, e.ReceivedAt.Add(48*time.Hour), "stale", true)
	if r.Installation.State != "Confirmed" || r.Freshness != "stale" || r.ObservedAt != e.ObservedAt {
		t.Fatal(r)
	}
	for _, state := range []string{"changed-host-key", "revoked-credential", "stale-endpoint"} {
		t.Run(state, func(t *testing.T) {
			r := Evaluate(e, e.ReceivedAt, "fresh", false)
			if r.Installation.State != "Unknown" || r.Deployment.State != "Unknown" {
				t.Fatal(r)
			}
		})
	}
	r = Evaluate(e, e.ObservedAt.Add(-time.Second), "fresh", true)
	if r.Installation.State != "Unknown" {
		t.Fatal("future evidence accepted")
	}
}
func TestMalformedAndSensitiveData(t *testing.T) {
	for _, raw := range []string{"", strings.Repeat("x", 8193), strings.ReplaceAll(allInOne, "END\n", "password=synthetic-secret\nEND\n"), strings.ReplaceAll(allInOne, "server_ip=192.0.2.10", "server_ip=synthetic-secret"), strings.ReplaceAll(allInOne, "svn=4034", "svn=4034\nsvn=4035"), strings.ReplaceAll(allInOne, "END\n", "registry_row=192.0.2.10|Web|-\nEND\n"), strings.TrimSuffix(allInOne, "END\n")} {
		o, d := Parse([]byte(raw))
		if len(o) != 0 || len(d) != 1 || d[0].Code != "parse_error" {
			t.Fatal("malformed output accepted or leaked")
		}
	}
	e := evidence(t, strings.ReplaceAll(allInOne, "END\n", "registry_row=192.0.2.11|Telephony|-\nEND\n"))
	if strings.Contains(e.Value.Text, "192.0.2.") {
		t.Fatal("addresses retained")
	}
	var s Snapshot
	if json.Unmarshal([]byte(e.Value.Text), &s) != nil || len(s.Peers) != 1 {
		t.Fatal("missing minimized candidate relationship")
	}
	for _, v := range []string{e.Value.Text + " {}", `{"Web":"matched"}`, strings.ReplaceAll(e.Value.Text, `"RegistryServers":2`, `"RegistryServers":99`)} {
		bad := e
		bad.Value = collection.Text(v)
		if r := Evaluate(bad, e.ReceivedAt, "fresh", true); r.Installation.State != "Unknown" {
			t.Fatal("invalid stored envelope accepted")
		}
	}
}
