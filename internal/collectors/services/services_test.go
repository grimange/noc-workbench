package services

import (
	"noc-workbench/internal/collection"
	"strings"
	"testing"
)

func Fixture() string {
	s := "NW_RUNTIME_1\n"
	for _, id := range IDs {
		support := "linux"
		unit := "loaded"
		active := "running"
		name := map[string]string{"asterisk": "asterisk.service", "database": "mariadb.service", "apache": "apache2.service"}[id]
		if name == "" {
			support = "svn4034"
			unit = "unavailable"
			active = "unavailable"
			name = "unknown"
		}
		s += id + "|present|" + unit + "|" + active + "|observed|" + support + "|" + name + "\n"
	}
	return s + "END\n"
}
func TestRuntimeClassification(t *testing.T) {
	for _, id := range IDs {
		base := Signal{ID: id, Binary: "present", Unit: "loaded", Active: "running", Process: "observed", Support: "linux", UnitName: "unknown"}
		if strings.HasPrefix(id, "AST_") {
			base.Support = "svn4034"
		}
		for _, tc := range []struct{ name, active, process, want string }{{"running", "running", "observed", "Running"}, {"stopped", "stopped", "not_observed", "Stopped"}, {"alternate startup", "stopped", "observed", "Running"}, {"no unit authority", "unavailable", "not_observed", "Unknown"}, {"unit only", "running", "unavailable", "Running"}, {"permission denied", "unavailable", "unavailable", "Unknown"}, {"transitional", "other", "not_observed", "Unknown"}} {
			t.Run(id+"/"+tc.name, func(t *testing.T) {
				s := base
				s.Active = tc.active
				s.Process = tc.process
				if tc.active == "unavailable" {
					s.Unit = "unavailable"
				}
				r := Classify(s)
				if r.Runtime != tc.want {
					t.Fatalf("%+v", r)
				}
			})
		}
	}
}
func TestBoundedPrivateProtocol(t *testing.T) {
	good := Fixture()
	obs, diag := Parse([]byte(good))
	if len(obs) != len(IDs) || len(diag) != 0 {
		t.Fatal(obs, diag)
	}
	for _, o := range obs {
		o.CollectorID = Collector
		o.CollectorVersion = Version
		s, e := Decode(collection.Evidence{Observation: o})
		if e != nil || Classify(s).Runtime != "Running" {
			t.Fatal(s, e)
		}
	}
	for _, bad := range []string{"", strings.Repeat("x", 4097), strings.Replace(good, "END\n", "", 1), strings.Replace(good, "observed", "password=synthetic-secret", 1), strings.Replace(good, "asterisk|", "arbitrary|", 1), strings.Replace(good, "running", "inactive\x00", 1), good + "secret\n", strings.Replace(good, "asterisk.service", "secret.service", 1)} {
		got, d := Parse([]byte(bad))
		if len(got) != 0 || len(d) != 1 || d[0].Code != "parse_error" {
			t.Fatal("malformed output accepted")
		}
		if strings.Contains(d[0].Code, "secret") {
			t.Fatal("raw diagnostic")
		}
	}
}
func TestUnsupportedAndGenericLinux(t *testing.T) {
	s := Signal{ID: "AST_update.pl", Binary: "unknown", Unit: "unavailable", Active: "unavailable", Process: "unavailable", Support: "unsupported", UnitName: "unknown"}
	if r := Classify(s); r.Runtime != "Unsupported" || r.Present != "Unknown" {
		t.Fatal(r)
	}
	s = Signal{ID: "asterisk", Binary: "unknown", Unit: "missing", Active: "unavailable", Process: "not_observed", Support: "linux", UnitName: "unknown"}
	if r := Classify(s); r.Runtime != "Unknown" || r.Present != "Unknown" {
		t.Fatal("missing sources inferred uninstalled", r)
	}
}
