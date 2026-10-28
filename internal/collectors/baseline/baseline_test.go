package baseline

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

const fixture = "NW_BASELINE_1\ncpu|25.000000\nprocess|42|asterisk|12.500000|1024\nprocess|56|perl|1.500000|2048\nprocess_status|sampled_up_to_4096\npage_bytes|4096\nswap_total|2048\nswap_free|1024\npressure|1.25\nunit|asterisk.service|loaded|inactive|dead\nunit|cron.service|loaded|active|running\nunit|oneshot.service|loaded|active|exited\nunits_status|observed\nunit_file|asterisk.service|enabled\nunit_file|unloaded.service|disabled\nfiles_status|observed\njob|system cron|* * * * *|AST_update.pl\njob|user cron|0 * * * *|command withheld\ncron_status|user_cron_unavailable_or_observed\ntimers_status|unavailable\nEND\n"

func TestParse(t *testing.T) {
	a, d := Parse([]byte(fixture))
	if len(d) != 0 || len(a) != 54 {
		t.Fatalf("observations %d diagnostic %v", len(a), d)
	}
	b, _ := Parse([]byte(fixture))
	if !reflect.DeepEqual(a, b) {
		t.Fatal("nondeterministic")
	}
	for _, o := range a {
		switch o.Key {
		case Prefix + "cpu_percent":
			if o.Value.Number != 25 {
				t.Fatal(o)
			}
		case Prefix + "processes":
			var p []Process
			json.Unmarshal([]byte(o.Value.Text), &p)
			if len(p) != 2 || p[0].RSS != 4194304 {
				t.Fatal(p)
			}
		case Prefix + "units":
			if o.Resource == "00" {
				var u []Unit
				json.Unmarshal([]byte(o.Value.Text), &u)
				if len(u) != 4 || u[0].Active != "inactive" || u[2].Sub != "exited" || u[3].Active != "unknown" {
					t.Fatal(u)
				}
			}
		}
	}
}
func TestMalformedNeverRetainsRaw(t *testing.T) {
	for _, s := range []string{strings.Repeat("x", 65537), strings.Replace(fixture, "cpu|25.000000", "cpu|NaN", 1), strings.Replace(fixture, "asterisk|12.5", "password=secret|12.5", 1), strings.TrimSuffix(fixture, "END\n"), strings.Replace(fixture, "command withheld", "password=secret", 1), strings.Replace(fixture, "page_bytes|4096", "page_bytes|0", 1), strings.Replace(fixture, "units_status|observed", "units_status|observed\nunits_status|observed", 1)} {
		o, d := Parse([]byte(s))
		if len(o) != 0 || len(d) != 1 || d[0].Code != "malformed_output" {
			t.Fatalf("unsafe malformed response %d %v", len(o), d)
		}
	}
}
func TestEmptyPagesClearOldIdentities(t *testing.T) {
	s := strings.ReplaceAll(fixture, "process|42|asterisk|12.500000|1024\n", "")
	o, d := Parse([]byte(s))
	if len(d) > 0 {
		t.Fatal(d)
	}
	for _, v := range o {
		if v.Key == Prefix+"units" && v.Resource == "31" && v.Value.Text != "[]" {
			t.Fatal(v)
		}
	}
}

func TestLocalOutput(t *testing.T) {
	path := os.Getenv("NOC_BASELINE_OUTPUT")
	if path == "" {
		t.Skip("local read-only output not requested")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	o, d := Parse(b)
	if len(d) > 0 || len(o) < 50 {
		t.Fatalf("local parsing %d %v", len(o), d)
	}
}

func TestCronNamesAndTimerProperties(t *testing.T) {
	for _, job := range []string{"job|system cron|0 9 * JAN MON|command withheld", "job|user cron|@daily|command withheld", "job|systemd timer|example.timer| TimersCalendar={ OnCalendar=*-*-* 00:00:00 ; next_elapse=Wed 2026-10-28 00:00:00 UTC } ActiveState=active", "job|systemd timer|example.timer| TimersMonotonic={ OnBootUSec=15min ; next_elapse=1h } ActiveState=active"} {
		if _, d := Parse([]byte(strings.Replace(fixture, "timers_status|unavailable", job+"\ntimers_status|observed", 1))); len(d) != 0 {
			t.Fatalf("supported job rejected: %s %v", job, d)
		}
	}
	for _, properties := range []string{"password=secret", "UnknownProperty=123 ActiveState=active", "TimersCalendar={ OnCalendar=password } ActiveState=active", "ActiveState=secret"} {
		o, d := Parse([]byte(strings.Replace(fixture, "timers_status|unavailable", "job|systemd timer|example.timer|"+properties+"\ntimers_status|observed", 1)))
		if len(o) != 0 || len(d) != 1 || d[0].Code != "malformed_output" {
			t.Fatal("unrestricted timer text retained")
		}
	}
}
