package web

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestCompactMonitoringRetainsIntervalAndEvidenceStates(t *testing.T) {
	for _, interval := range []int{60, 300} {
		for _, state := range []string{"Current", "Stale", "Unknown"} {
			d := pageData{}
			d.Server.Runtime.Enabled = true
			d.Server.Runtime.Profile.Interval = interval
			d.Server.Resources.Current = state == "Current"
			d.Server.Resources.State = state
			d.Server.View.Issues = "Unknown"
			var out bytes.Buffer
			if err := pages.ExecuteTemplate(&out, "server.html", d); err != nil {
				t.Fatal(err)
			}
			html := out.String()
			if !strings.Contains(html, fmt.Sprintf("%d-second target", interval)) {
				t.Fatal("Configured interval missing")
			}
			want := map[string]string{"Current": "current", "Stale": "stale", "Unknown": "unavailable"}[state]
			if !strings.Contains(html, "Evidence: "+want) {
				t.Fatal("Evidence state lost", state)
			}
			if strings.Contains(html, "<dt>Service issues</dt>") {
				t.Fatal("Unknown service issues asserted")
			}
		}
	}
}
