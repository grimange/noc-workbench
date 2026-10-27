package vicidial

import (
	"strings"
	"testing"
	"time"
)

func TestValidateMetadata(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	past := at.Add(-time.Hour)
	future := at.Add(time.Nanosecond)
	zero := time.Time{}
	for _, tc := range []struct {
		name  string
		v     Integration
		valid bool
	}{
		{"unknown", Integration{Name: " Synthetic installation "}, true},
		{"known provenance", Integration{Name: "Synthetic", Version: "2.14", RevisionSource: "Operator lab record", VerifiedAt: &past}, true},
		{"exact timestamp", Integration{Name: "Synthetic", Version: "2.14", RevisionSource: "Operator", VerifiedAt: &at}, true},
		{"missing name", Integration{}, false},
		{"version needs source", Integration{Name: "Synthetic", Version: "2.14"}, false},
		{"source needs version", Integration{Name: "Synthetic", RevisionSource: "Unknown"}, false},
		{"timestamp needs version", Integration{Name: "Synthetic", VerifiedAt: &past}, false},
		{"future verification", Integration{Name: "Synthetic", Version: "2.14", RevisionSource: "Operator", VerifiedAt: &future}, false},
		{"zero verification", Integration{Name: "Synthetic", Version: "2.14", RevisionSource: "Operator", VerifiedAt: &zero}, false},
		{"control", Integration{Name: "Synthetic\ninstallation"}, false},
		{"oversized", Integration{Name: strings.Repeat("x", 121)}, false},
		{"invalid unicode", Integration{Name: string([]byte{0xff})}, false},
		{"negative revision", Integration{Name: "Synthetic", Revision: -1}, false},
		{"bounded revisions", Integration{Name: "Synthetic", Revision: MaxRevisions}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, e := Validate(tc.v, at)
			if (e == nil) != tc.valid {
				t.Fatalf("valid=%t error=%v", tc.valid, e)
			}
			if e == nil && v.Name != strings.TrimSpace(tc.v.Name) {
				t.Fatal("name not normalized")
			}
		})
	}
}
