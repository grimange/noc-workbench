// Package vicidial provides optional, operator-documented installation context.
// V1 is index and navigate: it has no network, credential or collection authority.
package vicidial

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

type Scope struct{ CustomerID, EnvironmentID, ClusterID string }
type Integration struct {
	ID, CustomerID, EnvironmentID, ClusterID    string
	Name, Version, RevisionSource, Notes, Actor string
	Enabled                                     bool
	VerifiedAt                                  *time.Time
	Revision                                    int64
	CreatedAt, UpdatedAt                        time.Time
}
type Repository interface {
	VICIdialIntegration(context.Context, workspace.Principal, Scope) (Integration, error)
	SaveVICIdialIntegration(context.Context, workspace.Principal, Scope, Integration) (Integration, error)
}

const MaxRevisions = 4096

func ValidScope(h Scope) bool {
	return inventory.ValidID(h.CustomerID) && inventory.ValidID(h.EnvironmentID) && inventory.ValidID(h.ClusterID)
}

// Validate uses an explicit clock only to validate operator verification metadata.
// No version is inferred from Linux/Asterisk or the installation's name.
func Validate(v Integration, at time.Time) (Integration, error) {
	f := inventory.FieldErrors{}
	for _, field := range []struct {
		key      string
		value    *string
		max      int
		required bool
	}{
		{"name", &v.Name, 120, true}, {"version", &v.Version, 120, false},
		{"revision_source", &v.RevisionSource, 256, false}, {"notes", &v.Notes, 2048, false},
	} {
		*field.value = strings.TrimSpace(*field.value)
		if (!utf8.ValidString(*field.value)) || len(*field.value) > field.max || (field.required && *field.value == "") || strings.IndexFunc(*field.value, unicode.IsControl) >= 0 {
			f[field.key] = "Enter bounded plain text on one line."
		}
	}
	if v.Revision < 0 || v.Revision >= MaxRevisions {
		f["revision"] = "The revision is invalid or the revision limit has been reached."
	}
	if v.Version == "" && (v.RevisionSource != "" || v.VerifiedAt != nil) {
		f["version"] = "Record a version before adding version provenance; leave all three fields empty for Unknown."
	}
	if v.Version != "" && v.RevisionSource == "" {
		f["revision_source"] = "Document the source of the recorded version."
	}
	if v.VerifiedAt != nil && (v.VerifiedAt.IsZero() || v.VerifiedAt.After(at) || v.VerifiedAt.Year() < 1970) {
		f["verified_at"] = "Use a past or current verification timestamp."
	}
	if len(f) > 0 {
		return v, f
	}
	return v, nil
}
