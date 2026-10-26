package sshcli

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"time"
)

// Credential is a reference in a protected administrator-provisioned catalog.
// No private key, password, or executable SSH option is accepted by the browser.
type Credential struct {
	ID, User, IdentityFile, IdentitySHA256 string
	Enabled                                bool
	ExpiresAt                              time.Time
}

var referencePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func CredentialDigest(c Credential) string { b, _ := json.Marshal(c); return digest(b) }

// ReadCredentials shares NW-007's owner/mode/symlink checks. Read it on every
// approval, so revocation or replacement cannot hide behind a cached profile.
func ReadCredentials(path string) ([]Credential, error) {
	b, err := protectedRead(path, 65536)
	if err != nil {
		return nil, err
	}
	var list []Credential
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&list) != nil || d.Decode(new(any)) != io.EOF || len(list) > 32 {
		return nil, fail(Unsupported)
	}
	seen := map[string]bool{}
	for _, c := range list {
		if !referencePattern.MatchString(c.ID) || seen[c.ID] || !userPattern.MatchString(c.User) || !filepath.IsAbs(c.IdentityFile) || len(c.IdentitySHA256) != 64 {
			return nil, fail(Unsupported)
		}
		seen[c.ID] = true
	}
	return list, nil
}
