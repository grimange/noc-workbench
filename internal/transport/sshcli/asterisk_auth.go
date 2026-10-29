package sshcli

import (
	"context"
	_ "embed"
)

//go:embed asterisk_auth_reader.py
var asteriskAuthReader string

type authCursorKey struct{}

// WithAsteriskAuthCursor carries bounded internal cursor metadata over stdin.
// It cannot change the reviewed command or supply a filesystem destination.
func WithAsteriskAuthCursor(ctx context.Context, cursor []byte) context.Context {
	return context.WithValue(ctx, authCursorKey{}, append([]byte(nil), cursor...))
}
