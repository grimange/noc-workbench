package asteriskauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"noc-workbench/internal/collection"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type Repository interface {
	AuthCursors(context.Context, workspace.Principal, sshcli.Target) (map[string]Cursor, error)
	IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error
}
type Executor struct {
	Next       collection.Executor
	Repository Repository
	Clock      func() time.Time
}

func Specs() []collection.Spec {
	return []collection.Spec{{ID: Collector, Version: Version, CommandID: "asterisk.auth.v1", AlternateCommandIDs: []string{"asterisk.auth.helper.v1"}, Parse: ParseBatch, Optional: true}}
}
func (e Executor) Execute(ctx context.Context, p workspace.Principal, t sshcli.Target, id string) (sshcli.Result, error) {
	if id != "asterisk.auth.v1" && id != "asterisk.auth.helper.v1" {
		return e.Next.Execute(ctx, p, t, id)
	}
	started := time.Now().UTC()
	result := sshcli.Result{CommandID: id, StartedAt: started}
	deny := func() (sshcli.Result, error) {
		result.EndedAt = time.Now().UTC()
		return result, &sshcli.Failure{Category: sshcli.PermissionDenied}
	}
	if e.Repository == nil {
		return deny()
	}
	helper := e.Repository.IntegrationAllowed(ctx, p, t, "asterisk_auth_helper") == nil
	if id == "asterisk.auth.helper.v1" && !helper {
		return deny()
	}
	check := func(c context.Context) error {
		for _, cap := range []string{"asterisk", "asterisk_auth"} {
			if err := e.Repository.IntegrationAllowed(c, p, t, cap); err != nil {
				return err
			}
		}
		if helper {
			return e.Repository.IntegrationAllowed(c, p, t, "asterisk_auth_helper")
		}
		return nil
	}
	if check(ctx) != nil {
		return deny()
	}
	cursors, err := e.Repository.AuthCursors(ctx, p, t)
	if err != nil {
		return deny()
	}
	if helper {
		id = "asterisk.auth.helper.v1"
		result.CommandID = id
	}
	ctx = sshcli.WithExecutionCheck(ctx, check)
	// At most two bounded chunks per dispatch; remaining backlog continues next
	// scheduled run. Nothing is acknowledged remotely or before DB commit.
	var batch Batch
	for chunk := 0; chunk < 2; chunk++ {
		input, _ := json.Marshal(cursors)
		raw, err := e.Next.Execute(sshcli.WithAsteriskAuthCursor(ctx, input), p, t, id)
		if err != nil {
			return raw, err
		}
		now := time.Now().UTC()
		if e.Clock != nil {
			now = e.Clock().UTC()
		}
		next, err := Normalize(raw.Stdout, cursors, now)
		if err != nil {
			return result, &sshcli.Failure{Category: sshcli.CommandFailed}
		}
		if chunk == 0 {
			batch = next
		} else if next.Source == batch.Source && next.After.Generation == batch.After.Generation && next.After.Identity == batch.After.Identity {
			batch.After = next.After
			batch.Events = append(batch.Events, next.Events...)
			batch.Bytes += next.Bytes
			batch.Rejected += next.Rejected
			batch.Status = next.Status
			if batch.Rejected > 0 && strings.HasPrefix(batch.Status, "current") {
				batch.Status = "incomplete"
				if batch.After.Gap {
					batch.Status += "_with_gap"
				}
			}
			batch.InspectedAt = next.InspectedAt
		} else {
			break
		}
		if !strings.HasPrefix(next.Status, "backlog") {
			break
		}
		cursors[next.Source] = next.After
	}
	result.Stdout, _ = json.Marshal(batch)
	result.EndedAt = time.Now().UTC()
	return result, nil
}

type wire struct {
	Status, Source, Identity, Data, Prefix, Timezone string
	Generation, Offset, Size                         int64
	Skip, Gap, Rotated, Security                     bool
	ConfigurationIncomplete                          bool `json:"configuration_incomplete"`
	WarningsSupported                                bool `json:"warnings_supported"`
}

func Normalize(raw []byte, cursors map[string]Cursor, now time.Time) (Batch, error) {
	b := Batch{InspectedAt: now, Events: []Event{}}
	var w wire
	if len(raw) > 64*1024 || json.Unmarshal(raw, &w) != nil {
		return b, errors.New("invalid_protocol")
	}
	switch w.Status {
	case "permission_denied", "missing_source", "no_configured_source", "unsupported_configuration", "changed_during_read", "invalid_request":
		b.Status = w.Status
		return b, nil
	case "read":
	default:
		return b, errors.New("invalid_status")
	}
	if !Source(w.Source) || w.Offset < 0 || w.Size < w.Offset || w.Generation < 1 || !fileIdentity.MatchString(w.Identity) {
		return b, errors.New("invalid_source")
	}
	data, err := base64.StdEncoding.DecodeString(w.Data)
	if err != nil || len(data) > ChunkSize || w.Offset+int64(len(data)) > w.Size {
		return b, errors.New("invalid_chunk")
	}
	prefix, err := base64.StdEncoding.DecodeString(w.Prefix)
	if err != nil || len(prefix) != int(min(w.Offset, 64)) {
		return b, errors.New("invalid_anchor")
	}
	b.Source = w.Source
	b.Before = cursors[w.Source]
	b.Security = w.Security
	b.After = Cursor{Identity: w.Identity, Offset: w.Offset, Generation: w.Generation, Gap: w.Gap, Discard: w.Skip}
	consumed := 0
	start := 0
	recognizable := false
	for i, c := range data {
		if c != '\n' {
			continue
		}
		line := string(data[start:i])
		position := w.Offset + int64(start)
		if b.After.Discard {
			b.After.Discard = false
		} else {
			if logPrefix.MatchString(line) {
				recognizable = true
			}
			event, code := ParseLine(line, w.Timezone, now)
			if code != "" {
				b.Rejected++
			}
			if event != nil {
				event.Position = position
				b.Events = append(b.Events, *event)
			}
		}
		consumed = i + 1
		start = i + 1
	}
	if w.Rotated && w.Offset+int64(len(data)) == w.Size && consumed < len(data) {
		// A retained generation cannot complete this final line. Record the missing
		// coverage and move beyond it so the next run can reach the active file.
		consumed = len(data)
		b.After.Discard = false
		b.After.Gap = true
		b.Rejected++
	}
	if len(data)-consumed >= 16384 {
		// Never persist a secret-bearing partial line. Drain oversized lines using a
		// discard flag and an explicit coverage gap, with bounded memory each time.
		consumed = len(data)
		b.After.Discard = true
		b.After.Gap = true
		b.Rejected++
	}
	b.After.Offset += int64(consumed)
	b.Bytes = int64(consumed)
	anchor := append(prefix, data[:consumed]...)
	if len(anchor) > 64 {
		anchor = anchor[len(anchor)-64:]
	}
	hash := sha256.Sum256(anchor)
	b.After.Anchor = hex.EncodeToString(hash[:])
	b.Status = "current"
	if b.After.Offset < w.Size || w.Rotated {
		b.Status = "backlog"
	}
	if b.After.Offset < w.Size && len(data) < ChunkSize {
		b.Status = "incomplete_line"
	}
	if b.Rejected > 0 || w.ConfigurationIncomplete {
		b.Status = "incomplete"
	}
	if len(data) > 0 && consumed > 0 && !recognizable && b.Rejected > 0 {
		b.Status = "unsupported_format"
	}
	if !w.Security && !w.WarningsSupported {
		b.Status = "unsupported_format"
	}
	if b.After.Gap {
		b.Status += "_with_gap"
	}
	return b, nil
}

var fileIdentity = regexp.MustCompile(`^[0-9]{1,20}:[0-9]{1,20}$`)

func Source(s string) bool {
	return s == "security" || s == "security_log" || s == "messages" || s == "full"
}
func ParseBatch(raw []byte) ([]collection.Observation, []collection.Diagnostic) {
	b, err := Decode(raw)
	if err != nil || !ValidBatch(b) {
		return nil, []collection.Diagnostic{{Code: "invalid_auth_batch"}}
	}
	events := b.Events
	b.Events = nil
	data, _ := json.Marshal(b)
	obs := []collection.Observation{{Key: Key, Resource: b.Source, Value: collection.Text(string(data)), Unit: "text"}}
	for i, event := range events {
		v, _ := json.Marshal(event)
		obs = append(obs, collection.Observation{Key: "asterisk.auth.event", Resource: fmt.Sprintf("%s/%03d", b.Source, i), Value: collection.Text(string(v)), Unit: "text"})
	}

	if b.Status != "current" {
		code := strings.TrimSuffix(b.Status, "_with_gap")
		if code == "" || code == "current" {
			code = "coverage_gap"
		}
		return obs, []collection.Diagnostic{{Code: code}}
	}
	return obs, nil
}

// ValidBatch is also checked at the durable transaction boundary, preventing
// secret fields, free-form diagnostics and forged cursor data from persistence.
func ValidBatch(b Batch) bool {
	if b.InspectedAt.IsZero() || len(b.Events) > 512 || b.Bytes < 0 || b.Bytes > 2*ChunkSize || b.Rejected < 0 {
		return false
	}
	switch b.Status {
	case "permission_denied", "missing_source", "no_configured_source", "unsupported_configuration", "changed_during_read", "invalid_request":
		return b.Source == "" && len(b.Events) == 0
	case "current", "backlog", "incomplete_line", "incomplete", "unsupported_format", "current_with_gap", "backlog_with_gap", "incomplete_line_with_gap", "incomplete_with_gap", "unsupported_format_with_gap":
	default:
		return false
	}
	if !Source(b.Source) || !fileIdentity.MatchString(b.After.Identity) || b.After.Offset < 0 || b.After.Generation < 1 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(b.After.Anchor) {
		return false
	}
	if b.Before.Identity != "" {
		if !fileIdentity.MatchString(b.Before.Identity) || b.Before.Generation < 1 || b.Before.Offset < 0 || b.After.Generation < b.Before.Generation {
			return false
		}
		if b.After.Identity == b.Before.Identity && b.After.Generation == b.Before.Generation && b.After.Offset < b.Before.Offset {
			return false
		}
	}
	var last int64 = -1
	for _, e := range b.Events {
		if e.Position <= last || e.Position >= b.After.Offset || e.At.IsZero() || e.At.After(b.InspectedAt.Add(5*time.Minute)) || (e.Account != "" && !identifier.MatchString(e.Account)) || e.Port < 0 || e.Port > 65535 || e.Severity != "authentication_failure" {
			return false
		}
		last = e.Position
		if e.IP != "" {
			ip, _ := address(e.IP, "")
			if ip != e.IP {
				return false
			}
		}
		if e.Technology != "" && e.Technology != "SIP" && e.Technology != "PJSIP" {
			return false
		}
		switch e.Type {
		case "InvalidPassword", "InvalidAccountID", "ChallengeResponseFailed":
			if e.Reason != e.Type {
				return false
			}
		case "SIPRegistrationRejected":
			if e.Reason != "Wrong password" && e.Reason != "No matching peer found" && e.Reason != "Username/auth name mismatch" {
				return false
			}
		case "PJSIPAuthenticationRejected":
			if e.Reason != "Failed to authenticate" && e.Reason != "No matching endpoint found" {
				return false
			}
		default:
			return false
		}
	}
	return true
}
