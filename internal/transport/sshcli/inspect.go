package sshcli

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"noc-workbench/internal/workspace"
)

type Candidate struct{ Key, Fingerprint string }

// Inspect is explicitly authorized network inspection, never enrollment or
// trust establishment. Candidates MUST be compared with independent evidence.
// It uses a pinned address and does not read or change personal SSH files.
func (e *Executor) Inspect(ctx context.Context, actor workspace.Principal, t Target) ([]Candidate, error) {
	ctx, cancel := context.WithTimeout(ctx, min(5*time.Second, e.limits.TotalTimeout))
	defer cancel()
	release, err := e.acquire(ctx, t.AssetID)
	if err != nil {
		return nil, contextFailure(ctx)
	}
	defer release()
	p, err := e.approval.Approve(ctx, actor, t, ProfileUse)
	if err != nil {
		if ctx.Err() != nil {
			return nil, contextFailure(ctx)
		}
		return nil, fail(PermissionDenied)
	}
	if err = validProfile(p, t); err != nil {
		return nil, err
	}
	if err = e.resolve(ctx, p); err != nil {
		return nil, err
	}
	output, _, _, err := run(ctx, "/usr/bin/ssh-keyscan", []string{"-T", "5", "-p", strconv.Itoa(int(p.Port)), "-t", "ed25519,ecdsa,rsa", p.Address}, min(64*1024, e.limits.OutputBytes))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var result []Candidate
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return nil, fail(Unsupported)
		}
		key := fields[1] + " " + fields[2]
		fp, err := Fingerprint(key)
		if err != nil {
			return nil, err
		}
		if !seen[fp] {
			seen[fp] = true
			result = append(result, Candidate{key, fp})
		}
	}
	if len(result) == 0 {
		return nil, fail(UnknownKey)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Fingerprint < result[j].Fingerprint })
	return result, nil
}
