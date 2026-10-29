package asteriskauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
	"testing"
	"time"
)

type grants map[string]bool

func (g grants) IntegrationAllowed(_ context.Context, _ workspace.Principal, _ sshcli.Target, name string) error {
	if !g[name] {
		return workspace.ErrDenied
	}
	return nil
}
func (g grants) AuthCursors(context.Context, workspace.Principal, sshcli.Target) (map[string]Cursor, error) {
	return map[string]Cursor{}, nil
}

type deniedApproval struct{ t *testing.T }

func (a deniedApproval) Approve(context.Context, workspace.Principal, sshcli.Target, workspace.Permission) (sshcli.Profile, error) {
	a.t.Error("revoked grant reached SSH approval")
	return sshcli.Profile{}, workspace.ErrDenied
}

type revokeNext struct {
	g    grants
	name string
	next *sshcli.Executor
}

func (r revokeNext) Execute(c context.Context, p workspace.Principal, t sshcli.Target, id string) (sshcli.Result, error) {
	r.g[r.name] = false
	return r.next.Execute(c, p, t, id)
}
func TestLogAuthorityRecheckedAtTransport(t *testing.T) {
	for _, cap := range []string{"asterisk", "asterisk_auth", "asterisk_auth_helper"} {
		t.Run(cap, func(t *testing.T) {
			g := grants{"asterisk": true, "asterisk_auth": true, "asterisk_auth_helper": true}
			transport, _ := sshcli.New(deniedApproval{t})
			id := "11111111-1111-4111-8111-111111111111"
			target := sshcli.Target{AssetID: id, EndpointID: id, ProfileID: id, ProfileVersion: 1}
			_, err := (Executor{Next: revokeNext{g, cap, transport}, Repository: g}).Execute(context.Background(), workspace.Principal{ID: workspace.OperatorID}, target, "asterisk.auth.v1")
			var failure *sshcli.Failure
			if !errors.As(err, &failure) || failure.Category != sshcli.PermissionDenied {
				t.Fatal(err)
			}
		})
	}
}

type cursorRepository struct {
	grants
	cursors map[string]Cursor
}

func (r *cursorRepository) AuthCursors(context.Context, workspace.Principal, sshcli.Target) (map[string]Cursor, error) {
	return r.cursors, nil
}

type chunks struct {
	t             *testing.T
	repo          *cursorRepository
	data          []byte
	offset, calls int
	transition    bool
}

func (x *chunks) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, id string) (sshcli.Result, error) {
	x.calls++
	if x.calls > 2 {
		x.t.Fatal("unbounded reads")
	}
	if x.calls == 2 && x.repo.cursors["security"].Offset != int64(x.offset) {
		x.t.Fatal("second read did not advance transient cursor")
	}
	end := min(len(x.data), x.offset+ChunkSize)
	prefix := x.data[max(0, x.offset-64):x.offset]
	w := wire{Status: "read", Source: "security", Identity: "1:2", Generation: 1, Offset: int64(x.offset), Size: int64(len(x.data)), Data: base64.StdEncoding.EncodeToString(x.data[x.offset:end]), Prefix: base64.StdEncoding.EncodeToString(prefix), Security: true, Timezone: "+0000"}
	if x.transition {
		w.Rotated = x.calls == 1
		if x.calls == 2 {
			w.Identity = "1:3"
			w.Generation = 2
			w.Offset = 0
			w.Prefix = ""
			w.Size = int64(len(x.data))
			w.Data = base64.StdEncoding.EncodeToString(x.data)
		}
	}
	raw, _ := json.Marshal(w)
	last := bytes.LastIndexByte(x.data[x.offset:end], '\n')
	if last >= 0 {
		x.offset += last + 1
	}
	return sshcli.Result{CommandID: id, Stdout: raw}, nil
}
func TestBoundedMultipleChunksAndGenerationTransition(t *testing.T) {
	for _, transition := range []bool{false, true} {
		t.Run(fmt.Sprint(transition), func(t *testing.T) {
			repo := &cursorRepository{grants: grants{"asterisk": true, "asterisk_auth": true}, cursors: map[string]Cursor{}}
			count := 300
			if transition {
				count = 1
			}
			data := []byte(strings.Repeat(securityLine("InvalidPassword", "100", "IPV4/UDP/192.0.2.1/5060")+"\n", count))
			next := &chunks{t: t, repo: repo, data: data, transition: transition}
			raw, e := (Executor{Next: next, Repository: repo, Clock: func() time.Time { return testNow }}).Execute(context.Background(), workspace.Principal{}, sshcli.Target{}, "asterisk.auth.v1")
			if e != nil {
				t.Fatal(e)
			}
			batch, e := Decode(raw.Stdout)
			if e != nil || !ValidBatch(batch) || next.calls != 2 {
				t.Fatal(batch, e, next.calls)
			}
			if transition {
				if batch.After.Identity != "1:2" || len(batch.Events) != 1 {
					t.Fatal("mixed generation", batch)
				}
			} else {
				if batch.Bytes <= ChunkSize || batch.Bytes > 2*ChunkSize || batch.Status != "backlog" || batch.After.Offset != int64(next.offset) || len(batch.Events) < 2 {
					t.Fatal(batch)
				}
			}
		})
	}
}
