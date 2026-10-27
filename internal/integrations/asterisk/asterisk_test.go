package asterisk

import (
	"context"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"reflect"
	"strings"
	"testing"
	"time"
)

const runtimeVersion = "Asterisk 20.20.1 built by synthetic @ example.invalid on a x86_64 running Linux on 2026-01-01\n"

func framed(s string) []byte { return []byte(runtimeVersion + "\nNW_ASTERISK_DATA\n" + s) }
func TestParsers(t *testing.T) {
	tests := []struct {
		name  string
		p     collection.Parser
		input []byte
		key   string
		n     uint64
		code  string
	}{
		{"identity", Identity, []byte(runtimeVersion), "asterisk.version", 0, ""},
		{"channels", Channels, framed("0 active channels\n0 active calls\n0 calls processed\n"), "asterisk.channels.active", 0, ""},
		{"channels singular", Channels, framed("1 active channel\n1 active call\n2 calls processed"), "asterisk.channels.active", 1, ""},
		{"channels not calls", Channels, framed("20 active channels\n10 active calls\n30 calls processed"), "asterisk.channels.active", 20, ""},
		{"modules absent", Modules, framed("Module Description Use Count Status Support Level\n0 modules loaded"), "asterisk.modules.pjsip.available", 0, ""},
		{"modules present", Modules, framed("Module Description Use Count Status Support Level\nres_pjsip.so Basic SIP resource 1 Running core\nchan_pjsip.so PJSIP Channel Driver 0 Running core\n2 modules loaded"), "asterisk.modules.pjsip.available", 1, ""},
		{"empty registrations", PJSIP, framed("No objects found."), "asterisk.pjsip.registrations.count", 0, ""},
		{"registration aggregate", PJSIP, framed(" <Registration/ServerURI> <Auth> <Status>\n synthetic/sip:example.invalid auth Registered\nObjects found: 1"), "asterisk.pjsip.registrations.count", 1, ""},
		{"missing", Identity, []byte("NW_ASTERISK_NOT_INSTALLED\n"), "", 0, "not_installed"},
		{"socket denied", Identity, []byte("Unable to connect to remote asterisk (Permission denied)"), "", 0, "permission_denied"},
		{"socket unavailable", Identity, []byte("Unable to connect to remote asterisk (does /run/asterisk/asterisk.ctl exist?)"), "", 0, "cli_unavailable"},
		{"missing command", PJSIP, framed("No such command 'pjsip show registrations'"), "", 0, "unsupported_command"},
		{"unsupported release", Identity, []byte("Asterisk 22.8.1 built on Linux"), "", 0, "unsupported_version"},
		{"bad version", Identity, []byte("Asterisk twenty"), "", 0, "parse_error"},
		{"empty", Channels, nil, "", 0, "parse_error"},
		{"negative", Channels, framed("-1 active channels\n0 active calls\n0 calls processed"), "", 0, "parse_error"},
		{"overflow", Channels, framed("18446744073709551616 active channels\n0 active calls\n0 calls processed"), "", 0, "parse_error"},
		{"duplicate", Channels, framed("1 active channels\n1 active channels\n0 active calls\n0 calls processed"), "", 0, "parse_error"},
		{"raw channels forbidden", Channels, framed("Channel CallerID State\nSIP/synthetic 123 Up"), "", 0, "parse_error"},
		{"inconsistent modules", Modules, framed("Module Description Use Count Status Support Level\n1 modules loaded"), "", 0, "parse_error"},
		{"malformed registrations", PJSIP, framed("Objects found: 3"), "", 0, "parse_error"},
		{"excessive registrations", PJSIP, framed("<Registration/ServerURI> <Auth> <Status>\nsynthetic/sip:example.invalid auth Registered\nObjects found: 999999"), "", 0, "record_limit"},
		{"PJSIP missing rows", PJSIP, framed("<Registration/ServerURI> <Auth> <Status>\nObjects found: 5"), "", 0, "parse_error"},
		{"PJSIP bad row", PJSIP, framed("<Registration/ServerURI> <Auth> <Status>\ngarbage\nObjects found: 1"), "", 0, "parse_error"},
		{"PJSIP trailing garbage", PJSIP, framed("<Registration/ServerURI> <Auth> <Status>\nObjects found: 1\ngarbage"), "", 0, "parse_error"},
		{"PJSIP duplicate footer", PJSIP, framed("<Registration/ServerURI> <Auth> <Status>\nObjects found: 1\nObjects found: 1"), "", 0, "parse_error"},
		{"oversized", Identity, []byte(strings.Repeat("x", 65537)), "", 0, "parse_error"},
		{"control bytes", Identity, []byte(runtimeVersion + "\x1b[31m"), "", 0, "parse_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs, diag := tt.p(tt.input)
			if tt.code != "" {
				if len(obs) != 0 || len(diag) != 1 || diag[0].Code != tt.code {
					t.Fatalf("%+v %+v", obs, diag)
				}
				return
			}
			if len(diag) != 0 || len(obs) == 0 || obs[0].Key != tt.key {
				t.Fatalf("%+v %+v", obs, diag)
			}
			if obs[0].Value.Kind == "integer" && obs[0].Value.Integer != tt.n {
				t.Fatal(obs)
			}
			a, b := tt.p(tt.input)
			if !reflect.DeepEqual(obs, a) || !reflect.DeepEqual(diag, b) {
				t.Fatal("nondeterministic")
			}
		})
	}
}

type denied struct{}

func (denied) IntegrationAllowed(context.Context, workspace.Principal, sshcli.Target, string) error {
	return workspace.ErrDenied
}

type fake struct{ calls int }

func (f *fake) Execute(_ context.Context, _ workspace.Principal, _ sshcli.Target, id string) (sshcli.Result, error) {
	f.calls++
	now := time.Now()
	return sshcli.Result{StartedAt: now, EndedAt: now, Stdout: []byte(runtimeVersion)}, nil
}
func TestOptionalAndAuthority(t *testing.T) {
	r := linux.Registry().Extend(Specs()...)
	if len(r.Defaults()) != 5 || len(r.IDs()) != 9 {
		t.Fatal(r.IDs())
	}
	f := &fake{}
	e := Executor{Next: f, Authority: denied{}}
	_, err := e.Execute(context.Background(), workspace.Principal{}, sshcli.Target{}, "asterisk.identity.v1")
	if err == nil || f.calls != 0 {
		t.Fatal("bypassed opt-in")
	}
	_, err = r.Collect(context.Background(), f, workspace.Principal{}, sshcli.Target{}, []string{"asterisk.identity;core restart now"})
	if err == nil || f.calls != 0 {
		t.Fatal("arbitrary command")
	}
}
