package workspace

import (
	"noc-workbench/internal/inventory"
	"strings"
	"testing"
)

func TestPolicyAndValidation(t *testing.T) {
	policy := LocalOperatorPolicy{}
	for _, p := range []Principal{{}, {ID: "00000000-0000-4000-8000-000000000002"}} {
		if _, e := policy.Scope(p, Search); e == nil {
			t.Fatal("unknown principal allowed")
		}
	}
	if _, e := policy.Scope(Principal{OperatorID}, Permission("collection.run")); e == nil {
		t.Fatal("unknown permission allowed")
	}
	if (Scope{}).Allows(OperatorID, OperatorID) {
		t.Fatal("default scope allows")
	}
	if !(Scope{Customers: []string{OperatorID}}).Allows(OperatorID, "") {
		t.Fatal("explicit customer scope")
	}
	for _, raw := range []string{"javascript:alert(1)", "data:text/html,x", "https://user:password@example.invalid/", "https://example.invalid/?token=secret", "https://example.invalid/#token", "https://example.invalid:0/", "https://example.invalid/\n"} {
		if ValidateLink("Synthetic", raw, "rtm") == nil {
			t.Fatal("unsafe link", raw)
		}
	}
	for _, raw := range []string{"https://rtm.example.invalid/path", "http://[2001:db8::1]:8080/"} {
		if e := ValidateLink("Synthetic", raw, "rtm"); e != nil {
			t.Fatal(raw, e)
		}
	}
	if _, e := ValidateNote("", "private"); e == nil {
		t.Fatal("blank note")
	}
	if _, e := ValidateNote("ok", "unknown"); e == nil {
		t.Fatal("visibility")
	}
	if q, e := Query("WEB ' OR 1=1 --"); e != nil || q != "web:* & or:* & 1:* & 1:*" {
		t.Fatal(q, e)
	}
	if _, e := Query(strings.Repeat("x", 121)); e == nil {
		t.Fatal("unbounded query")
	}
}
func TestSSHCommand(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "ssh.example.invalid"} {
		e := inventory.Endpoint{EnvironmentID: OperatorID, AssetID: OperatorID, Protocol: "ssh", Host: host, Port: 2222, Status: "active"}
		cmd, err := SSHCommand(e)
		if err != nil || !strings.Contains(cmd, "-p 2222 -- '"+host+"'") || !strings.Contains(cmd, "-F /dev/null") {
			t.Fatal(cmd, err)
		}
	}
	for _, host := range []string{"-oProxyCommand=id", "x;id", "$(id)", "x'$(id)'", "x\n-oProxyCommand=id", "x y", "[2001:db8::1]"} {
		if _, e := SSHCommand(inventory.Endpoint{EnvironmentID: OperatorID, AssetID: OperatorID, Protocol: "ssh", Host: host, Port: 22, Status: "active"}); e == nil {
			t.Fatal("command injection", host)
		}
	}
}

func TestSSHCommandLifecycleAndProtocol(t *testing.T) {
	for _, e := range []inventory.Endpoint{
		{EnvironmentID: OperatorID, AssetID: OperatorID, Protocol: "https", Host: "ssh.example.invalid", Port: 22, Status: "active"},
		{EnvironmentID: OperatorID, AssetID: OperatorID, Protocol: "ssh", Host: "ssh.example.invalid", Port: 22, Status: "archived"},
	} {
		if _, err := SSHCommand(e); err == nil {
			t.Fatal("non-SSH or inactive endpoint accepted")
		}
	}
}
