package sshcli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeStaticCommand(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0700); e != nil {
			t.Fatal(e)
		}
	}
	write("svn", "printf '4034\\n'\n")
	write("ps", `printf 'asterisk S /usr/sbin/asterisk -f secret-password\nmysqld S /usr/sbin/mysqld --password=synthetic-secret\nhttpd-prefork S /usr/sbin/httpd-prefork -f private.conf\nAST_VDauto_dial S /usr/bin/perl /usr/share/astguiclient/AST_VDauto_dial.pl private-argument\nAST_VDauto_dial S /usr/bin/perl /usr/share/astguiclient/AST_VDauto_dial_FILL.pl private-argument\nperl S /usr/bin/perl /tmp/AST_update.pl\nperl Z /usr/bin/perl /usr/share/astguiclient/AST_manager_send.pl\n'
if [ "$RUNTIME_TEST_FAILURE" = ps ]; then exit 1; fi
`)
	write("systemctl", `case "$*" in
 *asterisk.service*) printf 'Id=asterisk.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n';;
 *mariadb.service*) printf 'Id=mariadb.service\nLoadState=loaded\nActiveState=active\nSubState=running\n';;
 *apache2.service*) printf 'Id=apache2.service\nLoadState=loaded\nActiveState=active\nSubState=running\n';;
 *) exit 9;;
esac
if [ "$RUNTIME_TEST_FAILURE" = unit ]; then exit 1; fi
`)
	command := strings.Replace(runtimeServicesCommand, "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "PATH="+dir+":/usr/sbin:/usr/bin:/sbin:/bin", 1)
	for _, failure := range []string{"", "ps", "unit"} {
		t.Run(failure, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", command)
			cmd.Env = append(os.Environ(), "RUNTIME_TEST_FAILURE="+failure)
			out, e := cmd.Output()
			if e != nil {
				t.Fatal(e)
			}
			value := string(out)
			if strings.Contains(value, "secret") || strings.Contains(value, "private") {
				t.Fatal("process arguments escaped")
			}
			if !strings.HasPrefix(value, "NW_RUNTIME_1\n") || !strings.HasSuffix(value, "END\n") {
				t.Fatal("framing", value)
			}
			if strings.Contains(value, "AST_update.pl|unknown|unavailable|unavailable|observed") || strings.Contains(value, "AST_manager_send.pl|unknown|unavailable|unavailable|observed") {
				t.Fatal("unrelated path or zombie classified running", value)
			}
			switch failure {
			case "":
				if !strings.Contains(value, "|loaded|stopped|observed|linux|asterisk.service") {
					t.Fatal("alternate startup", value)
				}
				if !strings.Contains(value, "AST_VDauto_dial.pl|unknown|unavailable|unavailable|observed") || !strings.Contains(value, "AST_VDauto_dial_FILL.pl|unknown|unavailable|unavailable|observed") {
					t.Fatal("script identity", value)
				}
			case "ps":
				if strings.Contains(value, "|observed|") || strings.Contains(value, "|not_observed|") {
					t.Fatal("incomplete process inspection", value)
				}
			case "unit":
				if strings.Contains(value, "|loaded|") {
					t.Fatal("failed unit inspection", value)
				}
			}
		})
	}
}
