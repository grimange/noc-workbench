package sshcli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryDatabaseIsolation(t *testing.T) {
	dir := t.TempDir()
	fake := `#!/bin/sh
for key in MYSQL_PWD MYSQL_HOME MYSQL_TCP_PORT MYSQL_UNIX_PORT MARIADB_HOME MYSQL_GROUP_SUFFIX MYSQL_TEST_LOGIN_FILE; do
 eval 'value=${'"$key"'-}'
 if [ -n "$value" ]; then exit 91; fi
done
[ "$1" = --no-defaults ] || exit 92
[ "$2" = --protocol=socket ] || exit 93
[ "$3" = --socket=/run/mysql/mysql.sock ] || exit 94
case "$*" in
 *"SELECT CONCAT('observed_port='"*) printf 'observed_port=3306\nregistry_row=192.0.2.10|Web|-\n';;
 *"SELECT COUNT(*) FROM information_schema.PROCESSLIST"*) printf '0\n';;
 *"SHOW ALL SLAVES STATUS"*) printf 'Slave_IO_Running\tSlave_SQL_Running\nYes\tYes\n';;
 *) exit 95;;
esac
printf 'called\n' >> "$DISCOVERY_TEST_CALLS"
`
	if err := os.WriteFile(filepath.Join(dir, "mariadb"), []byte(fake), 0700); err != nil {
		t.Fatal(err)
	}
	// Only the fixed PATH assignment is replaced to inject a synthetic client.
	command := strings.Replace(vicidialDiscoveryCommand, "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "PATH="+dir+":/usr/sbin:/usr/bin:/sbin:/bin", 1)
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Env = append(os.Environ(), "DISCOVERY_TEST_CALLS="+filepath.Join(dir, "calls"))
	for _, key := range []string{"MYSQL_PWD", "MYSQL_HOME", "MYSQL_TCP_PORT", "MYSQL_UNIX_PORT", "MARIADB_HOME", "MYSQL_GROUP_SUFFIX", "MYSQL_TEST_LOGIN_FILE"} {
		cmd.Env = append(cmd.Env, key+"=synthetic-secret")
	}
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(filepath.Join(dir, "calls"))
	if err != nil || strings.Count(string(calls), "called") != 3 {
		t.Fatal("isolated queries not executed", err)
	}
	for _, want := range []string{"registry=available", "primary_streams=0", "replica=running", "END\n"} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, forbidden := range []string{"synthetic-secret", "field2", "field3", "field4", "field5", "field6", "field7", "field8", "field9", "SELECT *"} {
		if strings.Contains(string(output), forbidden) || strings.Contains(vicidialDiscoveryCommand, forbidden) {
			t.Fatalf("sensitive output/query %s", forbidden)
		}
	}
}
