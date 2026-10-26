package linux

import (
	"noc-workbench/internal/collection"
	"strings"
	"testing"
)

func TestParserFixtures(t *testing.T) {
	tests := []struct {
		name  string
		parse collection.Parser
		input string
		count int
		code  string
	}{
		{"uptime unsupported procfs", Uptime, "NW_SOURCE_UNSUPPORTED\n", 0, "unsupported_source"},
		{"load unsupported procfs", Load, "NW_SOURCE_UNSUPPORTED\n", 0, "unsupported_source"},
		{"memory unsupported procfs", Memory, "NW_SOURCE_UNSUPPORTED\n", 0, "unsupported_source"},
		{"uptime decimals", Uptime, "1234.56 2000.99\n", 1, ""},
		{"uptime negative", Uptime, "-1 2", 0, "parse_error"},
		{"uptime nan", Uptime, "NaN 2", 0, "parse_error"},
		{"uptime infinity", Uptime, "Inf 2", 0, "parse_error"},
		{"uptime missing", Uptime, "", 0, "parse_error"},
		{"uptime exponent", Uptime, "1e3 2", 0, "parse_error"},
		{"load Linux", Load, "2.05 1.23 0.87 2/100 123\n\nCPU_COUNT=8\n", 4, ""},
		{"load missing CPU", Load, "0.00 0.01 0.02 1/100 1\n\nCPU_COUNT=", 3, "cpu_count_unavailable"},
		{"load zero CPU", Load, "0 0 0 1/100 1\nCPU_COUNT=0", 3, "cpu_count_unavailable"},
		{"load malformed", Load, "NaN 1 2 1/1 1\nCPU_COUNT=2", 0, "parse_error"},
		{"load missing fields", Load, "1 2\nCPU_COUNT=2", 0, "parse_error"},
		{"memory modern", Memory, "MemTotal: 1024 kB\nMemFree: 100 kB\nMemAvailable: 512 kB\nBuffers: 20 kB\n", 3, ""},
		{"memory old Linux", Memory, "MemTotal: 1024 kB\nMemFree: 100 kB\n", 2, "mem_available_unsupported"},
		{"memory missing total", Memory, "MemAvailable: 1 kB\n", 0, "parse_error"},
		{"memory negative", Memory, "MemTotal: -1 kB\n", 0, "parse_error"},
		{"memory inconsistent", Memory, "MemTotal: 1 kB\nMemAvailable: 2 kB\n", 0, "parse_error"},
		{"memory free exceeds available", Memory, "MemTotal: 10 kB\nMemAvailable: 2 kB\nMemFree: 3 kB\n", 3, ""},
		{"memory wrong unit", Memory, "MemTotal: 1024 MB\n", 0, "parse_error"},
		{"memory overflow", Memory, "MemTotal: 18446744073709551615 kB\n", 0, "parse_error"},
		{"memory duplicate", Memory, "MemTotal: 2 kB\nMemTotal: 2 kB\n", 0, "parse_error"},
		{"identity Debian style", Identity, "host.example.invalid\n6.1.0-generic\nx86_64\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\n", 5, ""},
		{"identity Alpine style", Identity, "alpine.example.invalid\n6.6.0\naarch64\nNAME='Alpine Linux'\nID=alpine\nVERSION_ID=3.20.0\n", 5, ""},
		{"identity RHEL style", Identity, "rhel.example.invalid\n5.14.0\nx86_64\nNAME=\"Red Hat Enterprise Linux\"\nVERSION_ID=\"9.4\"\n", 5, ""},
		{"identity missing os release", Identity, "host.example.invalid\n6.0\nx86_64\nNW_OS_RELEASE_UNAVAILABLE\n", 3, "os_release_unavailable"},
		{"identity invalid quote", Identity, "host.example.invalid\n6.0\nx86_64\nNAME=\"bad\n", 3, "os_release_parse_error"},
		{"identity duplicate", Identity, "host.example.invalid\n6.0\nx86_64\nNAME=first\nNAME=second\n", 3, "os_release_parse_error"},
		{"df ambiguous source or mount", Filesystems, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/source 100 10 90 10% /fake 1000 20 980 2% /real\n", 0, "filesystem_ambiguous_row"},
		{"df GNU", Filesystems, "Filesystem     1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 200 750 22% /\ntmpfs 100 0 100 0% /run\n", 10, ""},
		{"df BusyBox spaces", Filesystems, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/mapper/a long disk 1000 200 750 22% /path with spaces/é\n", 5, ""},
		{"df unavailable mount partial", Filesystems, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda 100 10 90 10% /\nbad row\n", 5, "filesystem_row_parse_error"},
		{"df overflow", Filesystems, "Filesystem 1024-blocks Used Available Capacity Mounted on\na 18446744073709551615 0 0 0% /\n", 0, "filesystem_range_error"},
		{"df inconsistent", Filesystems, "Filesystem 1024-blocks Used Available Capacity Mounted on\na 100 60 60 50% /\n", 0, "filesystem_range_error"},
		{"df incomplete", Filesystems, "Filesystem 1024-blocks Used Available Capacity Mounted on\na 100 10 90 10% /", 0, "parse_error"},
		{"df negative available", Filesystems, "Filesystem 1024-blocks Used Available Capacity Mounted on\na 100 10 -10 10% /\n", 0, "filesystem_row_parse_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs, d := tt.parse([]byte(tt.input))
			if len(obs) != tt.count {
				t.Fatalf("observations %d want %d, diagnostics %+v", len(obs), tt.count, d)
			}
			if tt.code == "" && len(d) > 0 {
				t.Fatal(d)
			}
			if tt.code != "" && (len(d) == 0 || d[0].Code != tt.code) {
				t.Fatal(d)
			}
		})
	}
}
func TestUnitsPrecisionAndResources(t *testing.T) {
	m, _ := Memory([]byte("MemTotal: 1024 kB\nMemAvailable: 512 kB\n"))
	if m[0].Value.Integer != 1048576 || m[1].Value.Integer != 524288 || m[0].Unit != "bytes" {
		t.Fatal(m)
	}
	u, _ := Uptime([]byte("1234.56 9999.2\n"))
	if u[0].Value.Number != 1234.56 || u[0].Unit != "seconds" {
		t.Fatal(u)
	}
	l, _ := Load([]byte("2.05 1.23 0.87 1/1 1\nCPU_COUNT=8\n"))
	if l[0].Value.Number != 2.05 || l[0].Unit != "load" {
		t.Fatal(l)
	}
	f, _ := Filesystems([]byte("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk label 100 10 90 10% /mount with spaces/é\n"))
	if f[0].Resource != "/mount with spaces/é" || f[0].Value.Text != "/dev/disk label" || f[1].Value.Integer != 102400 {
		t.Fatal(f)
	}
	for _, s := range []string{`"quoted \"word\""`, `'literal $value'`, `"$(touch /tmp/never-executed)"`} {
		if _, ok := osValue(s); !ok {
			t.Fatal(s)
		}
	}
}
func TestBoundsAndNoDiagnosticEcho(t *testing.T) {
	for _, p := range []collection.Parser{Identity, Uptime, Load, Memory, Filesystems} {
		for _, input := range []string{strings.Repeat("x", 65537), "sensitive\x1b[31msecret\n", "sensitive\x00secret\n"} {
			o, d := p([]byte(input))
			if len(o) != 0 || len(d) != 1 || d[0].Code != "parse_error" {
				t.Fatal(o, d)
			}
		}
	}
	input := "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
	for i := 0; i < 257; i++ {
		input += "tmpfs 1 0 1 0% /" + strings.Repeat("a", i+1) + "\n"
	}
	o, d := Filesystems([]byte(input))
	if len(o) != 256*5 || len(d) != 1 || d[0].Code != "filesystem_record_limit" {
		t.Fatal(len(o), d)
	}
}
func FuzzParsers(f *testing.F) {
	f.Add([]byte("123.45 1234.5\n"))
	f.Add([]byte("MemTotal: 1024 kB\n"))
	f.Add([]byte("Filesystem 1024-blocks Used Available Capacity Mounted on\na 1 0 1 0% /\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, p := range []collection.Parser{Identity, Uptime, Load, Memory, Filesystems} {
			o, d := p(b)
			if len(o) > 1280 || len(d) > 257 {
				t.Fatal("unbounded parser")
			}
		}
	})
}
