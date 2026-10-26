// Package linux parses bounded Linux observations, without transport authority.
package linux

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"noc-workbench/internal/collection"
)

func Registry() *collection.Registry {
	r, err := collection.NewRegistry([]collection.Spec{
		{ID: "linux.identity", Version: "1", CommandID: "linux.identity.v1", Parse: Identity},
		{ID: "linux.uptime", Version: "1", CommandID: "linux.uptime.v1", Parse: Uptime},
		{ID: "linux.load", Version: "1", CommandID: "linux.load.v1", Parse: Load},
		{ID: "linux.memory", Version: "1", CommandID: "linux.memory.v1", Parse: Memory},
		{ID: "linux.filesystems", Version: "1", CommandID: "linux.filesystems.v1", Parse: Filesystems},
	})
	if err != nil {
		panic(err)
	}
	return r
}
func diagnostic(code string) []collection.Diagnostic           { return []collection.Diagnostic{{Code: code}} }
func bad() ([]collection.Observation, []collection.Diagnostic) { return nil, diagnostic("parse_error") }
func valid(b []byte) bool {
	if len(b) == 0 || len(b) > 64*1024 || !utf8.Valid(b) {
		return false
	}
	for _, c := range string(b) {
		if unicode.IsControl(c) && c != '\n' && c != '\t' {
			return false
		}
	}
	return true
}

var decimal = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?$`)

func number(s string) (float64, bool) {
	if !decimal.MatchString(s) {
		return 0, false
	}
	n, e := strconv.ParseFloat(s, 64)
	return n, e == nil && !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0
}
func uintValue(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, e := strconv.ParseUint(s, 10, 64)
	return n, e == nil
}
func text(key, v string) collection.Observation {
	return collection.Observation{Key: key, Value: collection.Text(v), Unit: "text"}
}
func num(key, unit string, v float64) collection.Observation {
	return collection.Observation{Key: key, Value: collection.Number(v), Unit: unit}
}
func integer(key, unit string, v uint64) collection.Observation {
	return collection.Observation{Key: key, Value: collection.Integer(v), Unit: unit}
}

func Uptime(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	if string(b) == "NW_SOURCE_UNSUPPORTED\n" {
		return nil, diagnostic("unsupported_source")
	}
	if !valid(b) {
		return bad()
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return bad()
	}
	n, ok := number(f[0])
	if !ok {
		return bad()
	}
	if _, ok = number(f[1]); !ok {
		return bad()
	}
	return []collection.Observation{num("linux.uptime.seconds", "seconds", n)}, nil
}
func Load(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	if string(b) == "NW_SOURCE_UNSUPPORTED\n" {
		return nil, diagnostic("unsupported_source")
	}
	if !valid(b) {
		return bad()
	}
	parts := strings.Split(string(b), "\nCPU_COUNT=")
	if len(parts) != 2 {
		return bad()
	}
	f := strings.Fields(parts[0])
	if len(f) != 5 {
		return bad()
	}
	obs := []collection.Observation{}
	for i, k := range []string{"linux.load.1m", "linux.load.5m", "linux.load.15m"} {
		n, ok := number(f[i])
		if !ok {
			return bad()
		}
		obs = append(obs, num(k, "load", n))
	}
	cpus, ok := uintValue(strings.TrimSpace(parts[1]))
	if !ok || cpus == 0 || cpus > 1048576 {
		return obs, diagnostic("cpu_count_unavailable")
	}
	obs = append(obs, integer("linux.cpu.logical_count", "count", cpus))
	return obs, nil
}

// os-release is data, never sourced or evaluated as shell. Decode only its
// documented quote/escape subset; substitutions stay literal text.
func osValue(s string) (string, bool) {
	if len(s) > 1024 {
		return "", false
	}
	if s == "" {
		return "", true
	}
	quote := byte(0)
	if s[0] == '\'' || s[0] == '"' {
		quote = s[0]
		if len(s) < 2 || s[len(s)-1] != quote {
			return "", false
		}
		s = s[1 : len(s)-1]
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && quote != '\'' {
			if i+1 == len(s) {
				return "", false
			}
			next := s[i+1]
			if quote == 0 || strings.ContainsRune("$`\"\\", rune(next)) {
				out.WriteByte(next)
				i++
				continue
			}
		}
		if c == quote && quote != 0 {
			return "", false
		}
		if quote == 0 && (c == '\'' || c == '"' || c == ' ' || c == '\t') {
			return "", false
		}
		out.WriteByte(c)
	}
	return out.String(), true
}

var osKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func Identity(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	if !valid(b) {
		return bad()
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) < 4 {
		return bad()
	}
	obs := []collection.Observation{}
	for i, key := range []string{"linux.hostname", "linux.kernel.release", "linux.architecture"} {
		if len(lines[i]) == 0 || len(lines[i]) > 255 || strings.ContainsAny(lines[i], "\t ") {
			return bad()
		}
		obs = append(obs, text(key, lines[i]))
	}
	if len(lines) == 4 && lines[3] == "NW_OS_RELEASE_UNAVAILABLE" {
		return obs, diagnostic("os_release_unavailable")
	}
	values := map[string]string{}
	for _, line := range lines[3:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !osKey.MatchString(k) {
			return obs, diagnostic("os_release_parse_error")
		}
		if _, dup := values[k]; dup {
			return obs, diagnostic("os_release_parse_error")
		}
		v, ok = osValue(v)
		if !ok {
			return obs, diagnostic("os_release_parse_error")
		}
		values[k] = v
	}
	if values["NAME"] == "" {
		return obs, diagnostic("os_release_parse_error")
	}
	obs = append(obs, text("linux.os.name", values["NAME"]))
	if v := values["VERSION_ID"]; v != "" {
		obs = append(obs, text("linux.os.version", v))
	}
	return obs, nil
}
func Memory(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	if string(b) == "NW_SOURCE_UNSUPPORTED\n" {
		return nil, diagnostic("unsupported_source")
	}
	if !valid(b) {
		return bad()
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, rest, ok := strings.Cut(line, ":")
		if !ok {
			return bad()
		}
		if k != "MemTotal" && k != "MemAvailable" && k != "MemFree" {
			continue
		}
		if _, dup := values[k]; dup {
			return bad()
		}
		f := strings.Fields(rest)
		if len(f) != 2 || f[1] != "kB" {
			return bad()
		}
		n, ok := uintValue(f[0])
		if !ok || n > math.MaxUint64/1024 {
			return bad()
		}
		values[k] = n * 1024
	}
	total, ok := values["MemTotal"]
	if !ok || total == 0 {
		return bad()
	}
	for _, k := range []string{"MemAvailable", "MemFree"} {
		if values[k] > total {
			return bad()
		}
	}
	obs := []collection.Observation{integer("linux.mem.total_bytes", "bytes", total)}
	for _, kv := range [][2]string{{"MemAvailable", "linux.mem.available_bytes"}, {"MemFree", "linux.mem.free_bytes"}} {
		if v, ok := values[kv[0]]; ok {
			obs = append(obs, integer(kv[1], "bytes", v))
		}
	}
	if _, ok := values["MemAvailable"]; !ok {
		return obs, diagnostic("mem_available_unsupported")
	}
	return obs, nil
}

var dfRow = regexp.MustCompile(`^(.+?)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)%[ \t]+(/.*)$`)

func Filesystems(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	if !valid(b) || b[len(b)-1] != '\n' {
		return bad()
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "Filesystem") || !strings.Contains(lines[0], "1024-blocks") {
		return bad()
	}
	obs := []collection.Observation{}
	diag := []collection.Diagnostic{}
	seen := map[string]bool{}
	for i, line := range lines[1:] {
		if i >= 256 {
			diag = append(diag, collection.Diagnostic{Code: "filesystem_record_limit"})
			break
		}
		f := dfRow.FindStringSubmatch(line)
		if f != nil && dfRow.MatchString(f[6]) {
			diag = append(diag, collection.Diagnostic{Code: "filesystem_ambiguous_row"})
			continue
		}
		if f == nil || len(f[1]) > 1024 || len(f[6]) > 4096 || seen[f[6]] {
			diag = append(diag, collection.Diagnostic{Code: "filesystem_row_parse_error"})
			continue
		}
		vals := [4]uint64{}
		ok := true
		for j := range vals {
			var good bool
			vals[j], good = uintValue(f[j+2])
			ok = ok && good
		}
		if !ok || vals[0] > math.MaxUint64/1024 || vals[1] > vals[0] || vals[2] > vals[0]-vals[1] || vals[3] > 100 {
			diag = append(diag, collection.Diagnostic{Code: "filesystem_range_error"})
			continue
		}
		seen[f[6]] = true
		row := []collection.Observation{text("linux.filesystem.identifier", f[1]), integer("linux.filesystem.total_bytes", "bytes", vals[0]*1024), integer("linux.filesystem.used_bytes", "bytes", vals[1]*1024), integer("linux.filesystem.available_bytes", "bytes", vals[2]*1024), integer("linux.filesystem.utilization_percent", "percent", vals[3])}
		for j := range row {
			row[j].Resource = f[6]
		}
		obs = append(obs, row...)
	}
	if len(obs) == 0 && len(diag) == 0 {
		return bad()
	}
	return obs, diag
}
