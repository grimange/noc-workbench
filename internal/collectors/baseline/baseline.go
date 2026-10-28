// Package baseline normalizes resource, unit and schedule facts without transport.
package baseline

import (
	"encoding/json"
	"fmt"
	"math"
	"noc-workbench/internal/collection"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const Collector = "linux.baseline"
const Prefix = "linux.baseline."

func Specs() []collection.Spec {
	return []collection.Spec{{ID: Collector, Version: "2", CommandID: Collector + ".v1", Parse: Parse, Optional: true}}
}

type Process struct {
	PID  uint64
	Name string
	CPU  float64
	RSS  uint64
}
type Unit struct{ Name, Load, Active, Sub, Installed string }
type Job struct{ Source, Schedule, Identity string }

var identity = regexp.MustCompile(`^[A-Za-z0-9_.@:+-]{1,256}$`)
var schedule = regexp.MustCompile(`^[0-9A-Za-z*,/~ -]{1,128}$`)

func Parse(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	bad := func() ([]collection.Observation, []collection.Diagnostic) {
		return nil, []collection.Diagnostic{{Code: "malformed_output"}}
	}
	if len(b) > 65536 || !utf8.Valid(b) || !strings.HasPrefix(string(b), "NW_BASELINE_1\n") || !strings.HasSuffix(string(b), "\nEND\n") {
		return bad()
	}
	for _, r := range string(b) {
		if r < 32 && r != '\n' && r != '\t' {
			return bad()
		}
	}
	var out []collection.Observation
	add := func(key, resource string, value collection.Value, unit string) {
		out = append(out, collection.Observation{Key: Prefix + key, Resource: resource, Value: value, Unit: unit, Quality: "valid"})
	}
	processes := []Process{}
	units := []Unit{}
	jobs := []Job{}
	statuses := map[string]string{}
	files := map[string]string{}
	page := uint64(0)
	seen := map[string]bool{}
	number := func(s string) (float64, bool) {
		v, e := strconv.ParseFloat(s, 64)
		return v, e == nil && !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 100
	}
	integer := func(s string) (uint64, bool) { v, e := strconv.ParseUint(s, 10, 64); return v, e == nil && v <= 1<<50 }
	for _, line := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(string(b), "NW_BASELINE_1\n"), "END\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "|")
		switch f[0] {
		case "cpu", "pressure":
			if len(f) != 2 || seen[f[0]] {
				return bad()
			}
			seen[f[0]] = true
			if f[1] == "unavailable" {
				statuses[f[0]] = "unavailable"
				continue
			}
			v, ok := number(f[1])
			if !ok {
				return bad()
			}
			key := "cpu_percent"
			if f[0] == "pressure" {
				key = "pressure_some_percent"
			}
			add(key, "", collection.Number(v), "percent")
		case "swap_total", "swap_free", "page_bytes":
			if len(f) != 2 || seen[f[0]] {
				return bad()
			}
			seen[f[0]] = true
			v, ok := integer(f[1])
			if !ok {
				return bad()
			}
			if f[0] == "page_bytes" {
				if v < 512 || v > 1<<20 || v&(v-1) != 0 {
					return bad()
				}
				page = v
			} else {
				add(f[0]+"_bytes", "", collection.Integer(v*1024), "bytes")
			}
		case "process":
			if len(f) != 5 || len(processes) >= 20 || !identity.MatchString(f[2]) {
				return bad()
			}
			pid, ok := integer(f[1])
			if !ok || pid == 0 {
				return bad()
			}
			cpu, ok := number(f[3])
			if !ok {
				return bad()
			}
			rss, ok := integer(f[4])
			if !ok || rss > 1<<40 {
				return bad()
			}
			for _, p := range processes {
				if p.PID == pid {
					return bad()
				}
			}
			processes = append(processes, Process{pid, f[2], cpu, rss})
		case "unit":
			if len(f) != 5 || len(units) >= 512 {
				return bad()
			}
			for _, v := range f[1:] {
				if !identity.MatchString(v) {
					return bad()
				}
			}
			if !strings.HasSuffix(f[1], ".service") {
				return bad()
			}
			if seen["unit:"+f[1]] {
				return bad()
			}
			seen["unit:"+f[1]] = true
			units = append(units, Unit{Name: f[1], Load: f[2], Active: f[3], Sub: f[4]})
		case "unit_file":
			if len(f) != 3 || len(files) >= 512 || !identity.MatchString(f[1]) || !identity.MatchString(f[2]) || !strings.HasSuffix(f[1], ".service") {
				return bad()
			}
			files[f[1]] = f[2]
		case "job":
			if len(f) != 4 || len(jobs) >= 192 || len(f[3]) > 256 {
				return bad()
			}
			if f[1] != "system cron" && f[1] != "user cron" && f[1] != "systemd timer" {
				return bad()
			}
			if f[1] == "systemd timer" {
				if !identity.MatchString(f[2]) || !strings.HasSuffix(f[2], ".timer") || !safeTimer(f[3]) {
					return bad()
				}
			} else {
				if !safeCron(f[2]) || !(f[3] == "command withheld" || (identity.MatchString(f[3]) && strings.HasPrefix(f[3], "AST_") && strings.HasSuffix(f[3], ".pl"))) {
					return bad()
				}
			}
			jobs = append(jobs, Job{f[1], f[2], f[3]})
		case "units_status", "files_status", "cron_status", "timers_status", "process_status", "units_limit":
			if len(f) != 2 || seen[f[0]] || !identity.MatchString(f[1]) {
				return bad()
			}
			seen[f[0]] = true
			statuses[f[0]] = f[1]
		default:
			return bad()
		}
	}
	if !seen["cpu"] || page == 0 || !seen["units_status"] || !seen["timers_status"] {
		return bad()
	}
	for i := range processes {
		processes[i].RSS *= page
	}
	// Fixed pages include empty arrays. Disappeared processes/units/jobs do not
	// inherit an old page; failures retain history with an explicit unavailable status.
	put := func(key string, v any) {
		data, _ := json.Marshal(v)
		add(key, "", collection.Text(string(data)), "text")
	}
	put("processes", processes)
	for i := range units {
		units[i].Installed = files[units[i].Name]
		delete(files, units[i].Name)
	}
	// Unloaded installed units retain unknown runtime state, never fabricated inactive.
	for name, state := range files {
		units = append(units, Unit{Name: name, Load: "not_observed", Active: "unknown", Sub: "unknown", Installed: state})
	}
	// Stable sort prevents map order affecting normalized evidence.
	sortUnits(units)
	if len(units) > 512 {
		units = units[:512]
		statuses["units_limit"] = "512"
	}
	for i := 0; i < 32; i++ {
		lo := i * 16
		hi := lo + 16
		if lo > len(units) {
			lo = len(units)
		}
		if hi > len(units) {
			hi = len(units)
		}
		data, _ := json.Marshal(units[lo:hi])
		if len(data) > 4096 {
			return bad()
		}
		add("units", fmt.Sprintf("%02d", i), collection.Text(string(data)), "text")
	}
	for i := 0; i < 16; i++ {
		lo := i * 12
		hi := lo + 12
		if lo > len(jobs) {
			lo = len(jobs)
		}
		if hi > len(jobs) {
			hi = len(jobs)
		}
		data, _ := json.Marshal(jobs[lo:hi])
		if len(data) > 4096 {
			return bad()
		}
		add("jobs", fmt.Sprintf("%02d", i), collection.Text(string(data)), "text")
	}
	statuses["cron_scope"] = "readable_system_files_and_ssh_user_only_execution_unverified"
	put("status", statuses)
	return out, nil
}
func sortUnits(u []Unit) {
	for i := 1; i < len(u); i++ {
		for j := i; j > 0 && u[j].Name < u[j-1].Name; j-- {
			u[j], u[j-1] = u[j-1], u[j]
		}
	}
}

// Timer properties are a small structured vocabulary, never arbitrary text.
var timerChars = regexp.MustCompile(`^[A-Za-z0-9_*:,./~ +;={}\[\]-]{1,256}$`)
var timerWords = regexp.MustCompile(`[A-Za-z_]+`)
var timerAssignments = regexp.MustCompile(`([A-Za-z_]+)=`)

func safeTimer(s string) bool {
	if !timerChars.MatchString(s) {
		return false
	}
	properties := map[string]bool{"TimersCalendar": true, "TimersMonotonic": true, "OnCalendar": true, "next_elapse": true, "OnBootUSec": true, "OnStartupUSec": true, "OnActiveUSec": true, "OnUnitActiveUSec": true, "OnUnitInactiveUSec": true, "ActiveState": true}
	for _, a := range timerAssignments.FindAllStringSubmatch(s, -1) {
		if !properties[a[1]] {
			return false
		}
	}
	// systemd renders next_elapse in the host timezone. These additional
	// abbreviations are verified ViciBox output, not arbitrary timer text.
	words := " active inactive failed activating deactivating maintenance refreshing elapsed never n a UTC EST EDT Mon Tue Wed Thu Fri Sat Sun Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec us ms s sec min h d w month y "
	for _, w := range timerWords.FindAllString(s, -1) {
		if !properties[w] && !strings.Contains(words, " "+w+" ") {
			return false
		}
	}
	return strings.Contains(s, "ActiveState=")
}

func safeCron(s string) bool {
	if strings.HasPrefix(s, "@") {
		return strings.Contains(" @reboot @yearly @annually @monthly @weekly @daily @midnight @hourly ", " "+s+" ")
	}
	if !schedule.MatchString(s) {
		return false
	}
	fields := strings.Fields(s)
	if len(fields) != 5 {
		return false
	}
	for i, f := range fields {
		for _, word := range timerWords.FindAllString(f, -1) {
			word = strings.ToUpper(word)
			allowed := ""
			if i == 3 {
				allowed = " JAN FEB MAR APR MAY JUN JUL AUG SEP OCT NOV DEC "
			}
			if i == 4 {
				allowed = " SUN MON TUE WED THU FRI SAT "
			}
			if !strings.Contains(allowed, " "+word+" ") {
				return false
			}
		}
	}
	return true
}
