package web

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type resourceGauge struct {
	Label, Value, Detail, State string
	Percent                     float64
	Valid                       bool
}
type consolePresentation struct {
	Availability, Tone, Issues, Age, Reason, Monitoring string
	Attention                                           int
	Checked                                             time.Time
}

// Presentation never promotes a retained value to current evidence.
func resourceGauges(d *resourceData) {
	d.Gauges = []resourceGauge{{Label: "CPU", Value: "Unknown", Detail: "No current CPU sample"}, {Label: "Memory", Value: "Unknown", Detail: "No current RAM sample"}, {Label: "Storage", Value: "Unknown", Detail: "No current filesystem sample"}}
	for _, m := range d.Metrics {
		if m.Name == "CPU utilization (sampled counters)" && m.State == "Current" {
			v, e := strconv.ParseFloat(strings.TrimSuffix(m.Value, "%"), 64)
			if e == nil && !math.IsNaN(v) && v >= 0 && v <= 100 {
				d.Gauges[0] = resourceGauge{"CPU", m.Value, "Sampled CPU counters", "Current", v, true}
			}
		}
	}
	for _, m := range d.Metrics {
		if m.Name == "Load · 1 minute" && m.State == "Current" {
			d.Gauges[0].Detail += " · 1m load " + m.Value
		}
	}
	// Numeric memory ratios are prepared from same-run validated readings below.
	if d.MemoryGauge.Valid {
		d.Gauges[1] = d.MemoryGauge
		d.MemoryText = d.MemoryGauge.Value + " · " + d.MemoryText
	}
	d.DiskText = "Unknown"
	for _, f := range d.Filesystems {
		if f.Mount != "/" && (f.Technical || technicalMount(f.Mount)) {
			continue
		}
		d.PrimaryFilesystems = append(d.PrimaryFilesystems, f)
		if len(d.PrimaryFilesystems) == 1 || f.Mount == "/" {
			d.Gauges[2] = resourceGauge{Label: "Storage", Value: "Unknown", Detail: f.Mount + " · " + f.State, State: f.State}
			v, e := strconv.ParseFloat(strings.TrimSuffix(f.Percent, "%"), 64)
			if f.State == "Current" && e == nil && v >= 0 && v <= 100 {
				d.Gauges[2] = resourceGauge{"Storage", f.Percent, f.Mount + " · " + f.Used + " / " + f.Total + " · " + f.Available + " available", "Current", v, true}
				d.DiskText = f.Percent + " · " + f.Mount
			}
			if f.Mount == "/" {
				d.PrimaryFilesystems = []filesystemRow{f}
				break
			}
		}
	}
	// The compact view prioritizes root; all retained mounts stay available on demand.
	if len(d.PrimaryFilesystems) > 1 {
		d.PrimaryFilesystems = d.PrimaryFilesystems[:1]
	}
}
func technicalMount(m string) bool {
	for _, p := range []string{"/proc", "/sys", "/dev", "/run", "/snap"} {
		if m == p || strings.HasPrefix(m, p+"/") {
			return true
		}
	}
	return false
}
func presentation(r resourceData, d runtimeData, at time.Time) consolePresentation {
	v := consolePresentation{Availability: "Unknown", Tone: "neutral", Issues: "Unknown", Age: "No completed check"}
	v.Availability, v.Tone, v.Reason, v.Attention, v.Checked = availability(d, at)
	v.Monitoring = "Monitoring disabled — no current readings."
	if d.Paused {
		v.Monitoring = "Monitoring paused — no current readings."
	} else if d.Enabled {
		v.Monitoring = fmt.Sprintf("Background monitoring · %d-second target", d.Profile.Interval)
	}
	if !v.Checked.IsZero() {
		v.Age = observationAge(at, v.Checked)
	}
	if r.Current && r.UnitsAvailable && r.Status["units_status"] == "observed" {
		n := 0
		for _, u := range r.Units {
			if u.Active == "failed" {
				n++
			}
		}
		v.Issues = fmt.Sprintf("%d failed units", n)
		if n > 0 && v.Attention < 2 {
			v.Attention = 2
		}
	}
	return v
}

func transientFilesystem(source string) bool {
	switch source {
	case "tmpfs", "devtmpfs", "proc", "sysfs", "cgroup", "cgroup2", "securityfs", "pstore", "debugfs", "tracefs", "mqueue", "hugetlbfs", "configfs", "fusectl":
		return true
	}
	return false
}
