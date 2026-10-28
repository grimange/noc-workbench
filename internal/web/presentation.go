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
type consolePresentation struct{ Availability, Tone, Issues, Age string }

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
	// Numeric memory ratios are prepared from same-run validated readings below.
	if d.MemoryGauge.Valid {
		d.Gauges[1] = d.MemoryGauge
	}
	d.DiskText = "Unknown"
	for _, f := range d.Filesystems {
		if f.Mount != "/" && technicalMount(f.Mount) {
			continue
		}
		d.PrimaryFilesystems = append(d.PrimaryFilesystems, f)
		if len(d.PrimaryFilesystems) == 1 || f.Mount == "/" {
			d.Gauges[2] = resourceGauge{Label: "Storage", Value: "Unknown", Detail: f.Mount + " · " + f.State, State: f.State}
			v, e := strconv.ParseFloat(strings.TrimSuffix(f.Percent, "%"), 64)
			if f.State == "Current" && e == nil && v >= 0 && v <= 100 {
				d.Gauges[2] = resourceGauge{"Storage", f.Percent, f.Mount + " · " + f.Available + " free", "Current", v, true}
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
	for _, p := range []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/snap"} {
		if m == p || strings.HasPrefix(m, p+"/") {
			return true
		}
	}
	return false
}
func presentation(r resourceData, d runtimeData, at time.Time) consolePresentation {
	v := consolePresentation{Availability: "Unknown", Tone: "neutral", Issues: "Unknown", Age: "No observation"}
	if !d.LastObservation.IsZero() {
		age := at.Sub(d.LastObservation)
		if age < 0 {
			age = 0
		}
		switch {
		case age < time.Minute:
			v.Age = "<1 min ago"
		case age < time.Hour:
			v.Age = fmt.Sprintf("%d min ago", int(age.Minutes()))
		case age < 24*time.Hour:
			v.Age = fmt.Sprintf("%d hr ago", int(age.Hours()))
		default:
			v.Age = fmt.Sprintf("%d d ago", int(age.Hours()/24))
		}
	}
	switch {
	case !d.Enabled:
		v.Availability = "Monitoring inactive"
	case d.Outcome != "" && d.Outcome != "success" && d.Outcome != "Not attempted":
		v.Availability = "Collection " + d.Outcome
		v.Tone = "warning"
	case r.Current:
		v.Availability = "Observed"
		v.Tone = "observed"
	case strings.Contains(r.State, "Stale"):
		v.Availability = "Stale evidence"
		v.Tone = "warning"
	}
	if r.Current && r.UnitsAvailable && r.Status["units_status"] == "observed" {
		n := 0
		for _, u := range r.Units {
			if u.Active == "failed" {
				n++
			}
		}
		v.Issues = fmt.Sprintf("%d failed units", n)
	}
	return v
}
