package web

import (
	"encoding/json"
	"fmt"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/collectors/baseline"
	"noc-workbench/internal/health"
	"sort"
	"strings"
	"time"
)

type resourceMetric struct {
	Name, Value, State, Source string
	At                         time.Time
}
type filesystemRow struct {
	Technical                                     bool
	Mount, Used, Available, Total, Percent, State string
	At                                            time.Time
}
type resourceData struct {
	ProcessState, UnitsState, JobsState string
	UnitsAvailable                      bool
	Gauges                              []resourceGauge
	MemoryGauge                         resourceGauge
	PrimaryFilesystems                  []filesystemRow
	DiskText                            string
	Metrics                             []resourceMetric
	Filesystems                         []filesystemRow
	CPU, Memory                         []baseline.Process
	Units                               []baseline.Unit
	Jobs                                []baseline.Job
	Status                              map[string]string
	Current                             bool
	At                                  time.Time
	State, CPUText, MemoryText          string
	Evidence                            collection.Evidence
}

func bytesText(v uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	f := float64(v)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}
func resources(in health.Input, out health.Evaluation, d runtimeData) resourceData {
	result := resourceData{State: "Unknown — baseline evidence unavailable", CPUText: "Unknown", MemoryText: "Unknown", Status: map[string]string{}}
	readings := map[string]health.Reading{}
	for _, r := range out.Readings {
		readings[r.Evidence.Key+"\x00"+r.Evidence.Resource] = r
	}
	state := func(r health.Reading) string {
		ev := r.Evidence
		if !d.Enabled {
			return "Historical — monitoring paused or not authorized"
		}
		if !in.Active || !in.Trusted || in.Authority[ev.ProfileID] != ev.ProfileVersion || d.Profile.Target.ProfileID != ev.ProfileID || d.Profile.Target.ProfileVersion != ev.ProfileVersion {
			return "Unknown — authority unavailable"
		}
		if r.Quality != "valid" {
			return "Unknown — invalid evidence"
		}
		if r.Freshness != "fresh" {
			return "Stale"
		}
		// A later failed attempt never renews a successful sample.
		if in.LatestAttempt != nil && in.LatestAttempt.StartedAt.After(ev.ObservedAt) {
			for _, c := range in.LatestAttempt.Results {
				if c.CollectorID == ev.CollectorID && c.Outcome != "success" {
					return "Historical — collection " + c.Outcome
				}
			}
		}
		return "Current"
	}
	if r, ok := readings[baseline.Prefix+"status\x00"]; ok {
		result.State = state(r)
		result.Current = result.State == "Current"
		result.At = r.Evidence.ObservedAt
		result.Evidence = r.Evidence
		json.Unmarshal([]byte(r.Evidence.Value.Text), &result.Status)
	}
	metric := func(key, name string) {
		r, ok := readings[key+"\x00"]
		m := resourceMetric{Name: name, State: "Unknown", Value: "Unavailable"}
		if ok {
			m.State = state(r)
			if strings.HasPrefix(key, baseline.Prefix) && (result.Evidence.RunID == "" || r.Evidence.RunID != result.Evidence.RunID) {
				m.State = "Historical — unavailable in latest baseline sample"
			}
			m.At = r.Evidence.ObservedAt
			m.Source = r.Evidence.CommandID
			switch r.Evidence.Unit {
			case "bytes":
				m.Value = bytesText(r.Evidence.Value.Integer)
			case "percent":
				m.Value = fmt.Sprintf("%.1f%%", r.Evidence.Value.Number)
			case "load":
				m.Value = fmt.Sprintf("%.2f", r.Evidence.Value.Number)
			}
		}
		result.Metrics = append(result.Metrics, m)
		if key == baseline.Prefix+"cpu_percent" && m.State == "Current" {
			result.CPUText = m.Value
		}
		if key == "linux.mem.available_bytes" && m.State == "Current" {
			result.MemoryText = m.Value + " available"
		}
	}
	metric(baseline.Prefix+"cpu_percent", "CPU utilization (sampled counters)")
	for _, x := range []struct{ k, n string }{{"linux.load.1m", "Load · 1 minute"}, {"linux.load.5m", "Load · 5 minutes"}, {"linux.load.15m", "Load · 15 minutes"}, {"linux.mem.total_bytes", "RAM total"}, {"linux.mem.available_bytes", "RAM available"}, {baseline.Prefix + "swap_total_bytes", "Swap total"}, {baseline.Prefix + "swap_free_bytes", "Swap free"}, {baseline.Prefix + "pressure_some_percent", "Memory pressure · PSI some avg10"}} {
		metric(x.k, x.n)
	}
	total, tok := readings["linux.mem.total_bytes\x00"]
	avail, aok := readings["linux.mem.available_bytes\x00"]
	if tok && aok && total.Evidence.RunID == avail.Evidence.RunID && total.Evidence.Value.Integer >= avail.Evidence.Value.Integer {
		if state(total) == "Current" && state(avail) == "Current" && total.Evidence.Value.Integer > 0 {
			used := total.Evidence.Value.Integer - avail.Evidence.Value.Integer
			result.MemoryGauge = resourceGauge{"Memory", fmt.Sprintf("%.1f%%", 100*float64(used)/float64(total.Evidence.Value.Integer)), bytesText(used) + " / " + bytesText(total.Evidence.Value.Integer) + " · " + bytesText(avail.Evidence.Value.Integer) + " available", "Current", 100 * float64(used) / float64(total.Evidence.Value.Integer), true}
		}
		result.Metrics = append(result.Metrics, resourceMetric{Name: "RAM used (total − available)", Value: bytesText(total.Evidence.Value.Integer - avail.Evidence.Value.Integer), State: state(avail), At: avail.Evidence.ObservedAt, Source: avail.Evidence.CommandID})
	}
	mounts := map[string]bool{}
	for _, r := range out.Readings {
		if strings.HasPrefix(r.Evidence.Key, "linux.filesystem.") {
			mounts[r.Evidence.Resource] = true
		}
	}
	for mount := range mounts {
		r, ok := readings["linux.filesystem.total_bytes\x00"+mount]
		if !ok {
			continue
		}
		row := filesystemRow{Mount: mount, Total: bytesText(r.Evidence.Value.Integer), State: state(r), At: r.Evidence.ObservedAt, Used: "Unknown", Available: "Unknown", Percent: "Unknown"}
		if source, ok := readings["linux.filesystem.identifier\x00"+mount]; ok && source.Evidence.RunID == r.Evidence.RunID {
			row.Technical = transientFilesystem(source.Evidence.Value.Text)
		}
		for _, k := range []string{"used_bytes", "available_bytes", "utilization_percent"} {
			v, ok := readings["linux.filesystem."+k+"\x00"+mount]
			if !ok || v.Evidence.RunID != r.Evidence.RunID || state(v) != row.State {
				continue
			}
			if k == "used_bytes" {
				row.Used = bytesText(v.Evidence.Value.Integer)
			}
			if k == "available_bytes" {
				row.Available = bytesText(v.Evidence.Value.Integer)
			}
			if k == "utilization_percent" {
				row.Percent = fmt.Sprintf("%d%%", v.Evidence.Value.Integer)
			}
		}
		result.Filesystems = append(result.Filesystems, row)
	}
	sort.Slice(result.Filesystems, func(i, j int) bool { return result.Filesystems[i].Mount < result.Filesystems[j].Mount })
	unitStates, jobStates := map[string]string{}, map[string]string{}
	result.ProcessState = "Unknown — no process sample"
	for _, r := range out.Readings {
		if r.Evidence.RunID != result.Evidence.RunID || r.Quality != "valid" {
			continue
		}
		b := []byte(r.Evidence.Value.Text)
		switch r.Evidence.Key {
		case baseline.Prefix + "processes":
			if json.Unmarshal(b, &result.CPU) == nil {
				result.ProcessState = state(r)
			}
		case baseline.Prefix + "units":
			var rows []baseline.Unit
			if json.Unmarshal(b, &rows) == nil {
				unitStates[r.Evidence.Resource] = state(r)
				result.Units = append(result.Units, rows...)
			}
		case baseline.Prefix + "jobs":
			var rows []baseline.Job
			if json.Unmarshal(b, &rows) == nil {
				jobStates[r.Evidence.Resource] = state(r)
				result.Jobs = append(result.Jobs, rows...)
			}
		}
	}
	result.UnitsState = chunkState(unitStates, 32)
	result.JobsState = chunkState(jobStates, 16)
	result.UnitsAvailable = result.UnitsState == "Current"
	result.Memory = append([]baseline.Process(nil), result.CPU...)
	sort.Slice(result.CPU, func(i, j int) bool {
		if result.CPU[i].CPU == result.CPU[j].CPU {
			return result.CPU[i].PID < result.CPU[j].PID
		}
		return result.CPU[i].CPU > result.CPU[j].CPU
	})
	sort.Slice(result.Memory, func(i, j int) bool {
		if result.Memory[i].RSS == result.Memory[j].RSS {
			return result.Memory[i].PID < result.Memory[j].PID
		}
		return result.Memory[i].RSS > result.Memory[j].RSS
	})
	if len(result.CPU) > 10 {
		result.CPU = result.CPU[:10]
	}
	if len(result.Memory) > 10 {
		result.Memory = result.Memory[:10]
	}
	sort.Slice(result.Units, func(i, j int) bool {
		if (result.Units[i].Active == "failed") != (result.Units[j].Active == "failed") {
			return result.Units[i].Active == "failed"
		}
		return result.Units[i].Name < result.Units[j].Name
	})
	resourceGauges(&result)
	return result
}

// Chunked snapshots are current only when every required page is current.
func chunkState(states map[string]string, pages int) string {
	if len(states) != pages {
		return "Unknown — incomplete snapshot"
	}
	first := ""
	for i := 0; i < pages; i++ {
		v, ok := states[fmt.Sprintf("%02d", i)]
		if !ok {
			return "Unknown — incomplete snapshot"
		}
		if first == "" {
			first = v
		}
		if v != first {
			return "Unknown — mixed evidence freshness"
		}
	}
	return first
}
