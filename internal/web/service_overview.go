package web

import (
	"fmt"
	"strconv"
)

// Overview projections use already qualified evidence; they never collect or
// promote a historical measurement into a current condition.
type serviceIndicator struct{ Label, Value, Detail string }
type serviceOverview struct {
	Indicators []serviceIndicator
	Issues     []string
	MoreIssues int
}

func (d asteriskRegistrationData) Overview() serviceOverview {
	o := serviceOverview{}
	cli := "Unavailable or historical"
	families, issues := 0, 0
	for _, f := range d.Families {
		if !f.Current || f.Snapshot.Status != "supported" {
			continue
		}
		families++
		for _, r := range f.Snapshot.Rows {
			outbound := f.Name == "sip registry" || f.Name == "pjsip registrations"
			failed := outbound && (r.Registration == "Rejected" || r.Registration == "Unregistered" || r.Registration == "Stopped" || r.Registration == "Timeout" || r.Registration == "No Authentication" || r.Registration == "Failed")
			if r.Reachability == "Unreachable" || failed {
				issues++
				kind := "Peer/contact unreachable"
				if outbound {
					kind = "Outbound registration " + r.Registration
				}
				o.addIssue(kind + ": " + r.ID)
			}
		}
	}
	if families > 0 {
		cli = "CLI responding"
	}
	reg := "Unavailable"
	if families > 0 {
		reg = fmt.Sprintf("%d observed issues", issues)
	}
	o.Indicators = append(o.Indicators, serviceIndicator{"Asterisk monitoring", cli, "AMI " + d.AMI.State}, serviceIndicator{"Registration issues", reg, fmt.Sprintf("%d current supported snapshot families", families)})
	channels := "Unverified"
	if d.Activity.Current {
		channels = strconv.Itoa(d.ChannelCount)
	}
	o.Indicators = append(o.Indicators, serviceIndicator{"Active channels", channels, "Channels, not calls"})
	failures := "Unavailable"
	coverage := d.Auth.CoverageReason()
	if d.Auth.Current {
		failures = fmt.Sprintf("%d in 5 minutes", d.Auth.Failures5)
		coverage = "Current source inspection"
		if d.Auth.Gap {
			coverage = "Observed content only · historical coverage gap"
		}
	}
	o.Indicators = append(o.Indicators, serviceIndicator{"Authentication failures", failures, coverage})
	if !d.AMI.Current {
		o.addIssue("AMI " + d.AMI.State + " — " + d.AMI.Reason)
	}
	if !d.Activity.Current {
		o.addIssue("Current channel reconciliation unavailable — " + d.Activity.Reason)
	}
	if d.Auth.Current {
		for _, g := range d.Auth.Groups {
			if g.Repeated {
				account := g.Account
				if account == "" {
					account = "Unknown"
				}
				ip := g.IP
				if ip == "" {
					ip = "Unknown"
				}
				o.addIssue("Repeated authentication failures observed for account " + account + " · observed source IP " + ip)
			}
		}
	}
	return o
}

func (d mariaDBData) Overview() serviceOverview {
	o := serviceOverview{}
	ready, connected, running := d.Readiness, "Unavailable", "Unavailable"
	if d.Current {
		ready = "Ready"
		if d.Sample != nil {
			m := d.Sample.Snapshot.Metrics
			if n, ok := m["Threads_connected"]; ok {
				connected = strconv.FormatUint(n, 10)
				if max, yes := m["max_connections"]; yes && max > 0 {
					connected = fmt.Sprintf("%d / %d (%.1f%%)", n, max, 100*float64(n)/float64(max))
				}
			}
			if n, ok := m["Threads_running"]; ok {
				running = strconv.FormatUint(n, 10)
			}
			for _, c := range d.Sample.Snapshot.Channels {
				if c.Condition() != "Operating" {
					o.addIssue(c.NameDisplay() + ": " + c.Condition() + " · lag " + c.LagDisplay())
				}
			}
		}
	}
	if !d.Current && ready == "Unknown" {
		ready = "Unknown / unavailable"
	}
	o.Indicators = []serviceIndicator{{"Database readiness", ready, d.State}, {"Connections", connected, "Connected / maximum configured"}, {"Running threads", running, "Currently executing threads"}, {"Replication condition", d.Replication, "Database role: " + d.Role}}
	return o
}
func (d mariaDBData) Capacity() *float64 {
	if !d.Current || d.Sample == nil {
		return nil
	}
	m := d.Sample.Snapshot.Metrics
	n, ok := m["Threads_connected"]
	max, yes := m["max_connections"]
	if !ok || !yes || max == 0 {
		return nil
	}
	p := 100 * float64(n) / float64(max)
	return &p
}
func (d mariaDBData) MetricLabel(name string) string {
	switch name {
	case "Threads_connected":
		return "Connections"
	case "Threads_running":
		return "Running threads"
	case "Max_used_connections":
		return "Peak connections"
	case "Connections":
		return "Total connection attempts since startup"
	case "Aborted_connects":
		return "Failed connection attempts since startup"
	case "Uptime":
		return "Database uptime (seconds)"
	case "max_connections":
		return "Maximum configured connections"
	}
	return name
}

// Keep the overview bounded; investigation retains all accepted rows.
func (o *serviceOverview) addIssue(issue string) {
	if len(o.Issues) < 4 {
		o.Issues = append(o.Issues, issue)
	} else {
		o.MoreIssues++
	}
}
func (d asteriskRegistrationData) MediaSummary() string {
	if !d.MediaAuthorized {
		return "Media statistics unavailable"
	}
	if !d.AMI.Current {
		return "AMI reporting interrupted · media evidence historical"
	}
	if len(d.Media) > 0 {
		return "Retained media observations available below"
	}
	return "No RTCP reports retained (latest 100, up to 7 days)"
}
