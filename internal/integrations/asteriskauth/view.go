package asteriskauth

import (
	"strings"
	"time"
)

type Filter struct {
	Type, Account, IP string
	Minutes           int
}
type Group struct {
	Account, IP, Type                 string
	Count, Count5, Count15, CountHour int64
	First, Last                       time.Time
	Repeated                          bool
}
type EventRecord struct {
	Event
	Source, Identity, ParserVersion string
	Generation                      int64
	IngestedAt                      time.Time
}
type View struct {
	Events                                       []EventRecord
	Status, Source                               string
	CheckedAt                                    time.Time
	Current, Security, Gap                       bool
	Rejected                                     int
	Failures5, Failures15, FailuresHour, Sources int64
	Latest                                       time.Time
	Groups                                       []Group
	Cursors                                      map[string]Cursor
	Filter                                       Filter
	Limited                                      bool
}

func (v View) CoverageReason() string {
	switch strings.TrimSuffix(v.Status, "_with_gap") {
	case "not_authorized":
		return "Log collection has not been authorized for this verified connection"
	case "not_scheduled_or_paused":
		return "Monitoring is paused, inactive or not scheduled"
	case "permission_denied":
		return "Access denied to the configured logger source"
	case "missing_source":
		return "Configured log files are missing or are not regular files"
	case "no_configured_source":
		return "No supported log source is configured"
	case "unsupported_configuration":
		return "Logger destinations or includes are outside the supported fixed-source catalog"
	case "stale":
		return "Collection is stale (no successful inspection within 180 seconds)"
	case "backlog":
		return "Bounded collection is processing a backlog"
	case "incomplete_line":
		return "Waiting for an unfinished log line"
	case "incomplete":
		return "Some content or logger configuration could not be interpreted"
	case "unsupported_format":
		return "The inspected source uses an unsupported log format"
	case "changed_during_read":
		return "The source changed during inspection; coverage is incomplete"
	case "current":
		if v.Gap {
			return "A known coverage gap limits this source history"
		}
		return "Current collection"
	case "transport_unavailable":
		return "SSH collection failed; retained history is incomplete"
	default:
		return "Source inspection is unavailable"
	}
}
