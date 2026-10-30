package mariadb

import (
	"strconv"
	"time"
)

// Samples are journal projections, never a second latest-value store.
type Sample struct {
	Snapshot                     Snapshot
	At, Received                 time.Time
	RunID, ProfileID, EndpointID string
	ProfileVersion               int64
	TTL                          int
}
type Attempt struct {
	At      time.Time
	Outcome string
	Codes   []string
}
type History struct {
	Samples []Sample
	Attempt Attempt
}
type Metric struct{ Name, Value, Meaning string }

func (s Snapshot) Activity() []Metric {
	meanings := []string{"current connections", "currently executing threads", "connection high-water mark since startup", "cumulative connection attempts since startup", "cumulative failed connection attempts since startup", "seconds since database startup", "configured connection capacity"}
	out := []Metric{}
	for i, key := range Metrics {
		v := "Unavailable"
		if n, ok := s.Metrics[key]; ok {
			v = strconv.FormatUint(n, 10)
		}
		out = append(out, Metric{key, v, meanings[i]})
	}
	return out
}
func (c Channel) LagDisplay() string {
	if c.Lag == nil {
		return "Unavailable (NULL)"
	}
	return strconv.FormatUint(*c.Lag, 10) + " seconds"
}
func (c Channel) NameDisplay() string {
	if c.Name == "" {
		return "Default"
	}
	return c.Name
}
func (c Channel) ErrorDisplay() string {
	if c.IOError == 0 && c.SQLError == 0 {
		return "No error numbers reported"
	}
	return "I/O errno " + strconv.FormatUint(c.IOError, 10) + "; SQL errno " + strconv.FormatUint(c.SQLError, 10) + ". Server error text omitted to protect SQL/credentials."
}
