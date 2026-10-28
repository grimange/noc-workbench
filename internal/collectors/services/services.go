// Package services normalizes bounded runtime evidence; it never performs transport.
package services

import (
	"encoding/json"
	"fmt"
	"noc-workbench/internal/collection"
	"strings"
)

const Collector = "linux.services"
const Key = "linux.service.runtime"
const Version = "1"

// IDs are bounded service identifiers, not inventory associations.
var IDs = []string{"asterisk", "database", "apache", "AST_update.pl", "AST_VDauto_dial.pl", "AST_VDauto_dial_FILL.pl", "AST_manager_send.pl", "AST_manager_listen.pl"}

type Signal struct {
	UnitName string `json:"unit_name"`
	ID       string `json:"id"`
	Binary   string `json:"binary"`
	Unit     string `json:"unit"`
	Active   string `json:"active"`
	Process  string `json:"process"`
	Support  string `json:"support"`
}
type Reading struct {
	Signal
	Present, Runtime, Reason string
	Current                  string
}

func Specs() []collection.Spec {
	return []collection.Spec{{ID: Collector, Version: Version, CommandID: Collector + ".v1", Parse: Parse, Optional: true}}
}
func one(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}
func Valid(s Signal) bool {
	known := false
	for _, id := range IDs {
		known = known || id == s.ID
	}
	return one(s.UnitName, "unknown", "asterisk.service", "mariadb.service", "mysql.service", "mysqld.service", "apache2.service", "httpd.service") && known && one(s.Binary, "present", "unknown") && one(s.Unit, "loaded", "missing", "unavailable") && one(s.Active, "running", "stopped", "other", "unavailable") && one(s.Process, "observed", "not_observed", "unavailable") && one(s.Support, "linux", "svn4034", "unsupported") && (s.Unit == "loaded" || s.Active == "unavailable") && (s.Support != "unsupported" || s.Process == "unavailable")
}
func Parse(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	bad := func() ([]collection.Observation, []collection.Diagnostic) {
		return nil, []collection.Diagnostic{{Code: "parse_error"}}
	}
	if len(b) > 4096 || len(b) == 0 {
		return bad()
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) != len(IDs)+3 || lines[0] != "NW_RUNTIME_1" || lines[len(lines)-2] != "END" || lines[len(lines)-1] != "" {
		return bad()
	}
	out := make([]collection.Observation, 0, len(IDs))
	for i, id := range IDs {
		f := strings.Split(lines[i+1], "|")
		if len(f) != 7 {
			return bad()
		}
		s := Signal{ID: f[0], Binary: f[1], Unit: f[2], Active: f[3], Process: f[4], Support: f[5], UnitName: f[6]}
		if s.ID != id || !Valid(s) {
			return bad()
		}
		v, _ := json.Marshal(s)
		out = append(out, collection.Observation{Key: Key, Resource: id, Unit: "text", Value: collection.Text(string(v))})
	}
	return out, nil
}
func Decode(e collection.Evidence) (Signal, error) {
	var s Signal
	if e.Key != Key || e.CollectorID != Collector || e.CollectorVersion != Version || e.Value.Kind != "text" || len(e.Value.Text) > 512 {
		return s, fmt.Errorf("unsupported runtime evidence")
	}
	dec := json.NewDecoder(strings.NewReader(e.Value.Text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || !Valid(s) || s.ID != e.Resource {
		return Signal{}, fmt.Errorf("invalid runtime evidence")
	}
	encoded, _ := json.Marshal(s)
	if string(encoded) != e.Value.Text {
		return Signal{}, fmt.Errorf("noncanonical runtime evidence")
	}
	return s, nil
}
func Classify(s Signal) Reading {
	r := Reading{Signal: s, Present: "Unknown", Runtime: "Unknown", Reason: "No authoritative runtime evidence"}
	if !Valid(s) {
		return r
	}
	if s.Support == "unsupported" {
		r.Runtime = "Unsupported"
		r.Reason = "VICIdial runtime names require verified source SVN 4034"
		return r
	}
	if s.Binary == "present" || s.Unit == "loaded" || s.Process == "observed" {
		r.Present = "Present"
	}
	switch {
	case s.Process == "observed":
		r.Runtime = "Running"
		r.Reason = "Approved process identity observed; application responsiveness unverified"
		if s.Active == "stopped" {
			r.Reason = "Process observed despite inactive unit; alternate startup observed, application responsiveness unverified"
		}
	case s.Active == "running":
		r.Runtime = "Running"
		r.Reason = "Loaded service unit reports active/running; application responsiveness unverified"
	case s.Active == "stopped" && s.Process == "not_observed":
		r.Runtime = "Stopped"
		r.Reason = "Loaded service unit inactive/failed and approved process not observed"
	case s.Process == "not_observed":
		r.Reason = "Approved process not observed; absence alone does not prove stopped or uninstalled"
	}
	return r
}
