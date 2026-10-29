package web

import (
	"noc-workbench/internal/health"
	activity "noc-workbench/internal/integrations/asteriskactivity"
	ami "noc-workbench/internal/integrations/asteriskami"
	"noc-workbench/internal/scheduler"
	"strings"
	"testing"
	"time"
)

func TestMediaExactCorrelationFreshnessAndHistory(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	runtime := strings.Repeat("a", 64)
	base := func() asteriskRegistrationData {
		return asteriskRegistrationData{MediaAuthorized: true, AMI: ami.View{Current: true, Session: ami.Session{ID: "session"}}, Activity: activity.View{Current: true, State: activity.State{Snapshot: activity.Snapshot{Runtime: runtime, Channels: []activity.Channel{{ID: "1.1", Name: "PJSIP/phone-00000001", Endpoint: "phone", Association: "Matches observed endpoint definition"}, {ID: "1.2", Name: "Local (resource omitted)"}}}}}, Media: []ami.MediaRecord{{Runtime: runtime, Session: "session", At: now, Report: ami.MediaReport{Uniqueid: "1.1", Linkedid: "1.2"}}}}
	}
	d := base()
	correlateMedia(&d, now)
	if d.Media[0].Endpoint != "phone" || d.Media[0].Status != "Current" || d.MediaWithCurrent != 1 || d.MediaWithoutCurrent != 1 {
		t.Fatal(d.Media)
	}
	// Several SSRCs/blocks from one channel still count one measured channel.
	d = base()
	d.Media = append(d.Media, d.Media[0])
	correlateMedia(&d, now)
	if d.MediaWithCurrent != 1 {
		t.Fatal("counted streams as channels")
	}
	for _, mutate := range []func(*asteriskRegistrationData){
		func(d *asteriskRegistrationData) { d.Media[0].Runtime = strings.Repeat("b", 64) },
		func(d *asteriskRegistrationData) { d.Media[0].Session = "previous" },
		func(d *asteriskRegistrationData) { d.Media[0].Gap = true },
		func(d *asteriskRegistrationData) { d.Media[0].At = now.Add(-time.Minute) },
		func(d *asteriskRegistrationData) { d.Media[0].At = now.Add(time.Second) },
		func(d *asteriskRegistrationData) { d.AMI.Current = false },
		func(d *asteriskRegistrationData) { d.MediaAuthorized = false },
		func(d *asteriskRegistrationData) { d.Activity.Current = false },
		func(d *asteriskRegistrationData) { d.Media[0].Report.Uniqueid = "" },
	} {
		d = base()
		mutate(&d)
		correlateMedia(&d, now)
		if d.MediaWithCurrent != 0 || d.Media[0].Status == "Current" {
			t.Fatal("uncertain report marked current", d.Media)
		}
	}
	d = base()
	d.Activity.Channels[0].Association = "Unverified"
	correlateMedia(&d, now)
	if d.Media[0].Endpoint != "Unknown" {
		t.Fatal("unverified endpoint joined")
	}
	d = base()
	d.Media[0].Channel = "PJSIP/phone-00000001"
	d.Activity.Channels = nil
	correlateMedia(&d, now)
	if d.Media[0].Channel != "PJSIP/phone-00000001" || d.Media[0].Status == "Current" {
		t.Fatal("terminated history")
	}
}

func TestMediaCLIEligibility(t *testing.T) {
	base := scheduler.Profile{Enabled: true, Authorized: true, EvidenceEligible: true, Collectors: []string{"asterisk.media"}}
	in := health.Input{Active: true, Trusted: true}
	if !mediaCLIEligible(in, base, true, false) {
		t.Fatal("eligible")
	}
	for _, kind := range []string{"paused", "profile_paused", "disabled", "unauthorized", "ineligible", "removed", "untrusted", "inactive", "revoked"} {
		p := base
		i := in
		allowed, paused := true, false
		switch kind {
		case "paused":
			paused = true
		case "profile_paused":
			p.Paused = true
		case "disabled":
			p.Enabled = false
		case "unauthorized":
			p.Authorized = false
		case "ineligible":
			p.EvidenceEligible = false
		case "removed":
			p.Collectors = nil
		case "untrusted":
			i.Trusted = false
		case "inactive":
			i.Active = false
		case "revoked":
			allowed = false
		}
		if mediaCLIEligible(i, p, allowed, paused) {
			t.Fatal(kind)
		}
	}
}
