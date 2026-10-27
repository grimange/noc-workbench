package web

import (
	"noc-workbench/internal/alerts"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/health"
	"testing"
	"time"
)

func TestMonitoringAuthentication(t *testing.T) {
	h, _ := fixture(t)
	for _, path := range []string{"/monitoring", "/alerts", "/customers/a/environments/b/assets/c/monitoring", "/customers/a/environments/b/assets/c/events"} {
		if request(h, "GET", path, nil).Code != 401 {
			t.Fatal(path)
		}
	}
}
func TestMonitoringFingerprintExpiryAndAuthority(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	in := health.Input{Scope: collection.HistoryScope{AssetID: "a"}, At: at, Active: true, Trusted: true, Policies: []health.Policy{{ID: "p", Revision: 1, Version: health.Version, Selector: "linux.mem.available_bytes", Rule: "memory_available_low", Threshold: 1, TTLSeconds: 60, Enabled: true, CreatedAt: at}}, Evidence: []collection.Evidence{{Observation: collection.Observation{AssetID: "a", CollectorID: "linux.memory", Key: "linux.mem.available_bytes", Unit: "bytes", Quality: "valid", Value: collection.Integer(5), ObservedAt: at, ReceivedAt: at}}}}
	first, e := monitoringFingerprint(alerts.View{}, in)
	if e != nil {
		t.Fatal(e)
	}
	in.At = at.Add(59 * time.Second)
	before, _ := monitoringFingerprint(alerts.View{}, in)
	if first != before {
		t.Fatal("age-only notification")
	}
	in.At = at.Add(60 * time.Second)
	expiry, _ := monitoringFingerprint(alerts.View{}, in)
	if expiry == first {
		t.Fatal("exact expiry missing")
	}
	in.At = at
	in.Trusted = false
	revoked, _ := monitoringFingerprint(alerts.View{}, in)
	if revoked == first {
		t.Fatal("authority change missing")
	}
}
