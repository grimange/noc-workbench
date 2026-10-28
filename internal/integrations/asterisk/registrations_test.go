package asterisk

import (
	"encoding/json"
	"noc-workbench/internal/collection"
	"strings"
	"testing"
)

func registrationBundle(version string, sources map[string]string) []byte {
	var b strings.Builder
	b.WriteString("Asterisk " + version + " built by synthetic on Linux\n")
	for _, source := range RegistrationSources {
		b.WriteString("\nNW_REGISTRATIONS_" + source + "\n")
		v, ok := sources[source]
		if !ok {
			v = "No such command 'unsupported'"
		}
		b.WriteString(v)
	}
	b.WriteString("\nNW_REGISTRATIONS_END\n")
	return []byte(b.String())
}
func TestRegistrationFamilies(t *testing.T) {
	cases := []struct {
		name, source, data, state, reach string
		count                            int
	}{
		{"sip dynamic", "sip_peers", "Name/username Host Dyn Forcerport Comedia ACL Port Status Description\nphone/phone 192.0.2.1 D Yes Yes 5060 OK (12 ms)\n1 sip peers [Monitored: 1 online, 0 offline]", "Dynamic binding observed", "Reachable", 1},
		{"sip missing", "sip_peers", "Name/username Host Dyn Forcerport Comedia ACL Port Status Description\nphone (Unspecified) D Yes Yes 0 UNKNOWN\n1 sip peers [Monitored: 0 online, 1 offline]", "Dynamic binding not observed", "Unknown", 1},
		{"sip static", "sip_peers", "Name/username Host Dyn Forcerport Comedia ACL Port Status Description\ntrunk 192.0.2.1 Yes Yes 5060 UNREACHABLE\n1 sip peers [Monitored: 0 online, 1 offline]", "Static peer; registration unknown", "Unreachable", 1},
		{"endpoint contact", "pjsip_endpoints", "Endpoint: <Endpoint/CID> <State> <Channels>\n Aor: <Aor> <MaxContact>\nEndpoint: phone/private-caller Not in use 0 of inf\n Aor: phone 1\n Contact: phone/sip:phone@192.0.2.2 hash Avail 4.000\nObjects found: 1", "Contact present; registration unknown", "Unknown", 1},
		{"endpoint empty", "pjsip_endpoints", "Endpoint: <Endpoint/CID> <State> <Channels>\nEndpoint: phone Unavailable 0 of inf\n Aor: phone 1\nObjects found: 1", "No contact observed", "Unknown", 1},
		{"static or dynamic unknown", "pjsip_contacts", "Contact: <Aor/ContactUri> <Hash> <Status> <RTT(ms)>\nContact: phone/sip:user:secret@192.0.2.2:5060;password=secret?token=secret abcdef0123 Avail 2.500\nObjects found: 1", "Contact present; registration unknown", "Reachable", 1},
		{"contact unreachable", "pjsip_contacts", "Contact: <Aor/ContactUri> <Hash> <Status> <RTT(ms)>\nContact: phone/sip:phone@192.0.2.2 abcdef0123 Unavail nan\nObjects found: 1", "Contact present; registration unknown", "Unreachable", 1},
		{"outbound sip", "sip_registry", "Host dnsmgr Username Refresh State Reg.Time\nregistrar.example.invalid:5060 N trunk 105 Registered Wed\n1 SIP registrations.", "Registered", "Unknown", 1},
		{"outbound pjsip", "pjsip_registrations", "<Registration/ServerURI> <Auth> <Status>\ntrunk/sip:registrar.example.invalid private-auth Registered (exp. 40s)\nObjects found: 1", "Registered", "Unknown", 1},
		{"unregistered", "pjsip_registrations", "<Registration/ServerURI> <Auth> <Status>\ntrunk/sip:registrar.example.invalid private-auth Unregistered\nObjects found: 1", "Unregistered", "Unknown", 1},
		{"empty", "pjsip_contacts", "No objects found.", "", "", 0},
		{"empty SIP", "sip_peers", "Name/username Host Dyn Forcerport Comedia ACL Port Status Description\n0 sip peers [Monitored: 0 online, 0 offline]", "", "", 0},
	}
	for _, version := range []string{"18.26.4-vici", "20.20.1"} {
		for _, tc := range cases {
			t.Run(version+"/"+tc.name, func(t *testing.T) {
				obs, diag := Registrations(registrationBundle(version, map[string]string{tc.source: tc.data}))
				if len(diag) > 0 {
					t.Fatalf("%+v", diag)
				}
				var evidence []collection.Evidence
				var manifest collection.Evidence
				for _, o := range obs {
					e := collection.Evidence{Observation: o, RunID: "synthetic"}
					evidence = append(evidence, e)
					if o.Resource == tc.source {
						manifest = e
					}
					if len(o.Value.Text) > 4096 || strings.Contains(o.Value.Text, "secret") || strings.Contains(o.Value.Text, "private-auth") || strings.Contains(o.Value.Text, "private-caller") {
						t.Fatal("leak or oversized observation")
					}
				}
				snap, e := DecodeRegistration(manifest, evidence)
				if e != nil || snap.Count != tc.count || snap.Status != "supported" {
					t.Fatalf("%+v %v", snap, e)
				}
				if tc.count > 0 && (snap.Rows[0].Registration != tc.state || snap.Rows[0].Reachability != tc.reach) {
					t.Fatalf("%+v", snap.Rows)
				}
			})
		}
	}
}
func TestRegistrationFailuresAndIsolation(t *testing.T) {
	for _, bad := range []string{"Permission denied", "Unable to connect to remote asterisk", "unparseable output", "", "Objects found: 1"} {
		obs, diag := Registrations(registrationBundle("20.20.1", map[string]string{"sip_peers": bad, "pjsip_contacts": "No objects found."}))
		if len(diag) != 1 {
			t.Fatalf("%q %+v", bad, diag)
		}
		found := false
		for _, o := range obs {
			if o.Resource == "sip_peers" {
				t.Fatal("failed observation replaced valid manifest")
			}
			if o.Resource == "pjsip_contacts" {
				found = true
			}
		}
		if !found {
			t.Fatal("one family discarded another")
		}
	}
	for _, b := range [][]byte{[]byte(strings.Repeat("x", 65537)), []byte("Asterisk 22.0.0\n"), []byte("Asterisk 20.20.1\x00"), []byte("NW_ASTERISK_NOT_INSTALLED")} {
		obs, d := Registrations(b)
		if len(obs) != 0 || len(d) == 0 {
			t.Fatal("accepted malformed output")
		}
	}
}
func TestRegistrationPagingAndEmptyReplacement(t *testing.T) {
	var b strings.Builder
	b.WriteString("Contact: <Aor/ContactUri> <Hash> <Status> <RTT(ms)>\n")
	for i := 0; i < 200; i++ {
		b.WriteString(strings.ReplaceAll("Contact: phoneN/sip:phone@192.0.2.2 abcdef0123 Avail 1.000\n", "N", strconvI(i)))
	}
	b.WriteString("Objects found: 200")
	obs, d := Registrations(registrationBundle("20.20.1", map[string]string{"pjsip_contacts": b.String()}))
	if len(d) != 0 {
		t.Fatal(d)
	}
	var es []collection.Evidence
	var m collection.Evidence
	for _, o := range obs {
		e := collection.Evidence{Observation: o, RunID: "old"}
		es = append(es, e)
		if o.Resource == "pjsip_contacts" {
			m = e
		}
		if len(o.Value.Text) > 4096 {
			t.Fatal("page exceeds SQL bound")
		}
	}
	s, e := DecodeRegistration(m, es)
	if e != nil || s.Count != 200 || s.Pages < 2 {
		t.Fatalf("%+v %v", s, e)
	}
	m.RunID = "new"
	m.Value = collection.Text(`{"version":"20.20.1","status":"supported","count":0,"pages":0}`)
	s, e = DecodeRegistration(m, es)
	if e != nil || len(s.Rows) != 0 {
		t.Fatal("old contacts survived empty manifest")
	}
	m.Value = collection.Text(`{"version":"20.20.1","status":"supported","count":1,"pages":1}`)
	if _, e = DecodeRegistration(m, es); e == nil {
		t.Fatal("cross-run pages accepted")
	}
}
func strconvI(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestRegistrationCombinedDriversAndOversizedRow(t *testing.T) {
	inputs := map[string]string{
		"sip_peers":      "Name/username Host Dyn Forcerport Comedia ACL Port Status Description\nphone 192.0.2.1 D Yes Yes 5060 OK (2 ms)\n1 sip peers [Monitored: 1 online, 0 offline]",
		"pjsip_contacts": "Contact: <Aor/ContactUri> <Hash> <Status> <RTT(ms)>\nContact: phone/sip:phone@192.0.2.2 abcdef0123 Avail 2.5\nObjects found: 1",
	}
	obs, d := Registrations(registrationBundle("20.20.1", inputs))
	if len(d) != 0 || len(obs) != 7 {
		t.Fatalf("combined drivers: %d %+v", len(obs), d)
	}
	inputs["pjsip_endpoints"] = "Endpoint: <Endpoint/CID> <State> <Channels>\nEndpoint: phone Not in use 0 of inf\n" + strings.Repeat("Aor: "+strings.Repeat("x", 120)+" 1\n", 40) + "Objects found: 1"
	obs, d = Registrations(registrationBundle("20.20.1", inputs))
	if len(obs) != 0 || len(d) == 0 {
		t.Fatal("oversized individual row accepted")
	}
}
