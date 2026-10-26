package interchange

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExampleAndSanitization(t *testing.T) {
	d, e := Parse(Example)
	if e != nil {
		t.Fatal(e)
	}
	if len(d.Records) < 40 {
		t.Fatal("insufficient fixture graph")
	}
	for i := range d.Records {
		r := &d.Records[i]
		if r.Type == "customer" {
			r.Fields["display_name"] = "Synthetic sensitive marker"
		}
		if r.Type == "asset_endpoint" {
			r.Fields["host"] = "sensitive.example.invalid"
		}
		if r.Type == "cluster_membership" {
			r.Fields["role"] = "sensitive-role"
		}
	}
	clean := Sanitize(d)
	if e = Validate(clean); e != nil {
		t.Fatal(e)
	}
	a, e := Encode(clean)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := Encode(clean)
	if !bytes.Equal(a, b) || bytes.Contains(a, []byte("sensitive")) {
		t.Fatal("nondeterministic or unsanitized export")
	}
	if _, e = Parse(a); e != nil {
		t.Fatal(e)
	}
}
func TestRejectDocuments(t *testing.T) {
	for _, raw := range []string{"{}", "null", `{"format":"other","version":1,"records":[]}`, `{"format":"noc-workbench.sanitized-inventory","version":2,"records":[]}`, string(Example) + "{}", strings.Repeat(" ", MaxBytes+1)} {
		if _, e := Parse([]byte(raw)); e == nil {
			t.Fatal("accepted malformed/version/size")
		}
	}
	for _, change := range []func(*Document){
		func(d *Document) { d.Records[0].ID = "not-uuid" },
		func(d *Document) { d.Records = append(d.Records, d.Records[0]) },
		func(d *Document) { d.Records[0].Fields["password"] = "secret" },
		func(d *Document) {
			for i := range d.Records {
				if d.Records[i].Type == "asset_endpoint" {
					d.Records[i].Fields["port"] = "22"
					return
				}
			}
		},
		func(d *Document) {
			for i := range d.Records {
				if d.Records[i].Type == "asset_endpoint" {
					d.Records[i].Fields["asset_id"] = d.Records[0].ID
					return
				}
			}
		},
		func(d *Document) {
			for i := range d.Records {
				if d.Records[i].Type == "cluster_membership" {
					for _, x := range d.Records {
						if x.Type == "asset" && x.String("environment_id") != d.Records[i].String("environment_id") {
							d.Records[i].Fields["asset_id"] = x.ID
							return
						}
					}
				}
			}
		},
	} {
		d, e := Parse(Example)
		if e != nil {
			t.Fatal(e)
		}
		change(&d)
		raw, _ := json.Marshal(d)
		if _, e = Parse(raw); e == nil {
			t.Fatal("accepted invalid graph")
		}
	}
}

func TestStrictJSON(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"format":"x","format":"noc-workbench.sanitized-inventory","version":1,"records":[]}`),
		[]byte(`{"format":"noc-workbench.sanitized-inventory","version":1,"records":[],"records":[]}`),
		[]byte(strings.Repeat("[", 20) + strings.Repeat("]", 20)),
		{0xff},
	} {
		if _, err := Parse(raw); err == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}
