// Package interchange defines a bounded topology-only interchange, never a backup.
package interchange

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"noc-workbench/internal/inventory"
	"sort"
	"strings"
	"unicode/utf8"
)

const Format = "noc-workbench.sanitized-inventory"
const Version = 1
const MaxBytes = 262144
const MaxRecords = 500

type Document struct {
	Format  string   `json:"format"`
	Version int      `json:"version"`
	Records []Record `json:"records"`
}
type Record struct {
	Type   string         `json:"type"`
	ID     string         `json:"id"`
	Fields map[string]any `json:"fields"`
}
type Definition struct {
	Table   string
	Columns []string
}

// Definitions are compiled allowlists, never supplied by the uploaded document.
var Definitions = []Definition{
	{"customer", []string{"display_name", "short_code", "status"}},
	{"environment", []string{"customer_id", "name", "kind", "status"}},
	{"cluster", []string{"environment_id", "name", "type", "lifecycle"}},
	{"asset", []string{"environment_id", "name", "kind", "lifecycle"}},
	{"asset_endpoint", []string{"environment_id", "asset_id", "protocol", "host", "port", "preferred", "status"}},
	{"cluster_membership", []string{"environment_id", "cluster_id", "asset_id", "role"}},
	{"service", []string{"environment_id", "cluster_id", "name", "service_type", "lifecycle"}},
	{"service_instance", []string{"environment_id", "service_id", "name", "role", "instance_key", "lifecycle"}},
	{"service_instance_host", []string{"environment_id", "service_instance_id", "asset_id", "binding_role"}},
}

func DefinitionFor(kind string) (Definition, bool) {
	for _, d := range Definitions {
		if d.Table == kind {
			return d, true
		}
	}
	return Definition{}, false
}
func (r Record) String(k string) string { v, _ := r.Fields[k].(string); return v }
func Parse(raw []byte) (Document, error) {
	var d Document
	if len(raw) > MaxBytes {
		return d, errors.New("Inventory JSON exceeds 256 KiB.")
	}
	if !utf8.Valid(raw) || checkJSON(raw) != nil {
		return d, errors.New("Invalid JSON, duplicate fields, or excessive nesting.")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if e := dec.Decode(&d); e != nil {
		return d, errors.New("Invalid inventory JSON or unsupported fields.")
	}
	if dec.Decode(new(any)) != io.EOF {
		return d, errors.New("Use exactly one JSON document.")
	}
	if e := Validate(d); e != nil {
		return d, e
	}
	Sort(&d)
	return d, nil
}
func Sort(d *Document) {
	rank := map[string]int{}
	for i, x := range Definitions {
		rank[x.Table] = i
	}
	sort.Slice(d.Records, func(i, j int) bool {
		a, b := d.Records[i], d.Records[j]
		if a.Type != b.Type {
			return rank[a.Type] < rank[b.Type]
		}
		return a.ID < b.ID
	})
}
func Encode(d Document) ([]byte, error) {
	Sort(&d)
	b, e := json.MarshalIndent(d, "", "  ")
	if len(b)+1 > MaxBytes {
		return nil, errors.New("Inventory exceeds the 256 KiB export limit.")
	}
	return append(b, '\n'), e
}
func Validate(d Document) error {
	if d.Format != Format || d.Version != Version {
		return errors.New("Unsupported inventory format/version; expected sanitized-inventory version 1.")
	}
	if d.Records == nil {
		return errors.New("The records array is required (use [] for empty inventory).")
	}
	if len(d.Records) > MaxRecords {
		return errors.New("Inventory is limited to 500 records.")
	}
	refs := map[string]Record{}
	fail := func(i int, msg string) error { return fmt.Errorf("Record %d: %s", i+1, msg) }
	for i, r := range d.Records {
		def, ok := DefinitionFor(r.Type)
		if !ok || !inventory.ValidID(r.ID) {
			return fail(i, "invalid entity type or UUID.")
		}
		if _, ok = refs[r.ID]; ok {
			return fail(i, "duplicate UUID in document.")
		}
		refs[r.ID] = r
		if len(r.Fields) != len(def.Columns) {
			return fail(i, "missing or unsupported topology fields.")
		}
		for _, k := range def.Columns {
			v, ok := r.Fields[k]
			if !ok {
				return fail(i, "missing required field.")
			}
			switch k {
			case "port":
				n, ok := v.(json.Number)
				if !ok {
					return fail(i, "port must be an integer.")
				}
				p, e := n.Int64()
				if e != nil || p < 1 || p > 65535 {
					return fail(i, "port must be 1–65535.")
				}
			case "preferred":
				if _, ok := v.(bool); !ok {
					return fail(i, "preferred must be boolean.")
				}
			default:
				s, ok := v.(string)
				limit := 120
				if k == "host" {
					limit = 253
				}
				if !ok || len(s) > limit || strings.TrimSpace(s) != s || strings.ContainsAny(s, "\x00\r\n\t") {
					return fail(i, "invalid plain-text field.")
				}
				if strings.HasSuffix(k, "_id") && !(k == "cluster_id" && s == "") && !inventory.ValidID(s) {
					return fail(i, "invalid reference UUID.")
				}
			}
		}
		var e error
		switch r.Type {
		case "customer":
			if r.String("short_code") != strings.ToUpper(r.String("short_code")) {
				return fail(i, "customer short code must be uppercase.")
			}
			_, e = inventory.ValidateCustomer(inventory.Customer{ID: r.ID, DisplayName: r.String("display_name"), ShortCode: r.String("short_code"), Status: r.String("status")})
		case "environment":
			_, e = inventory.ValidateEnvironment(inventory.Environment{ID: r.ID, CustomerID: r.String("customer_id"), Name: r.String("name"), Kind: r.String("kind"), Status: r.String("status")})
		case "cluster":
			_, e = inventory.ValidateCluster(inventory.Cluster{ID: r.ID, EnvironmentID: r.String("environment_id"), Name: r.String("name"), Type: r.String("type"), Lifecycle: r.String("lifecycle")})
		case "asset":
			_, e = inventory.ValidateAsset(inventory.Asset{ID: r.ID, EnvironmentID: r.String("environment_id"), Name: r.String("name"), Kind: r.String("kind"), Lifecycle: r.String("lifecycle")})
		case "asset_endpoint":
			p, _ := r.Fields["port"].(json.Number).Int64()
			_, e = inventory.ValidateEndpoint(inventory.Endpoint{ID: r.ID, EnvironmentID: r.String("environment_id"), AssetID: r.String("asset_id"), Protocol: r.String("protocol"), Host: r.String("host"), Port: int(p), Status: r.String("status")})
		case "cluster_membership":
			_, e = inventory.ValidateMembership(inventory.Membership{ID: r.ID, EnvironmentID: r.String("environment_id"), ClusterID: r.String("cluster_id"), AssetID: r.String("asset_id"), Role: r.String("role")})
		case "service":
			_, e = inventory.ValidateService(inventory.Service{ID: r.ID, EnvironmentID: r.String("environment_id"), ClusterID: r.String("cluster_id"), Name: r.String("name"), ServiceType: r.String("service_type"), Lifecycle: r.String("lifecycle")})
		case "service_instance":
			_, e = inventory.ValidateInstance(inventory.Instance{ID: r.ID, EnvironmentID: r.String("environment_id"), ServiceID: r.String("service_id"), Name: r.String("name"), Role: r.String("role"), InstanceKey: r.String("instance_key"), Lifecycle: r.String("lifecycle")})
		case "service_instance_host":
			_, e = inventory.ValidateBinding(inventory.Binding{ID: r.ID, EnvironmentID: r.String("environment_id"), InstanceID: r.String("service_instance_id"), AssetID: r.String("asset_id"), BindingRole: r.String("binding_role")})
		}
		if e != nil {
			return fail(i, "invalid fields for this entity.")
		}
	}
	for i, r := range d.Records {
		for k, v := range r.Fields {
			if !strings.HasSuffix(k, "_id") || v == "" {
				continue
			}
			id, _ := v.(string)
			parent, ok := refs[id]
			kind := strings.TrimSuffix(k, "_id")
			if !ok || parent.Type != kind {
				return fail(i, "reference is missing or has the wrong entity type.")
			}
			if k != "customer_id" && k != "environment_id" && parent.String("environment_id") != r.String("environment_id") {
				return fail(i, "cross-environment relationship rejected.")
			}
		}
	}
	return nil
}
func Pseudonym(id string) string {
	h := sha256.Sum256([]byte("noc-workbench.sanitized.v1:" + id))
	h[6] = (h[6] & 15) | 80
	h[8] = (h[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// Sanitize discards all free-text identifiers; only bounded structural enums survive.
func Sanitize(d Document) Document {
	for i := range d.Records {
		r := &d.Records[i]
		r.ID = Pseudonym(r.ID)
		for k, v := range r.Fields {
			s, _ := v.(string)
			switch {
			case strings.HasSuffix(k, "_id"):
				if s != "" {
					r.Fields[k] = Pseudonym(s)
				}
			case k == "name" || k == "display_name":
				r.Fields[k] = "Synthetic " + r.Type + " " + r.ID
			case k == "short_code":
				r.Fields[k] = "S" + strings.ToUpper(strings.ReplaceAll(r.ID, "-", "")[:22])
			case k == "host":
				r.Fields[k] = "endpoint-" + r.ID + ".example.invalid"
			case k == "role" || k == "binding_role":
				r.Fields[k] = "member"
			case k == "instance_key":
				r.Fields[k] = r.ID
			case k == "type" || k == "service_type":
				r.Fields[k] = "generic"
			}
		}
	}
	Sort(&d)
	return d
}

// Check tokens before decoding maps: duplicate keys must never silently win.
func checkJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("nesting")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate key")
				}
				seen[name] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('}'), json.Delim(']'):
			return errors.New("unexpected delimiter")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
