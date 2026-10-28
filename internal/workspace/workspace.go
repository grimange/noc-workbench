// Package workspace owns operator organization and explicit access/query boundaries.
// It does not execute connections or implement multi-user authentication.
package workspace

import (
	"errors"
	"net/url"
	"noc-workbench/internal/inventory"
	"strconv"
	"strings"
	"unicode"
)

const OperatorID = "00000000-0000-4000-8000-000000000001"

type Principal struct{ ID string }
type Permission string

const (
	ScheduleManage  Permission = "collection.schedule.manage"
	InventoryExport Permission = "inventory.export.sanitized"
	InventoryImport Permission = "inventory.import"
	Search          Permission = "inventory.search"
	Organize        Permission = "workspace.organize"
	NotesRead       Permission = "notes.read"
	NotesWrite      Permission = "notes.write"
	LinksWrite      Permission = "links.write"
)

var ErrLimit = errors.New("This collection is limited to 100 records. Remove an existing record before adding another.")

var ErrDenied = errors.New("access denied")

// Scope is deny-by-default. Future authorization must resolve these filters before
// repository retrieval, including counts. Empty scope never means global access.
type Scope struct {
	All                     bool
	Customers, Environments []string
}
type Policy interface {
	Scope(Principal, Permission) (Scope, error)
}
type LocalOperatorPolicy struct{}

func (LocalOperatorPolicy) Scope(p Principal, permission Permission) (Scope, error) {
	if p.ID != OperatorID {
		return Scope{}, ErrDenied
	}
	switch permission {
	case ScheduleManage, Search, Organize, NotesRead, NotesWrite, LinksWrite, InventoryExport, InventoryImport:
		return Scope{All: true}, nil
	}
	return Scope{}, ErrDenied
}
func (s Scope) Allows(customer, environment string) bool {
	if s.All {
		return true
	}
	for _, id := range s.Customers {
		if id == customer {
			return true
		}
	}
	for _, id := range s.Environments {
		if environment != "" && id == environment {
			return true
		}
	}
	return false
}
func Query(raw string) (string, error) {
	if len(raw) > 120 {
		return "", errors.New("Search is limited to 120 bytes.")
	}
	words := strings.FieldsFunc(strings.ToLower(raw), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' })
	if len(words) > 8 {
		return "", errors.New("Use up to eight search terms.")
	}
	clean := words[:0]
	for _, word := range words {
		word = strings.Trim(word, ".")
		if word != "" {
			clean = append(clean, word+":*")
		}
	}
	words = clean
	return strings.Join(words, " & "), nil
}

type Target struct{ Kind, ID, CustomerID, EnvironmentID, Label, Customer, Environment, Lifecycle, URL, Summary string }

func (t Target) QuickURL() string { return "/workspace/" + t.Kind + "/" + t.ID }

type Note struct{ ID, PrincipalID, Body, Visibility, UpdatedAt string }
type Link struct {
	ID, Label, URL, Type, UpdatedAt string
	Pinned                          bool
	Enabled                         bool
}

func ValidateNote(body, visibility string) (string, error) {
	body = strings.TrimSpace(body)
	if len(body) < 1 || len(body) > 4096 || strings.ContainsRune(body, 0) {
		return body, errors.New("Notes require 1–4096 bytes of plain text.")
	}
	if visibility != "private" && visibility != "shared" {
		return body, errors.New("Choose private or shared visibility.")
	}
	return body, nil
}
func ValidateLink(label, raw, kind string) error {
	if label != strings.TrimSpace(label) || len(label) < 1 || len(label) > 120 || strings.ContainsAny(label, "\n\r\t") {
		return errors.New("Link label requires 1–120 bytes on one line.")
	}
	if len(raw) > 2048 || strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return errors.New("Use a valid credential-free HTTP(S) URL.")
	}
	u, e := url.Parse(raw)
	if e != nil || u.Opaque != "" || u.User != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("Use an HTTP(S) URL without credentials, query parameters or fragments.")
	}
	// Inventory host validation also rejects shell syntax, zone IDs and ambiguous addresses.
	_, e = inventory.ValidateEndpoint(inventory.Endpoint{EnvironmentID: OperatorID, AssetID: OperatorID, Protocol: u.Scheme, Host: u.Hostname(), Port: 443, Status: "active"})
	if e != nil {
		return errors.New("Use a valid URL hostname or IP address.")
	}
	if u.Port() != "" {
		port, e := strconv.Atoi(u.Port())
		if e != nil || port < 1 || port > 65535 {
			return errors.New("Invalid URL port.")
		}
	}
	switch kind {
	case "rtm", "admin", "dashboard", "support", "other":
		return nil
	}
	return errors.New("Choose a supported link type.")
}

type Change struct {
	Operation, ID, Body, Visibility, Label, URL, Type string
	Pinned                                            bool
	Disabled                                          bool
}
