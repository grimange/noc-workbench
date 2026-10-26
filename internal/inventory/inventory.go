// Package inventory models explicitly entered, vendor-neutral local inventory.
package inventory

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrNotFound    = errors.New("inventory record not found")
	ErrUnavailable = errors.New("inventory storage unavailable")
	ErrArchived    = errors.New("restore the customer before changing environments")
)

// FieldErrors contains fixed, safe messages keyed by form field name.
type FieldErrors map[string]string

func (FieldErrors) Error() string { return "invalid inventory fields" }

type Customer struct {
	ID, DisplayName, ShortCode, Notes, Status string
	CreatedAt, UpdatedAt                      time.Time
	EnvironmentCount                          int
}
type Environment struct {
	ID, CustomerID, Name, Kind, Status string
	CreatedAt, UpdatedAt               time.Time
}

type Repository interface {
	ListCustomers(context.Context) ([]Customer, error)
	Customer(context.Context, string) (Customer, error)
	CreateCustomer(context.Context, Customer) (Customer, error)
	UpdateCustomer(context.Context, Customer) (Customer, error)
	ListEnvironments(context.Context, string) ([]Environment, error)
	Environment(context.Context, string, string) (Environment, error)
	CreateEnvironment(context.Context, Environment) (Environment, error)
	UpdateEnvironment(context.Context, Environment) (Environment, error)
}

var codePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{1,23}$`)
var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidID(id string) bool { return idPattern.MatchString(id) }

func validName(s string, max int) bool {
	return utf8.ValidString(s) && len(s) > 0 && len(s) <= max && strings.IndexFunc(s, unicode.IsControl) < 0
}
func lifecycle(s string) bool { return s == "active" || s == "archived" }

func ValidateCustomer(c Customer) (Customer, error) {
	c.DisplayName = strings.TrimSpace(c.DisplayName)
	c.ShortCode = strings.ToUpper(strings.TrimSpace(c.ShortCode))
	c.Notes = strings.TrimSpace(c.Notes)
	e := FieldErrors{}
	if !validName(c.DisplayName, 120) {
		e["display_name"] = "Enter a name of 1–120 bytes without control characters."
	}
	if !codePattern.MatchString(c.ShortCode) {
		e["short_code"] = "Use 2–24 letters, digits, hyphens or underscores, starting with a letter."
	}
	if !utf8.ValidString(c.Notes) || len(c.Notes) > 4096 || strings.IndexFunc(c.Notes, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' }) >= 0 {
		e["notes"] = "Use at most 4096 bytes of plain text."
	}
	if !lifecycle(c.Status) {
		e["status"] = "Choose active or archived."
	}
	if len(e) > 0 {
		return c, e
	}
	return c, nil
}
func ValidateEnvironment(e Environment) (Environment, error) {
	e.Name = strings.TrimSpace(e.Name)
	f := FieldErrors{}
	if !validName(e.Name, 80) {
		f["name"] = "Enter a name of 1–80 bytes without control characters."
	}
	if e.Kind != "lab" && e.Kind != "test" && e.Kind != "production" {
		f["kind"] = "Choose lab, test or production."
	}
	if !lifecycle(e.Status) {
		f["status"] = "Choose active or archived."
	}
	if !ValidID(e.CustomerID) {
		f["customer_id"] = "Choose an existing customer."
	}
	if len(f) > 0 {
		return e, f
	}
	return e, nil
}
