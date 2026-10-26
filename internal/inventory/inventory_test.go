package inventory

import (
	"strings"
	"testing"
)

func TestCustomerValidation(t *testing.T) {
	c, err := ValidateCustomer(Customer{DisplayName: "  Synthetic Customer  ", ShortCode: " syn_01 ", Status: "active"})
	if err != nil || c.DisplayName != "Synthetic Customer" || c.ShortCode != "SYN_01" {
		t.Fatalf("normalization: %+v %v", c, err)
	}
	for _, c := range []Customer{
		{DisplayName: "", ShortCode: "AA", Status: "active"},
		{DisplayName: "Name\n", ShortCode: "1A", Status: "active"},
		{DisplayName: "bad\x00name", ShortCode: "AA", Status: "active"},
		{DisplayName: strings.Repeat("é", 61), ShortCode: "AA", Status: "active"},
		{DisplayName: "Name", ShortCode: "AA", Status: "deleted"},
		{DisplayName: "Name", ShortCode: "AA", Status: "active", Notes: strings.Repeat("x", 4097)},
		{DisplayName: "Name", ShortCode: "AA", Status: "active", Notes: "bad\x00"},
	} {
		if _, err := ValidateCustomer(c); err == nil {
			t.Fatalf("accepted invalid customer: %+v", c)
		}
	}
}
func TestEnvironmentValidation(t *testing.T) {
	owner := "00000000-0000-4000-8000-000000000001"
	for _, kind := range []string{"lab", "test", "production"} {
		e, err := ValidateEnvironment(Environment{CustomerID: owner, Name: " Test ", Kind: kind, Status: "active"})
		if err != nil || e.Name != "Test" {
			t.Fatal(err)
		}
	}
	for _, e := range []Environment{
		{CustomerID: owner, Name: "", Kind: "lab", Status: "active"},
		{CustomerID: owner, Name: "Test", Kind: "other", Status: "active"},
		{CustomerID: "missing", Name: "Test", Kind: "lab", Status: "active"},
		{CustomerID: owner, Name: "Test", Kind: "lab", Status: "deleted"},
	} {
		if _, err := ValidateEnvironment(e); err == nil {
			t.Fatalf("accepted invalid environment: %+v", e)
		}
	}
	if ValidID("../login") {
		t.Fatal("invalid UUID accepted")
	}
}
