package main

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	const password = "synthetic-test-password"
	var output bytes.Buffer
	if err := hash(strings.NewReader(password+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	result := strings.TrimSpace(output.String())
	if err := bcrypt.CompareHashAndPassword([]byte(result), []byte(password)); err != nil {
		t.Fatal("generated hash does not verify")
	}
	if strings.Contains(result, password) {
		t.Fatal("output exposes password")
	}
}

func TestHashRejectsInvalidLength(t *testing.T) {
	for _, password := range []string{"", "short", strings.Repeat("x", 73), strings.Repeat("x", 1025)} {
		var output bytes.Buffer
		if err := hash(strings.NewReader(password), &output); err == nil || output.Len() > 0 {
			t.Fatal("invalid password accepted")
		}
	}
}
