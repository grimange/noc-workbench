package testlab

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIntegrationIdentityRotation(t *testing.T) {
	lab := Start(t)
	old, err := os.ReadFile(filepath.Join(lab.Dir, "host"))
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := os.ReadFile(filepath.Join(lab.Dir, "wrong"))
	if err != nil {
		t.Fatal(err)
	}
	lab.ReplaceHostKey(t, wrong)
	lab.ReplaceHostKey(t, old)
}
