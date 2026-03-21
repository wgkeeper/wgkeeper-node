package version

import (
	"testing"
)

func TestName(t *testing.T) {
	if Name != "wgkeeper-node" {
		t.Errorf("Name = %q, want wgkeeper-node", Name)
	}
}

func TestVersionNonEmpty(t *testing.T) {
	if Version == "" {
		t.Error("Version must not be empty")
	}
}
