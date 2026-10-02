package version

import (
	"strings"
	"testing"
)

func TestVersionGet(t *testing.T) {
	info := Get()
	if info.Version == "" {
		t.Fatal("expected non-empty version")
	}
	if info.GoVersion == "" {
		t.Fatal("expected non-empty go_version")
	}
	full := Full()
	if !strings.Contains(full, "OneAuth") {
		t.Fatalf("expected 'OneAuth' in Full(), got: %s", full)
	}
}
