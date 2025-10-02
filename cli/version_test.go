package cli

import (
	"strings"
	"testing"
)

func TestRunVersion_PrintsInjectedVersion(t *testing.T) {
	old := version
	version = "test-build"
	defer func() { version = old }()

	var code int
	out := captureStdout(t, func() { code = runVersion(nil) })
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if strings.TrimSpace(out) != "test-build" {
		t.Fatalf("unexpected version output: %q", out)
	}
}

func TestRunVersion_WithArguments_Returns2(t *testing.T) {
	var code int
	errOut := captureStderr(t, func() { code = runVersion([]string{"extra"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "does not accept arguments") {
		t.Fatalf("unexpected stderr: %q", errOut)
	}
}
