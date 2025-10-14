package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// Test that setting --algod-token without --algod-url results in an error.
func TestRunAlgorandSend_AlgodTokenRequiresURL(t *testing.T) {
	t.Setenv("ALGOD_URL", "")
	t.Setenv("ALGOD_TOKEN", "")

	var code int
	_, stderr := captureStdoutStderr(t, func() {
		code = runAlgorandSend([]string{
			"--key", "dummy.json",
			"--to", "ALGOADDRESS",
			"--amount", "1",
			"--algod-token", "token",
		})
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr, "--algod-token requires --algod-url") {
		t.Fatalf("expected error about --algod-token requiring --algod-url, got %q", stderr)
	}
}

// Test that setting --algod-url to empty and --algod-token to non-empty results
// in an error.
func TestRunAlgorandSend_TokenWithClearedURLRejected(t *testing.T) {
	t.Setenv("ALGOD_URL", "https://example")
	t.Setenv("ALGOD_TOKEN", "example-token")

	var code int
	_, stderr := captureStdoutStderr(t, func() {
		code = runAlgorandSend([]string{
			"--key", "dummy.json",
			"--to", "ALGOADDRESS",
			"--amount", "1",
			"--algod-url", "",
			"--algod-token", "still-set",
		})
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr, "--algod-token requires a non-empty --algod-url") {
		t.Fatalf("expected error about --algod-token with empty url, got %q", stderr)
	}
}

// Test that setting --algod-url to whitespace is treated as empty and results in an
// error when using devnet.
func TestRunAlgorandSend_AlgodURLWhitespaceTreatedAsEmpty(t *testing.T) {
	t.Setenv("ALGOD_URL", "https://custom")
	t.Setenv("ALGOD_TOKEN", "custom-token")

	seed := deriveSeed([]byte("whitespace url test seed"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	keyPath := writeKeypairJSON(t, dir, "keys.json", kp, true)

	var addr types.Address
	var code int
	_, stderr := captureStdoutStderr(t, func() {
		code = runAlgorandSend([]string{
			"--key", keyPath,
			"--to", addr.String(),
			"--amount", "1",
			"--network", "devnet",
			"--algod-url", "   ",
		})
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr, "send failed: ALGOD_URL not set for DevNet") {
		t.Fatalf("expected devnet ALGOD_URL error, got %q", stderr)
	}
	if got := os.Getenv("ALGOD_URL"); got != "" {
		t.Fatalf("expected ALGOD_URL to be empty string, got %q", got)
	}
}

// Test that setting --algod-url and --algod-token to empty clears the environment
func TestRunAlgorandSend_ClearAlgodURLResetsEnv(t *testing.T) {
	t.Setenv("ALGOD_URL", "https://custom-endpoint")
	t.Setenv("ALGOD_TOKEN", "custom-token")

	seed := deriveSeed([]byte("clear algod url test seed"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	keyPath := writeKeypairJSON(t, dir, "keys.json", kp, true)

	var addr types.Address
	var code int
	_, stderr := captureStdoutStderr(t, func() {
		code = runAlgorandSend([]string{
			"--key", keyPath,
			"--to", addr.String(),
			"--amount", "1",
			"--network", "devnet",
			"--algod-url", "",
			"--algod-token", "",
		})
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr, "send failed: ALGOD_URL not set for DevNet") {
		t.Fatalf("expected devnet ALGOD_URL error, got %q", stderr)
	}
	if got := os.Getenv("ALGOD_URL"); got != "" {
		t.Fatalf("expected ALGOD_URL to be cleared, got %q", got)
	}
	if got := os.Getenv("ALGOD_TOKEN"); got != "" {
		t.Fatalf("expected ALGOD_TOKEN to be cleared, got %q", got)
	}
}
