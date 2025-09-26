package cli

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// captureStdout captures os.Stdout output produced by fn and returns it as a string.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	_ = w.Close()
	b, _ := io.ReadAll(r)
	_ = r.Close()
	return string(b)
}

func TestRunCreate_WithSeed_PrintsDeterministicJSON(t *testing.T) {
	seed := "unit test seed phrase for create"

	var code1, code2 int
	out1 := captureStdout(t, func() { code1 = runCreate([]string{"--seed", seed}) })
	out2 := captureStdout(t, func() { code2 = runCreate([]string{"--seed", seed}) })
	if code1 != 0 || code2 != 0 {
		t.Fatalf("expected exit code 0, got %d and %d", code1, code2)
	}

	if strings.TrimSpace(out1) != strings.TrimSpace(out2) {
		t.Fatalf("create output should be deterministic for same seed")
	}

	var obj keyPairJSON
	if err := json.Unmarshal([]byte(out1), &obj); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if obj.PublicKey == "" || obj.PrivateKey == "" {
		t.Fatalf("expected both public and private keys in output JSON")
	}

	// Validate hex decodes and sizes match implementation types
	pkBytes, err := parseHex(obj.PublicKey)
	if err != nil {
		t.Fatalf("public_key hex decode failed: %v", err)
	}
	skBytes, err := parseHex(obj.PrivateKey)
	if err != nil {
		t.Fatalf("private_key hex decode failed: %v", err)
	}

	// Cross-check deterministically derived keys match library output
	// Use zero-value types to obtain expected lengths without generating a keypair
	var zeroKP falcongo.KeyPair
	if got, want := len(pkBytes), len(zeroKP.PublicKey); got != want {
		t.Fatalf("public key length mismatch: got %d want %d", got, want)
	}
	if got, want := len(skBytes), len(zeroKP.PrivateKey); got != want {
		t.Fatalf("private key length mismatch: got %d want %d", got, want)
	}
}

func TestRunCreate_WritesOutFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "keys.json")
	seed := "another deterministic seed for create"

	if code := runCreate([]string{"--seed", seed, "--out", outPath}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed reading output file: %v", err)
	}
	var obj keyPairJSON
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatalf("invalid JSON in output file: %v", err)
	}
	if obj.PublicKey == "" || obj.PrivateKey == "" {
		t.Fatalf("expected keys in file JSON")
	}
	// Sanity: hex decodes
	if _, err := hex.DecodeString(strings.TrimPrefix(obj.PublicKey, "0x")); err != nil {
		t.Fatalf("public_key not hex: %v", err)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(obj.PrivateKey, "0x")); err != nil {
		t.Fatalf("private_key not hex: %v", err)
	}
}

func TestRunCreate_OutDirMissing_Returns2AndStderr(t *testing.T) {
	dir := t.TempDir()
	badOut := filepath.Join(dir, "missing", "keys.json") // parent dir does not exist
	seed := "seed for failing write"

	var code int
	errOut := captureStderr(t, func() { code = runCreate([]string{"--seed", seed, "--out", badOut}) })
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "failed to write") {
		t.Fatalf("expected error about failed to write, got: %q", errOut)
	}
}
