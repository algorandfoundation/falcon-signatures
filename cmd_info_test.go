package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr captures os.Stderr output produced by fn and returns it as a string.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	_ = w.Close()
	b, _ := io.ReadAll(r)
	_ = r.Close()
	return string(b)
}

func TestRunInfo_PrintsBothKeys(t *testing.T) {
	// Deterministic keypair
	seed := deriveSeed([]byte("info both keys seed"))
	kp, err := GenerateFalconKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	keyPath := writeKeypairJSON(t, dir, "keys.json", kp, true)

	var code int
	out := captureStdout(t, func() { code = runInfo([]string{"--key", keyPath}) })
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	if !strings.Contains(out, "public_key:") || !strings.Contains(out, "private_key:") {
		t.Fatalf("expected both keys in output, got: %q", out)
	}
}

func TestRunInfo_PublicOnly(t *testing.T) {
	seed := deriveSeed([]byte("info public only seed"))
	kp, err := GenerateFalconKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	// Write only public key
	dir := t.TempDir()
	obj := keyPairJSON{PublicKey: strings.ToLower(hex.EncodeToString(kp.PublicKey[:]))}
	b, _ := json.Marshal(obj)
	keyPath := filepath.Join(dir, "pub.json")
	if err := os.WriteFile(keyPath, b, 0o600); err != nil {
		t.Fatalf("write pub json: %v", err)
	}

	var code int
	out := captureStdout(t, func() { code = runInfo([]string{"--key", keyPath}) })
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out, "public_key:") {
		t.Fatalf("expected public_key in output")
	}
	if strings.Contains(out, "private_key:") {
		t.Fatalf("did not expect private_key in output")
	}
}

func TestRunInfo_NoKeys_Returns2AndStderr(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(keyPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write empty json: %v", err)
	}

	var code int
	errOut := captureStderr(t, func() { code = runInfo([]string{"--key", keyPath}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "no keys found") {
		t.Fatalf("expected error about no keys found, got: %q", errOut)
	}
}

func TestRunInfo_MissingKeyFlag_Returns2(t *testing.T) {
	var code int
	errOut := captureStderr(t, func() { code = runInfo([]string{}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "--key is required") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunInfo_MissingFile_Returns2(t *testing.T) {
	var code int
	errOut := captureStderr(t, func() { code = runInfo([]string{"--key", "does/not/exist.json"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "failed to read --key") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunInfo_InvalidJSON_Returns2(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write bad json: %v", err)
	}
	var code int
	errOut := captureStderr(t, func() { code = runInfo([]string{"--key", p}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "invalid json") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunInfo_InvalidPublicHex_Returns2(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "badpub.json")
	obj := keyPairJSON{PublicKey: "zz"}
	b, _ := json.Marshal(obj)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write bad pub: %v", err)
	}
	var code int
	errOut := captureStderr(t, func() { code = runInfo([]string{"--key", p}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "invalid public_key hex") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunInfo_InvalidPrivateHex_Returns2(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "badpriv.json")
	obj := keyPairJSON{PrivateKey: "zz"}
	b, _ := json.Marshal(obj)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write bad priv: %v", err)
	}
	var code int
	errOut := captureStderr(t, func() { code = runInfo([]string{"--key", p}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "invalid private_key hex") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}
