package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper to write a keypair JSON file for tests
func writeKeypairJSON(t *testing.T, dir string, fname string, kp FalconKeyPair, includePriv bool) string {
	t.Helper()
	obj := keyPairJSON{
		PublicKey:  strings.ToLower(hex.EncodeToString(kp.PublicKey[:])),
		PrivateKey: "",
	}
	if includePriv {
		obj.PrivateKey = strings.ToLower(hex.EncodeToString(kp.PrivateKey[:]))
	}
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal keypair json: %v", err)
	}
	path := filepath.Join(dir, fname)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write keypair json: %v", err)
	}
	return path
}

func TestRunSign_MsgStdout_DeterministicAndVerifiable(t *testing.T) {
	// Deterministic key from seed
	seed := deriveSeed([]byte("unit test seed for sign"))
	kp, err := GenerateFalconKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	keyPath := writeKeypairJSON(t, dir, "keys.json", kp, true)

	msg := "hello world"

	var code1, code2 int
	out1 := captureStdout(t, func() {
		code1 = runSign([]string{"--key", keyPath, "--msg", msg})
	})
	out2 := captureStdout(t, func() {
		code2 = runSign([]string{"--key", keyPath, "--msg", msg})
	})

	hexSig1 := strings.TrimSpace(out1)
	hexSig2 := strings.TrimSpace(out2)
	if hexSig1 == "" {
		t.Fatalf("expected hex signature on stdout")
	}
	if hexSig1 != hexSig2 {
		t.Fatalf("signatures should be deterministic: %q vs %q", hexSig1, hexSig2)
	}

	if code1 != 0 || code2 != 0 {
		t.Fatalf("expected exit code 0, got %d and %d", code1, code2)
	}

	sigBytes, err := hex.DecodeString(hexSig1)
	if err != nil {
		t.Fatalf("stdout not valid hex: %v", err)
	}
	if err := Verify([]byte(msg), sigBytes, kp.PublicKey); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
}

func TestRunSign_InHexToOutFile_Verifiable(t *testing.T) {
	// Deterministic key
	seed := deriveSeed([]byte("unit test seed for sign hex file"))
	kp, err := GenerateFalconKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	keyPath := writeKeypairJSON(t, dir, "keys.json", kp, true)

	// Message provided as hex in a file
	msgHex := "00ffee01deadbeef"
	msgPath := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(msgPath, []byte(msgHex+"\n"), 0o644); err != nil {
		t.Fatalf("write msg file: %v", err)
	}
	outPath := filepath.Join(dir, "sig.bin")

	// Should write raw signature bytes to file
	if code := runSign([]string{"--key", keyPath, "--in", msgPath, "--hex", "--out", outPath}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	sigBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read signature file: %v", err)
	}
	msgBytes, err := parseHex(msgHex)
	if err != nil {
		t.Fatalf("parse message hex: %v", err)
	}
	if err := Verify(msgBytes, sigBytes, kp.PublicKey); err != nil {
		t.Fatalf("signature from file did not verify: %v", err)
	}
}

func TestRunSign_MissingKey_Returns2(t *testing.T) {
	var code int
	errOut := captureStderr(t, func() { code = runSign([]string{"--msg", "hello"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "--key is required") {
		t.Fatalf("expected --key is required error, got: %q", errOut)
	}
}

func TestRunSign_BothMsgAndIn_Returns2(t *testing.T) {
	code := 0
	errOut := captureStderr(t, func() {
		code = runSign([]string{"--key", "dummy", "--msg", "a", "--in", "b"})
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "provide exactly one of --in or --msg") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunSign_NoneMsgNorIn_Returns2(t *testing.T) {
	code := 0
	errOut := captureStderr(t, func() {
		code = runSign([]string{"--key", "dummy"})
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "provide exactly one of --in or --msg") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunSign_RequiresPrivateKey_Returns2(t *testing.T) {
	// Key file with only public key
	seed := deriveSeed([]byte("sign missing sk"))
	kp, err := GenerateFalconKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	keyPath := writeKeypairJSON(t, dir, "pub.json", kp, false)

	var code int
	errOut := captureStderr(t, func() { code = runSign([]string{"--key", keyPath, "--msg", "hello"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "private key not found") {
		t.Fatalf("expected private key not found error, got: %q", errOut)
	}
}

func TestRunSign_InvalidMsgHex_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("sign invalid msg hex"))
	kp, err := GenerateFalconKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	keyPath := writeKeypairJSON(t, dir, "keys.json", kp, true)

	var code int
	errOut := captureStderr(t, func() { code = runSign([]string{"--key", keyPath, "--msg", "zz", "--hex"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "invalid --msg hex") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunSign_FailedInFileRead_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("sign missing file"))
	kp, err := GenerateFalconKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	keyPath := writeKeypairJSON(t, dir, "keys.json", kp, true)

	var code int
	errOut := captureStderr(t, func() { code = runSign([]string{"--key", keyPath, "--in", filepath.Join(dir, "nope.bin")}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "failed to read --in") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunSign_InvalidKeyJSON_Returns2(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(keyPath, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write bad json: %v", err)
	}
	var code int
	errOut := captureStderr(t, func() { code = runSign([]string{"--key", keyPath, "--msg", "hi"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "invalid json") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunSign_InvalidPublicHex_Returns2(t *testing.T) {
	dir := t.TempDir()
	// public invalid hex; private missing
	obj := keyPairJSON{PublicKey: "zz"}
	b, _ := json.Marshal(obj)
	keyPath := filepath.Join(dir, "badpub.json")
	if err := os.WriteFile(keyPath, b, 0o600); err != nil {
		t.Fatalf("write bad pub: %v", err)
	}
	var code int
	errOut := captureStderr(t, func() { code = runSign([]string{"--key", keyPath, "--msg", "hi"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "invalid public_key hex") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunSign_InvalidPrivateHex_Returns2(t *testing.T) {
	dir := t.TempDir()
	obj := keyPairJSON{PrivateKey: "zz"}
	b, _ := json.Marshal(obj)
	keyPath := filepath.Join(dir, "badpriv.json")
	if err := os.WriteFile(keyPath, b, 0o600); err != nil {
		t.Fatalf("write bad priv: %v", err)
	}
	var code int
	errOut := captureStderr(t, func() { code = runSign([]string{"--key", keyPath, "--msg", "hi"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "invalid private_key hex") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunSign_InvalidHexInFile_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("sign invalid file hex"))
	kp, err := GenerateFalconKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	keyPath := writeKeypairJSON(t, dir, "keys.json", kp, true)
	msgPath := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(msgPath, []byte("zz"), 0o644); err != nil {
		t.Fatalf("write msg: %v", err)
	}
	var code int
	errOut := captureStderr(t, func() { code = runSign([]string{"--key", keyPath, "--in", msgPath, "--hex"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "invalid hex in --in file") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestRunSign_OutWriteFails_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("sign out write fails"))
	kp, err := GenerateFalconKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	keyPath := writeKeypairJSON(t, dir, "keys.json", kp, true)
	badOut := filepath.Join(dir, "missing", "sig.bin")

	var code int
	errOut := captureStderr(t, func() { code = runSign([]string{"--key", keyPath, "--msg", "hi", "--out", badOut}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "failed to write signature") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}
