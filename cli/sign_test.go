package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	falconlib "github.com/algorand/falcon"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
	"github.com/algorandfoundation/falcon-signatures/mnemonic"
)

// helper to write a keypair JSON file for tests
func writeKeypairJSON(t *testing.T, dir string, fname string, kp falcongo.KeyPair, includePriv bool) string {
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

// writeMnemonicJSON writes a mnemonic JSON file for tests and returns the path.
func writeMnemonicJSON(t *testing.T, dir, fname string, words []string, passphrase string) string {
	obj := keyPairJSON{Mnemonic: strings.Join(words, " ")}
	if passphrase != "" {
		obj.MnemonicPassphrase = passphrase
	}
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal mnemonic json: %v", err)
	}
	path := filepath.Join(dir, fname)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write mnemonic json: %v", err)
	}
	return path
}

// TestRunSign_MsgStdout_DeterministicAndVerifiable ensures stdout signatures are deterministic and valid.
func TestRunSign_MsgStdout_DeterministicAndVerifiable(t *testing.T) {
	// Deterministic key from seed
	seed := deriveSeed([]byte("unit test seed for sign"))
	kp, err := falcongo.GenerateKeyPair(seed)
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
	if err := falcongo.Verify([]byte(msg), falconlib.CompressedSignature(sigBytes), kp.PublicKey); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
}

// TestRunSign_InHexToOutFile_Verifiable confirms hex input to file output remains verifiable.
func TestRunSign_InHexToOutFile_Verifiable(t *testing.T) {
	// Deterministic key
	seed := deriveSeed([]byte("unit test seed for sign hex file"))
	kp, err := falcongo.GenerateKeyPair(seed)
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
	if err := falcongo.Verify(msgBytes, falconlib.CompressedSignature(sigBytes), kp.PublicKey); err != nil {
		t.Fatalf("signature from file did not verify: %v", err)
	}
}

// TestRunSign_MissingKey_Returns2 checks that --key is required.
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

// TestRunSign_BothMsgAndIn_Returns2 ensures mutually exclusive input flags are enforced.
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

// TestRunSign_NoneMsgNorIn_Returns2 verifies an input is mandatory.
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

// TestRunSign_RequiresPrivateKey_Returns2 confirms a private key is needed for signing.
func TestRunSign_RequiresPrivateKey_Returns2(t *testing.T) {
	// Key file with only public key
	seed := deriveSeed([]byte("sign missing sk"))
	kp, err := falcongo.GenerateKeyPair(seed)
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

// TestRunSign_InvalidMsgHex_Returns2 validates hex parsing for --msg.
func TestRunSign_InvalidMsgHex_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("sign invalid msg hex"))
	kp, err := falcongo.GenerateKeyPair(seed)
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

// TestRunSign_FailedInFileRead_Returns2 surfaces file read errors.
func TestRunSign_FailedInFileRead_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("sign missing file"))
	kp, err := falcongo.GenerateKeyPair(seed)
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

// TestRunSign_InvalidKeyJSON_Returns2 detects malformed key JSON.
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

// TestRunSign_InvalidPublicHex_Returns2 reports bad public key encoding.
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

// TestRunSign_InvalidPrivateHex_Returns2 reports bad private key encoding.
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

// TestRunSign_InvalidHexInFile_Returns2 ensures hex parsing from file fails gracefully.
func TestRunSign_InvalidHexInFile_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("sign invalid file hex"))
	kp, err := falcongo.GenerateKeyPair(seed)
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

// TestRunSign_OutWriteFails_Returns2 checks write errors bubble up.
func TestRunSign_OutWriteFails_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("sign out write fails"))
	kp, err := falcongo.GenerateKeyPair(seed)
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

// TestRunSign_FromMnemonicOnly verifies signing when only a mnemonic is provided.
func TestRunSign_FromMnemonicOnly(t *testing.T) {
	words := strings.Fields("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title")
	seed, err := mnemonic.SeedFromMnemonic(words, "")
	if err != nil {
		t.Fatalf("SeedFromMnemonic failed: %v", err)
	}
	kp, err := falcongo.GenerateKeyPair(seed[:])
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if _, err := kp.Sign([]byte("self-test")); err != nil {
		t.Fatalf("pre-check sign failed: %v", err)
	}

	dir := t.TempDir()
	keyPath := writeMnemonicJSON(t, dir, "mnemonic.json", words, "")
	empty := ""
	pubDerived, privDerived, _, err := loadKeypairFile(keyPath, &empty)
	if err != nil {
		t.Fatalf("loadKeypairFile failed: %v", err)
	}
	if len(privDerived) != len(kp.PrivateKey) {
		t.Fatalf("expected derived private key length %d, got %d", len(kp.PrivateKey), len(privDerived))
	}
	if len(pubDerived) != len(kp.PublicKey) {
		t.Fatalf("expected derived public key length %d, got %d", len(kp.PublicKey), len(pubDerived))
	}
	if !bytes.Equal(privDerived, kp.PrivateKey[:]) {
		t.Fatalf("derived private key mismatch")
	}
	if !bytes.Equal(pubDerived, kp.PublicKey[:]) {
		t.Fatalf("derived public key mismatch")
	}

	msg := "signing with mnemonic only"
	var code int
	out := captureStdout(t, func() {
		code = runSign([]string{"--key", keyPath, "--msg", msg, "--mnemonic-passphrase", ""})
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	sigHex := strings.TrimSpace(out)
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("stdout not valid hex: %v", err)
	}
	if err := falcongo.Verify([]byte(msg), falconlib.CompressedSignature(sigBytes), kp.PublicKey); err != nil {
		t.Fatalf("signature did not verify with mnemonic-derived key: %v", err)
	}
}

// TestRunSign_MnemonicPassphraseRequired enforces supplying the mnemonic passphrase.
func TestRunSign_MnemonicPassphraseRequired(t *testing.T) {
	words := strings.Fields("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title")
	passphrase := "TREZOR"
	seed, err := mnemonic.SeedFromMnemonic(words, passphrase)
	if err != nil {
		t.Fatalf("SeedFromMnemonic failed: %v", err)
	}
	kp, err := falcongo.GenerateKeyPair(seed[:])
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	dir := t.TempDir()
	keyPath := writeMnemonicJSON(t, dir, "mnemonic-pass.json", words, "")

	msg := "mnemonic passphrase test"
	var code int
	errOut := captureStderr(t, func() { code = runSign([]string{"--key", keyPath, "--msg", msg}) })
	if code != 2 {
		t.Fatalf("expected exit 2 when passphrase missing, got %d", code)
	}
	if !strings.Contains(errOut, "file contains mnemonic without passphrase") {
		t.Fatalf("expected mnemonic warning about passphrase, got: %q", errOut)
	}

	var okCode int
	out := captureStdout(t, func() {
		okCode = runSign([]string{"--key", keyPath, "--msg", msg, "--mnemonic-passphrase", passphrase})
	})
	if okCode != 0 {
		t.Fatalf("expected exit 0 with passphrase supplied, got %d", okCode)
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("stdout not valid hex: %v", err)
	}
	if err := falcongo.Verify([]byte(msg), falconlib.CompressedSignature(sigBytes), kp.PublicKey); err != nil {
		t.Fatalf("signature did not verify with passphrase: %v", err)
	}
}
