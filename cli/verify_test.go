package cli

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	"github.com/algorandfoundation/falcon-signatures/mnemonic"
)

// TestRunVerify_WithSignatureHex_STDOUT_VALID ensures hex signature verification succeeds.
func TestRunVerify_WithSignatureHex_STDOUT_VALID(t *testing.T) {
	// Deterministic key and signature
	seed := deriveSeed([]byte("unit test seed for verify"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}

	// Write public key only
	dir := t.TempDir()
	pubPath := writeKeypairJSON(t, dir, "pub.json", kp, false)

	msg := "hello verify"
	sig, err := kp.Sign([]byte(msg))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	sigHex := strings.ToLower(hex.EncodeToString(sig))

	var code int
	out := captureStdout(t, func() { code = runVerify([]string{"--key", pubPath, "--msg", msg, "--signature", sigHex}) })
	if strings.TrimSpace(out) != "VALID" {
		t.Fatalf("expected VALID, got %q", strings.TrimSpace(out))
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

// TestRunVerify_InFileAndSigFile_VALID covers file-based inputs verifying correctly.
func TestRunVerify_InFileAndSigFile_VALID(t *testing.T) {
	seed := deriveSeed([]byte("unit test seed for verify files"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	pubPath := writeKeypairJSON(t, dir, "pub.json", kp, false)

	msgBytes := []byte{0x00, 0x01, 0x02, 0x03, 'A', 'B'}
	msgPath := filepath.Join(dir, "msg.bin")
	if err := os.WriteFile(msgPath, msgBytes, 0o644); err != nil {
		t.Fatalf("write msg file: %v", err)
	}

	sig, err := kp.Sign(msgBytes)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	sigPath := filepath.Join(dir, "sig.bin")
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		t.Fatalf("write sig file: %v", err)
	}

	var code int
	out := captureStdout(t, func() { code = runVerify([]string{"--key", pubPath, "--in", msgPath, "--sig", sigPath}) })
	if strings.TrimSpace(out) != "VALID" {
		t.Fatalf("expected VALID, got %q", strings.TrimSpace(out))
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

// TestRunVerify_InvalidSignature_Exits1AndPrintsINVALID checks invalid signatures report properly.
func TestRunVerify_InvalidSignature_Exits1AndPrintsINVALID(t *testing.T) {
	seed := deriveSeed([]byte("unit test seed for verify invalid"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	pubPath := writeKeypairJSON(t, dir, "pub.json", kp, false)

	goodMsg := "hello verify invalid"
	badSig, err := kp.Sign([]byte("different message"))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	badSigHex := hex.EncodeToString(badSig)

	var code int
	out := captureStdout(t, func() { code = runVerify([]string{"--key", pubPath, "--msg", goodMsg, "--signature", badSigHex}) })
	if strings.TrimSpace(out) != "INVALID" {
		t.Fatalf("expected INVALID on stdout, got %q", strings.TrimSpace(out))
	}
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

// TestRunVerify_MissingKey_Returns2 ensures --key is required.
func TestRunVerify_MissingKey_Returns2(t *testing.T) {
	var code int
	errOut := captureStderr(t, func() { code = runVerify([]string{"--msg", "hi", "--signature", "00"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "--key is required") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_BothMsgAndIn_Returns2 enforces message input exclusivity.
func TestRunVerify_BothMsgAndIn_Returns2(t *testing.T) {
	code := 0
	errOut := captureStderr(t, func() {
		code = runVerify([]string{"--key", "dummy", "--msg", "a", "--in", "b", "--signature", "00"})
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "provide exactly one of --in or --msg") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_BothSigFlags_Returns2 enforces signature input exclusivity.
func TestRunVerify_BothSigFlags_Returns2(t *testing.T) {
	code := 0
	errOut := captureStderr(t, func() {
		code = runVerify([]string{"--key", "dummy", "--msg", "a", "--sig", "x", "--signature", "00"})
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "provide exactly one of --sig or --signature") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_InvalidMsgHex_Returns2 validates hex parsing for message input.
func TestRunVerify_InvalidMsgHex_Returns2(t *testing.T) {
	// Provide valid key file so we pass key validation
	seed := deriveSeed([]byte("verify invalid msg hex"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	pubPath := writeKeypairJSON(t, dir, "pub.json", kp, false)

	var code int
	errOut := captureStderr(t, func() { code = runVerify([]string{"--key", pubPath, "--msg", "zz", "--hex", "--signature", "00"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "invalid --msg hex") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_InvalidSignatureHex_Returns2 validates hex parsing for signature input.
func TestRunVerify_InvalidSignatureHex_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("verify invalid sig hex"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	pubPath := writeKeypairJSON(t, dir, "pub.json", kp, false)

	var code int
	errOut := captureStderr(t, func() { code = runVerify([]string{"--key", pubPath, "--msg", "hi", "--signature", "zz"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "invalid --signature hex") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_PublicKeyMissingInFile_Returns2 checks that a public key is required.
func TestRunVerify_PublicKeyMissingInFile_Returns2(t *testing.T) {
	// key file with only private key
	seed := deriveSeed([]byte("verify missing pub"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	// write JSON with only private_key
	obj := keyPairJSON{PrivateKey: strings.ToLower(hex.EncodeToString(kp.PrivateKey[:]))}
	b, _ := json.Marshal(obj)
	keyPath := filepath.Join(dir, "sk.json")
	if err := os.WriteFile(keyPath, b, 0o600); err != nil {
		t.Fatalf("write sk json: %v", err)
	}

	var code int
	errOut := captureStderr(t, func() { code = runVerify([]string{"--key", keyPath, "--msg", "hi", "--signature", "00"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "public key not found") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_FailedSigFileRead_Returns2 surfaces signature file read errors.
func TestRunVerify_FailedSigFileRead_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("verify missing sig file"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	pubPath := writeKeypairJSON(t, dir, "pub.json", kp, false)
	msgPath := filepath.Join(dir, "m.bin")
	if err := os.WriteFile(msgPath, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write msg: %v", err)
	}

	var code int
	errOut := captureStderr(t, func() {
		code = runVerify([]string{"--key", pubPath, "--in", msgPath, "--sig", filepath.Join(dir, "nope.sig")})
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "failed to read --sig") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_InvalidJSONKey_Returns2 reports malformed key JSON.
func TestRunVerify_InvalidJSONKey_Returns2(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write bad json: %v", err)
	}
	var code int
	errOut := captureStderr(t, func() { code = runVerify([]string{"--key", p, "--msg", "hi", "--signature", "00"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "invalid json") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_InvalidPublicHexInKey_Returns2 detects bad public key encoding.
func TestRunVerify_InvalidPublicHexInKey_Returns2(t *testing.T) {
	dir := t.TempDir()
	obj := keyPairJSON{PublicKey: "zz"}
	b, _ := json.Marshal(obj)
	p := filepath.Join(dir, "badpub.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write bad pub: %v", err)
	}
	var code int
	errOut := captureStderr(t, func() { code = runVerify([]string{"--key", p, "--msg", "hi", "--signature", "00"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "invalid public_key hex") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_NoneMsgNorIn_Returns2 ensures a message input is mandatory.
func TestRunVerify_NoneMsgNorIn_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("verify none msg"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	pubPath := writeKeypairJSON(t, dir, "pub.json", kp, false)
	var code int
	errOut := captureStderr(t, func() { code = runVerify([]string{"--key", pubPath, "--signature", "00"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "provide exactly one of --in or --msg") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_InvalidHexInMsgFile_Returns2 validates hex parsing from message files.
func TestRunVerify_InvalidHexInMsgFile_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("verify invalid msg file"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	pubPath := writeKeypairJSON(t, dir, "pub.json", kp, false)
	msgPath := filepath.Join(dir, "m.txt")
	if err := os.WriteFile(msgPath, []byte("zz"), 0o644); err != nil {
		t.Fatalf("write msg: %v", err)
	}
	var code int
	errOut := captureStderr(t, func() { code = runVerify([]string{"--key", pubPath, "--in", msgPath, "--hex", "--signature", "00"}) })
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "invalid hex in --in file") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_FailedInFileRead_Returns2 surfaces message file read errors.
func TestRunVerify_FailedInFileRead_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("verify missing in file"))
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("GenerateFalconKeyPair failed: %v", err)
	}
	dir := t.TempDir()
	pubPath := writeKeypairJSON(t, dir, "pub.json", kp, false)
	var code int
	errOut := captureStderr(t, func() {
		code = runVerify([]string{"--key", pubPath, "--in", filepath.Join(dir, "nope"), "--signature", "00"})
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut), "failed to read --in") {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

// TestRunVerify_FromMnemonicOnly verifies verification when only a mnemonic is supplied.
func TestRunVerify_FromMnemonicOnly(t *testing.T) {
	words := strings.Fields("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title")
	seed, err := mnemonic.SeedFromMnemonic(words, "")
	if err != nil {
		t.Fatalf("SeedFromMnemonic failed: %v", err)
	}
	kp, err := falcongo.GenerateKeyPair(seed[:])
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	dir := t.TempDir()
	keyPath := writeMnemonicJSON(t, dir, "mnemonic.json", words, "")

	msg := "verify mnemonic only"
	sig, err := kp.Sign([]byte(msg))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	sigHex := strings.ToLower(hex.EncodeToString(sig))

	var code int
	out := captureStdout(t, func() {
		code = runVerify([]string{"--key", keyPath, "--msg", msg, "--signature", sigHex, "--mnemonic-passphrase", ""})
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if strings.TrimSpace(out) != "VALID" {
		t.Fatalf("expected VALID, got %q", strings.TrimSpace(out))
	}
}

// TestRunVerify_MnemonicPassphraseRequired enforces providing the mnemonic passphrase.
func TestRunVerify_MnemonicPassphraseRequired(t *testing.T) {
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

	msg := "verify mnemonic passphrase"
	sig, err := kp.Sign([]byte(msg))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	sigHex := strings.ToLower(hex.EncodeToString(sig))

	var code int
	errOut := captureStderr(t, func() { code = runVerify([]string{"--key", keyPath, "--msg", msg, "--signature", sigHex}) })
	if code != 2 {
		t.Fatalf("expected exit 2 when passphrase missing, got %d", code)
	}
	if !strings.Contains(errOut, "file contains mnemonic without passphrase") {
		t.Fatalf("expected mnemonic warning about passphrase, got: %q", errOut)
	}

	var okCode int
	out := captureStdout(t, func() {
		okCode = runVerify([]string{"--key", keyPath, "--msg", msg, "--signature", sigHex, "--mnemonic-passphrase", passphrase})
	})
	if okCode != 0 {
		t.Fatalf("expected exit 0 with passphrase supplied, got %d", okCode)
	}
	if strings.TrimSpace(out) != "VALID" {
		t.Fatalf("expected VALID, got %q", strings.TrimSpace(out))
	}
}
