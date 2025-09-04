package cli

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVerify_WithSignatureHex_STDOUT_VALID(t *testing.T) {
	// Deterministic key and signature
	seed := deriveSeed([]byte("unit test seed for verify"))
	kp, err := GenerateFalconKeyPair(seed)
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

func TestRunVerify_InFileAndSigFile_VALID(t *testing.T) {
	seed := deriveSeed([]byte("unit test seed for verify files"))
	kp, err := GenerateFalconKeyPair(seed)
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

func TestRunVerify_InvalidSignature_Exits1AndPrintsINVALID(t *testing.T) {
	seed := deriveSeed([]byte("unit test seed for verify invalid"))
	kp, err := GenerateFalconKeyPair(seed)
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

func TestRunVerify_InvalidMsgHex_Returns2(t *testing.T) {
	// Provide valid key file so we pass key validation
	seed := deriveSeed([]byte("verify invalid msg hex"))
	kp, err := GenerateFalconKeyPair(seed)
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

func TestRunVerify_InvalidSignatureHex_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("verify invalid sig hex"))
	kp, err := GenerateFalconKeyPair(seed)
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

func TestRunVerify_PublicKeyMissingInFile_Returns2(t *testing.T) {
	// key file with only private key
	seed := deriveSeed([]byte("verify missing pub"))
	kp, err := GenerateFalconKeyPair(seed)
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

func TestRunVerify_FailedSigFileRead_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("verify missing sig file"))
	kp, err := GenerateFalconKeyPair(seed)
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

func TestRunVerify_NoneMsgNorIn_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("verify none msg"))
	kp, err := GenerateFalconKeyPair(seed)
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

func TestRunVerify_InvalidHexInMsgFile_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("verify invalid msg file"))
	kp, err := GenerateFalconKeyPair(seed)
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

func TestRunVerify_FailedInFileRead_Returns2(t *testing.T) {
	seed := deriveSeed([]byte("verify missing in file"))
	kp, err := GenerateFalconKeyPair(seed)
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
