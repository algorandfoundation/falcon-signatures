package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	"github.com/algorandfoundation/falcon-signatures/mnemonic"
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

// captureStderr captures os.Stderr output produced by fn and returns it as a string.
func captureStdoutStderr(t *testing.T, fn func()) (string, string) {
	t.Helper()
	oldOut := os.Stdout
	oldErr := os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stdout = wOut
	os.Stderr = wErr
	defer func() {
		os.Stdout = oldOut
		os.Stderr = oldErr
	}()

	fn()

	_ = wOut.Close()
	_ = wErr.Close()
	stdoutBytes, _ := io.ReadAll(rOut)
	stderrBytes, _ := io.ReadAll(rErr)
	_ = rOut.Close()
	_ = rErr.Close()
	return string(stdoutBytes), string(stderrBytes)
}

// decodeKeyJSON unmarshals stdout JSON into a keyPairJSON helper.
func decodeKeyJSON(t *testing.T, out string) keyPairJSON {
	t.Helper()
	var obj keyPairJSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &obj); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	return obj
}

// TestRunCreate_WithSeed_PrintsDeterministicJSON verifies that using the same seed
// produces the same key pair output.
func TestRunCreate_WithSeed_PrintsDeterministicJSON(t *testing.T) {
	seed := "unit test seed phrase for create"

	var code1, code2 int
	out1 := captureStdout(t, func() { code1 = runCreate([]string{"--seed", seed}) })
	out2 := captureStdout(t, func() { code2 = runCreate([]string{"--seed", seed}) })
	if code1 != 0 || code2 != 0 {
		t.Fatalf("expected exit code 0, got %d and %d", code1, code2)
	}

	obj1 := decodeKeyJSON(t, out1)
	obj2 := decodeKeyJSON(t, out2)
	if obj1.PublicKey != obj2.PublicKey || obj1.PrivateKey != obj2.PrivateKey {
		t.Fatalf("create output should be deterministic for same seed")
	}

	var zeroKP falcongo.KeyPair
	pkBytes, err := parseHex(obj1.PublicKey)
	if err != nil {
		t.Fatalf("public_key hex decode failed: %v", err)
	}
	skBytes, err := parseHex(obj1.PrivateKey)
	if err != nil {
		t.Fatalf("private_key hex decode failed: %v", err)
	}
	if got, want := len(pkBytes), len(zeroKP.PublicKey); got != want {
		t.Fatalf("public key length mismatch: got %d want %d", got, want)
	}
	if got, want := len(skBytes), len(zeroKP.PrivateKey); got != want {
		t.Fatalf("private key length mismatch: got %d want %d", got, want)
	}
}

// TestRunCreate_DefaultIncludesMnemonic ensures stdout JSON includes the generated mnemonic.
func TestRunCreate_DefaultIncludesMnemonic(t *testing.T) {
	var code int
	stdout, stderr := captureStdoutStderr(t, func() { code = runCreate(nil) })
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	obj := decodeKeyJSON(t, stdout)
	if _, err := parseHex(obj.PublicKey); err != nil {
		t.Fatalf("public_key hex decode failed: %v", err)
	}
	if _, err := parseHex(obj.PrivateKey); err != nil {
		t.Fatalf("private_key hex decode failed: %v", err)
	}
	if obj.Mnemonic == "" {
		t.Fatalf("expected mnemonic in output JSON")
	}
	if words := strings.Fields(obj.Mnemonic); len(words) != 24 {
		t.Fatalf("expected 24 mnemonic words, got %d", len(words))
	}
	if stderr != "" {
		t.Fatalf("expected no stderr output, got: %q", stderr)
	}
}

// TestRunCreate_NoMnemonicFlagOmitsMnemonic ensures opting out omits the mnemonic field.
func TestRunCreate_NoMnemonicFlagOmitsMnemonic(t *testing.T) {
	var code int
	stdout, stderr := captureStdoutStderr(t, func() { code = runCreate([]string{"--no-mnemonic"}) })
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	obj := decodeKeyJSON(t, stdout)
	if obj.Mnemonic != "" {
		t.Fatalf("expected mnemonic to be omitted when --no-mnemonic is set")
	}
	if stderr != "" {
		t.Fatalf("did not expect stderr output, got %q", stderr)
	}
}

// TestRunCreate_FromMnemonic validates recovering a keypair from a mnemonic plus passphrase.
func TestRunCreate_FromMnemonic(t *testing.T) {
	wordStr := "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
	words := strings.Fields(wordStr)
	passphrase := "TREZOR"

	seed, err := mnemonic.SeedFromMnemonic(words, passphrase)
	if err != nil {
		t.Fatalf("SeedFromMnemonic failed: %v", err)
	}
	expectedKP, err := falcongo.GenerateKeyPair(seed[:])
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	var code int
	stdout, stderr := captureStdoutStderr(t, func() {
		code = runCreate([]string{"--from-mnemonic", wordStr, "--mnemonic-passphrase", passphrase})
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if stderr != "" {
		t.Fatalf("expected no stderr output, got %q", stderr)
	}

	obj := decodeKeyJSON(t, stdout)
	if obj.Mnemonic != wordStr {
		t.Fatalf("expected mnemonic to be preserved in JSON")
	}
	if obj.MnemonicPassphrase != passphrase {
		t.Fatalf("expected mnemonic passphrase to match in JSON")
	}

	pubBytes, err := parseHex(obj.PublicKey)
	if err != nil {
		t.Fatalf("public_key hex decode failed: %v", err)
	}
	privBytes, err := parseHex(obj.PrivateKey)
	if err != nil {
		t.Fatalf("private_key hex decode failed: %v", err)
	}
	if !bytes.Equal(pubBytes, expectedKP.PublicKey[:]) {
		t.Fatalf("public key mismatch when recovering from mnemonic")
	}
	if !bytes.Equal(privBytes, expectedKP.PrivateKey[:]) {
		t.Fatalf("private key mismatch when recovering from mnemonic")
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "recovered.json")
	if exit := runCreate([]string{"--from-mnemonic", wordStr, "--mnemonic-passphrase", passphrase, "--out", outPath}); exit != 0 {
		t.Fatalf("expected exit 0 when writing recovered key, got %d", exit)
	}
	fileBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read recovered file: %v", err)
	}
	var fileObj keyPairJSON
	if err := json.Unmarshal(fileBytes, &fileObj); err != nil {
		t.Fatalf("invalid JSON in recovered file: %v", err)
	}
	if fileObj.Mnemonic != wordStr {
		t.Fatalf("expected mnemonic to be stored in recovered JSON")
	}
	if fileObj.MnemonicPassphrase != passphrase {
		t.Fatalf("expected mnemonic passphrase to match in JSON")
	}
}

// TestRunCreate_FromMnemonicWithoutOutput checks flag validation and recovery without passphrase.
func TestRunCreate_FromMnemonicWithoutOutput(t *testing.T) {
	wordStr := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	words := strings.Fields(wordStr)

	seed, err := mnemonic.SeedFromMnemonic(words, "")
	if err != nil {
		t.Fatalf("SeedFromMnemonic failed: %v", err)
	}
	expectedKP, err := falcongo.GenerateKeyPair(seed[:])
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	var code int
	errOut := captureStderr(t, func() {
		code = runCreate([]string{"--from-mnemonic", wordStr, "--no-mnemonic"})
	})
	if code != 2 {
		t.Fatalf("expected exit 2 due to incompatible flags, got %d", code)
	}
	if !strings.Contains(errOut, "cannot combine --from-mnemonic with --no-mnemonic") {
		t.Fatalf("unexpected error message: %q", errOut)
	}

	// Recovery without --no-mnemonic should continue to succeed.
	var okCode int
	stdout, stderr := captureStdoutStderr(t, func() {
		okCode = runCreate([]string{"--from-mnemonic", wordStr})
	})
	if okCode != 0 {
		t.Fatalf("expected exit 0 without --no-mnemonic, got %d", okCode)
	}
	if stderr != "" {
		t.Fatalf("expected no stderr output, got: %q", stderr)
	}
	obj := decodeKeyJSON(t, stdout)
	if obj.Mnemonic != wordStr {
		t.Fatalf("expected mnemonic to round-trip in JSON")
	}
	pubBytes, err := parseHex(obj.PublicKey)
	if err != nil {
		t.Fatalf("public_key hex decode failed: %v", err)
	}
	privBytes, err := parseHex(obj.PrivateKey)
	if err != nil {
		t.Fatalf("private_key hex decode failed: %v", err)
	}
	if !bytes.Equal(pubBytes, expectedKP.PublicKey[:]) {
		t.Fatalf("public key mismatch when recovering mnemonic")
	}
	if !bytes.Equal(privBytes, expectedKP.PrivateKey[:]) {
		t.Fatalf("private key mismatch when recovering mnemonic")
	}
}

// TestRunCreate_FromMnemonicWrongWordCount ensures --from-mnemonic enforces 24 words.
func TestRunCreate_FromMnemonicWrongWordCount(t *testing.T) {
	words := strings.Fields("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title extra")
	joined := strings.Join(words, " ")

	var code int
	errOut := captureStderr(t, func() {
		code = runCreate([]string{"--from-mnemonic", joined})
	})
	if code != 2 {
		t.Fatalf("expected exit 2 for wrong word count, got %d", code)
	}
	if !strings.Contains(errOut, "requires exactly 24 words") {
		t.Fatalf("unexpected error message: %q", errOut)
	}

	// Too few words should also be rejected.
	shortWords := strings.Fields("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage")
	shortJoined := strings.Join(shortWords, " ")

	errOut = captureStderr(t, func() {
		code = runCreate([]string{"--from-mnemonic", shortJoined})
	})
	if code != 2 {
		t.Fatalf("expected exit 2 for short word count, got %d", code)
	}
	if !strings.Contains(errOut, "requires exactly 24 words") {
		t.Fatalf("unexpected error message for short mnemonic: %q", errOut)
	}
}

// TestRunCreate_WritesOutFile confirms JSON is written when --out is used.
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

// TestRunCreate_OutDirMissing_Returns2AndStderr ensures write failures bubble an error.
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
