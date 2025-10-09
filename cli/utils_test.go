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

// legacyKeyJSON returns a minimal JSON payload mimicking the original format.
func legacyKeyJSON(pub, priv string) []byte {
	obj := keyPairJSON{PublicKey: pub, PrivateKey: priv}
	b, _ := json.Marshal(obj)
	return b
}

func writeTempFile(t *testing.T, dir, name string, data []byte) string {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

// TestLoadKeypairFile_LegacyJSON ensures legacy key files without mnemonic fields still load.
func TestLoadKeypairFile_LegacyJSON(t *testing.T) {
	dir := t.TempDir()
	pub := "aa"
	priv := "bb"
	path := writeTempFile(t, dir, "legacy.json", legacyKeyJSON(pub, priv))

	loadedPub, loadedPriv, meta, err := loadKeypairFile(path, nil)
	if err != nil {
		t.Fatalf("loadKeypairFile returned error: %v", err)
	}
	if meta.Mnemonic != "" {
		t.Fatalf("expected no mnemonic in meta, got %q", meta.Mnemonic)
	}
	if !strings.EqualFold(hex.EncodeToString(loadedPub), pub) {
		t.Fatalf("expected pub %q, got %x", pub, loadedPub)
	}
	if !strings.EqualFold(hex.EncodeToString(loadedPriv), priv) {
		t.Fatalf("expected priv %q, got %x", priv, loadedPriv)
	}
}

// TestLoadKeypairFile_PassphraseMismatch ensures overriding with a different passphrase errors.
func TestLoadKeypairFile_PassphraseMismatch(t *testing.T) {
	dir := t.TempDir()
	words := strings.Fields("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title")
	obj := keyPairJSON{Mnemonic: strings.Join(words, " "), MnemonicPassphrase: "alpha"}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal mnemonic json: %v", err)
	}
	path := writeTempFile(t, dir, "mnemonic.json", b)

	override := "beta"
	if _, _, _, err := loadKeypairFile(path, &override); err == nil {
		t.Fatalf("expected passphrase mismatch error")
	}

	match := obj.MnemonicPassphrase
	pub, priv, _, err := loadKeypairFile(path, &match)
	if err != nil {
		t.Fatalf("expected success when passphrase matches, got: %v", err)
	}
	expected := deriveKeyPair(t, words, match)
	if hex.EncodeToString(pub) != hex.EncodeToString(expected.PublicKey[:]) {
		t.Fatalf("public key mismatch when passphrase matches")
	}
	if hex.EncodeToString(priv) != hex.EncodeToString(expected.PrivateKey[:]) {
		t.Fatalf("private key mismatch when passphrase matches")
	}
}

// TestLoadKeypairFile_MnemonicWithoutPassphrase validates behavior when only mnemonic is present.
func TestLoadKeypairFile_MnemonicWithoutPassphrase(t *testing.T) {
	dir := t.TempDir()
	words := strings.Fields("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
	obj := keyPairJSON{Mnemonic: strings.Join(words, " ")}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal mnemonic json: %v", err)
	}
	path := writeTempFile(t, dir, "mnemonic-only.json", b)

	if _, _, _, err := loadKeypairFile(path, nil); err == nil || !strings.Contains(err.Error(), "file contains mnemonic without passphrase") {
		t.Fatalf("expected error about missing passphrase, got %v", err)
	}

	empty := ""
	pub, priv, _, err := loadKeypairFile(path, &empty)
	if err != nil {
		t.Fatalf("expected success with explicit empty passphrase, got: %v", err)
	}

	expected := deriveKeyPair(t, words, empty)
	if hex.EncodeToString(pub) != hex.EncodeToString(expected.PublicKey[:]) {
		t.Fatalf("public key mismatch for empty-passphrase recovery")
	}
	if hex.EncodeToString(priv) != hex.EncodeToString(expected.PrivateKey[:]) {
		t.Fatalf("private key mismatch for empty-passphrase recovery")
	}
}

func deriveKeyPair(t *testing.T, words []string, pass string) falcongo.KeyPair {
	t.Helper()
	seed, err := mnemonic.SeedFromMnemonic(words, pass)
	if err != nil {
		t.Fatalf("SeedFromMnemonic failed: %v", err)
	}
	kp, err := falcongo.GenerateKeyPair(seed[:])
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	return kp
}
