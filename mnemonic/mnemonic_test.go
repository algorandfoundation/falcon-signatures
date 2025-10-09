package mnemonic

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// TestEntropyToMnemonicZeroVector checks converting zero entropy yields known words.
func TestEntropyToMnemonicZeroVector(t *testing.T) {
	entropy := make([]byte, 32)
	got, err := EntropyToMnemonic(entropy)
	if err != nil {
		t.Fatalf("EntropyToMnemonic returned error: %v", err)
	}

	expected := strings.Fields("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")

	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("EntropyToMnemonic mismatch\nexpected: %v\n     got: %v", expected, got)
	}
}

// TestMnemonicToEntropyZeroVector verifies the zero-word list round trips to zero entropy.
func TestMnemonicToEntropyZeroVector(t *testing.T) {
	phrase := strings.Fields("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
	got, err := MnemonicToEntropy(phrase)
	if err != nil {
		t.Fatalf("MnemonicToEntropy returned error: %v", err)
	}

	expected := make([]byte, 32)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("MnemonicToEntropy mismatch\nexpected: %x\n     got: %x", expected, got)
	}
}

// TestRoundTripKnownVector ensures known vectors convert both ways exactly.
func TestRoundTripKnownVector(t *testing.T) {
	const entropyHex = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
	entropy, err := hex.DecodeString(entropyHex)
	if err != nil {
		t.Fatalf("invalid test data: %v", err)
	}

	expectedWords := strings.Fields("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title")

	words, err := EntropyToMnemonic(entropy)
	if err != nil {
		t.Fatalf("EntropyToMnemonic returned error: %v", err)
	}

	if !reflect.DeepEqual(words, expectedWords) {
		t.Fatalf("EntropyToMnemonic mismatch\nexpected: %v\n     got: %v", expectedWords, words)
	}

	recovered, err := MnemonicToEntropy(words)
	if err != nil {
		t.Fatalf("MnemonicToEntropy returned error: %v", err)
	}

	if !reflect.DeepEqual(recovered, entropy) {
		t.Fatalf("round trip mismatch\nexpected: %x\n     got: %x", entropy, recovered)
	}
}

// TestRoundTripAdditionalVectors covers extra BIP-39 official test vectors.
func TestRoundTripAdditionalVectors(t *testing.T) {
	testCases := []struct {
		entropyHex string
		mnemonic   string
	}{
		{
			entropyHex: "8080808080808080808080808080808080808080808080808080808080808080",
			mnemonic:   "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		},
		{
			entropyHex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			mnemonic:   "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		},
	}

	for _, tc := range testCases {
		entropy, err := hex.DecodeString(tc.entropyHex)
		if err != nil {
			t.Fatalf("invalid test entropy: %v", err)
		}
		expectedWords := strings.Fields(tc.mnemonic)

		words, err := EntropyToMnemonic(entropy)
		if err != nil {
			t.Fatalf("EntropyToMnemonic returned error: %v", err)
		}
		if !reflect.DeepEqual(words, expectedWords) {
			t.Fatalf("EntropyToMnemonic mismatch\nexpected: %v\n     got: %v", expectedWords, words)
		}

		recovered, err := MnemonicToEntropy(words)
		if err != nil {
			t.Fatalf("MnemonicToEntropy returned error: %v", err)
		}
		if !reflect.DeepEqual(recovered, entropy) {
			t.Fatalf("round trip mismatch\nexpected: %x\n     got: %x", entropy, recovered)
		}
	}
}

// TestMnemonicErrors covers common malformed input scenarios.
func TestMnemonicErrors(t *testing.T) {
	if _, err := EntropyToMnemonic([]byte{0x00}); err == nil {
		t.Fatalf("expected error for short entropy")
	}

	if _, err := MnemonicToEntropy([]string{"abandon"}); err == nil {
		t.Fatalf("expected error for short phrase")
	}

	valid := strings.Fields("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")

	invalidWord := append([]string{}, valid...)
	invalidWord[0] = "invalid"
	if _, err := MnemonicToEntropy(invalidWord); err == nil {
		t.Fatalf("expected error for word outside BIP-39 list")
	}

	badChecksum := append([]string{}, valid...)
	badChecksum[len(badChecksum)-1] = "zoo"
	if _, err := MnemonicToEntropy(badChecksum); err == nil {
		t.Fatalf("expected checksum error")
	}
}

// TestSeedFromMnemonic validates HKDF derivation from mnemonic plus passphrase.
func TestSeedFromMnemonic(t *testing.T) {
	words := strings.Fields("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title")
	passphrase := "TREZOR"

	seed, err := SeedFromMnemonic(words, passphrase)
	if err != nil {
		t.Fatalf("SeedFromMnemonic returned error: %v", err)
	}

	if len(seed) != falconSeedSize {
		t.Fatalf("expected %d-byte seed, got %d", falconSeedSize, len(seed))
	}

	sentence := normalizeNFKD(strings.Join(words, " "))
	pass := normalizeNFKD(passphrase)
	salt := "mnemonic" + pass

	bip39Seed := pbkdf2.Key([]byte(sentence), []byte(salt), pbkdf2Iterations, bip39SeedSize, sha512.New)
	reader := hkdf.New(sha512.New, bip39Seed, []byte(hkdfSalt), []byte(hkdfInfoString))

	expected := make([]byte, falconSeedSize)
	if _, err := io.ReadFull(reader, expected); err != nil {
		t.Fatalf("hkdf reference derivation failed: %v", err)
	}

	if !bytes.Equal(seed[:], expected) {
		t.Fatalf("SeedFromMnemonic mismatch\nexpected: %x\n     got: %x", expected, seed[:])
	}
}

// TestSeedFromMnemonicNormalization ensures different Unicode forms yield identical seeds.
func TestSeedFromMnemonicNormalization(t *testing.T) {
	words := strings.Fields("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title")
	pass1 := "café"
	pass2 := "cafe\u0301"

	seed1, err := SeedFromMnemonic(words, pass1)
	if err != nil {
		t.Fatalf("SeedFromMnemonic (pass1) returned error: %v", err)
	}
	seed2, err := SeedFromMnemonic(words, pass2)
	if err != nil {
		t.Fatalf("SeedFromMnemonic (pass2) returned error: %v", err)
	}

	if !reflect.DeepEqual(seed1, seed2) {
		t.Fatalf("normalized seeds differ for equivalent passphrases:\n% x\n% x", seed1[:], seed2[:])
	}
}
