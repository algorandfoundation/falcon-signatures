// Package mnemonic provides functions to generate and validate mnemonic phrases
// based on the BIP-39 standard, and to derive Falcon seeds from them.
//
// It uses 24 words from the BIP-39 English word list, corresponding to
// 256 bits of entropy plus an 8-bit checksum.
//
// This is consistent with NIST level 5 security requirements of 128 bits of
// quantum security, even if reduces Falcon-1024 native security of ~140 bits
package mnemonic

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"runtime"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

const (
	entropyLength    = 32
	mnemonicWordSize = 24
	bitsPerWord      = 11
	checksumBits     = entropyLength / 4 // 8 bits for 256-bit entropy
	pbkdf2Iterations = 2048
	bip39SeedSize    = 64
	falconSeedSize   = 48
	hkdfSalt         = "bip39-falcon-seed-salt-v1"
	hkdfInfoString   = "Falcon1024 seed v1"
)

var wordToIndex = func() map[string]uint16 {
	m := make(map[string]uint16, len(words))
	for i, w := range words {
		m[w] = uint16(i)
	}
	return m
}()

// EntropyToMnemonic converts a 32-byte entropy value into a 24-word BIP-39 mnemonic.
func EntropyToMnemonic(entropy []byte) ([]string, error) {
	if len(entropy) != entropyLength {
		return nil, fmt.Errorf("mnemonic: entropy must be %d bytes", entropyLength)
	}

	out := make([]string, mnemonicWordSize)
	hashed := sha256.Sum256(entropy)
	checksum := uint32(hashed[0] >> (8 - checksumBits))

	var acc uint32
	bits := 0
	wordIdx := 0
	for _, b := range entropy {
		acc = (acc << 8) | uint32(b)
		bits += 8

		for bits >= bitsPerWord {
			bits -= bitsPerWord
			index := (acc >> bits) & ((1 << bitsPerWord) - 1)
			out[wordIdx] = words[index]
			wordIdx++
			acc &= (1 << bits) - 1
		}
	}

	acc = (acc << checksumBits) | checksum
	bits += checksumBits
	if bits != bitsPerWord {
		return nil, fmt.Errorf("mnemonic: unexpected leftover bits count: %d", bits)
	}

	out[wordIdx] = words[acc]
	if (wordIdx + 1) != mnemonicWordSize {
		return nil, fmt.Errorf("mnemonic: produced %d words; expected %d",
			wordIdx, mnemonicWordSize)
	}
	return out, nil
}

// MnemonicToEntropy converts a 24-word BIP-39 mnemonic phrase into the original
// 32-byte entropy.
func MnemonicToEntropy(phrase []string) ([]byte, error) {
	if len(phrase) != mnemonicWordSize {
		return nil, fmt.Errorf("mnemonic: phrase must contain %d words",
			mnemonicWordSize)
	}

	entropy := make([]byte, 0, entropyLength)

	var acc uint32
	bits := 0
	for _, word := range phrase {
		index, ok := wordToIndex[word]
		if !ok {
			return nil, fmt.Errorf("mnemonic: word %q is not in the BIP-39 list", word)
		}

		acc = (acc << bitsPerWord) | uint32(index)
		bits += bitsPerWord

		for bits >= 8 && len(entropy) < entropyLength {
			bits -= 8
			entropy = append(entropy, byte(acc>>bits))
			acc &= (1 << bits) - 1
		}
	}

	if len(entropy) != entropyLength {
		return nil, fmt.Errorf("mnemonic: incomplete entropy data")
	}

	if bits != checksumBits {
		return nil, fmt.Errorf("mnemonic: unexpected checksum length: expected %d, got %d",
			checksumBits, bits)
	}

	checksum := byte(acc)
	expected := sha256.Sum256(entropy)
	expectedChecksum := byte(expected[0] >> (8 - checksumBits))

	if checksum != expectedChecksum {
		return nil, fmt.Errorf("mnemonic: checksum mismatch")
	}

	return entropy, nil
}

// SeedFromMnemonic derives a 48-byte Falcon seed from a BIP-39 mnemonic and
// optional passphrase.
// The procedure mirrors the BIP-39 specification and documents our only
// intentional deviation:
//  1. Normalize the mnemonic sentence and passphrase with NFKD (as required by
//     BIP-39) and run PBKDF2-HMAC-SHA512 with 2048 iterations and the
//     "mnemonic"+passphrase salt to obtain the canonical 64-byte BIP-39 seed.
//  2. Collapse that seed to the 48-byte value we'll use in falcon.GenerateKey
//     via HKDF-SHA512 using a Falcon-specific salt/info pair.
func SeedFromMnemonic(phrase []string, passphrase string) ([falconSeedSize]byte, error) {
	// Ensure mnemonic is valid (structure + checksum) before deriving secrets.
	if _, err := MnemonicToEntropy(phrase); err != nil {
		return [falconSeedSize]byte{}, err
	}

	sentence := normalizeNFKD(strings.Join(phrase, " "))
	pass := normalizeNFKD(passphrase)
	salt := "mnemonic" + pass

	bip39Seed := pbkdf2.Key([]byte(sentence), []byte(salt), pbkdf2Iterations,
		bip39SeedSize, sha512.New)
	defer zero(bip39Seed)

	r := hkdf.New(sha512.New, bip39Seed, []byte(hkdfSalt), []byte(hkdfInfoString))

	var out [falconSeedSize]byte
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return [falconSeedSize]byte{}, fmt.Errorf("mnemonic: hkdf derive: %w", err)
	}
	return out, nil
}

// normalizeNFKD applies Unicode NFKD normalization to the input string.
func normalizeNFKD(s string) string {
	return norm.NFKD.String(s)
}

// zero overwrites the contents of the given byte slice with zeros.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
