package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	"github.com/algorandfoundation/falcon-signatures/mnemonic"
)

// parseHex decodes a hex string, accepting optional 0x prefix and odd nibble by padding
func parseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if s == "" {
		return []byte{}, nil
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	dst := make([]byte, hex.DecodedLen(len(s)))
	n, err := hex.Decode(dst, []byte(s))
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// loadKeypairFile reads key material and returns decoded keys,
// optionally regenerating them from a mnemonic.
func loadKeypairFile(path string, overridePassphrase *string,
) (pub []byte, priv []byte, meta keyPairJSON, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, keyPairJSON{}, err
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return nil, nil, keyPairJSON{}, fmt.Errorf("invalid JSON: %w", err)
	}
	var pubBytes, privBytes []byte
	if meta.PublicKey != "" {
		pb, err := parseHex(meta.PublicKey)
		if err != nil {
			return nil, nil, keyPairJSON{}, fmt.Errorf("invalid public_key hex: %w",
				err)
		}
		pubBytes = pb
	}
	if meta.PrivateKey != "" {
		sk, err := parseHex(meta.PrivateKey)
		if err != nil {
			return pubBytes, nil, keyPairJSON{},
				fmt.Errorf("invalid private_key hex: %w", err)
		}
		privBytes = sk
	}

	overrideProvided := overridePassphrase != nil
	overrideValue := ""
	if overrideProvided {
		overrideValue = *overridePassphrase
	}

	mnemonicPass := meta.MnemonicPassphrase
	if overrideProvided {
		if mnemonicPass != "" && mnemonicPass != overrideValue {
			return nil, nil, keyPairJSON{},
				fmt.Errorf("mnemonic passphrase mismatch between file and flag")
		}
		mnemonicPass = overrideValue
	}

	words := strings.Fields(meta.Mnemonic)
	if len(words) > 0 {
		if pubBytes == nil && privBytes == nil &&
			mnemonicPass == "" && !overrideProvided {
			return nil, nil, keyPairJSON{},
				fmt.Errorf("file contains mnemonic without passphrase; " +
					"supply --mnemonic-passphrase '' (empty string) or your " +
					"passphrase to derive keys")
		}
		seed, err := mnemonic.SeedFromMnemonic(words, mnemonicPass)
		if err != nil {
			return nil, nil, keyPairJSON{}, fmt.Errorf("mnemonic derivation failed: %w",
				err)
		}
		kp, err := falcongo.GenerateKeyPair(seed[:])
		if err != nil {
			return nil, nil, keyPairJSON{},
				fmt.Errorf("falcon keygen from mnemonic failed: %w", err)
		}
		// Best-effort wipe of intermediate seed.
		for i := range seed {
			seed[i] = 0
		}
		derivedPub := make([]byte, len(kp.PublicKey))
		copy(derivedPub, kp.PublicKey[:])
		derivedPriv := make([]byte, len(kp.PrivateKey))
		copy(derivedPriv, kp.PrivateKey[:])

		if privBytes == nil {
			privBytes = derivedPriv
		} else if !bytes.Equal(privBytes, derivedPriv) {
			return nil, nil, keyPairJSON{},
				fmt.Errorf("mnemonic does not match private key material")
		}
		if pubBytes == nil {
			pubBytes = derivedPub
		} else if !bytes.Equal(pubBytes, derivedPub) {
			return nil, nil, keyPairJSON{},
				fmt.Errorf("mnemonic does not match public key material")
		}
	} else if overrideProvided && overrideValue != "" {
		return nil, nil, keyPairJSON{},
			fmt.Errorf("--mnemonic-passphrase provided but mnemonic not found in file")
	}

	return pubBytes, privBytes, meta, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if path == "" {
		return errors.New("empty path")
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	// temp file
	tf, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return err
	}
	name := tf.Name()
	defer func() {
		tf.Close()
		os.Remove(name)
	}()
	if _, err := tf.Write(data); err != nil {
		return err
	}
	if err := tf.Sync(); err != nil { // ensure persisted
		return err
	}
	if mode != 0 {
		if err := tf.Chmod(mode); err != nil {
			return err
		}
	}
	if err := tf.Close(); err != nil {
		return err
	}
	// Atomic rename
	if err := os.Rename(name, path); err != nil {
		return err
	}
	// Best-effort directory sync on POSIX
	if df, err := os.Open(dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}
