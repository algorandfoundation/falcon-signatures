package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// parseHex decodes a hex string, accepting optional 0x prefix and odd nibble by padding.
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

// loadKeypairFile reads JSON {public_key, private_key} as hex strings.
func loadKeypairFile(path string) (pub []byte, priv []byte, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var obj keyPairJSON
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if obj.PublicKey != "" {
		pb, err := parseHex(obj.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid public_key hex: %w", err)
		}
		pub = pb
	}
	if obj.PrivateKey != "" {
		sk, err := parseHex(obj.PrivateKey)
		if err != nil {
			return pub, nil, fmt.Errorf("invalid private_key hex: %w", err)
		}
		priv = sk
	}
	return pub, priv, nil
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

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(2)
}
