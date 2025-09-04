package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ---- create ----
func runCreate(args []string) int {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	seedText := fs.String("seed", "", "text seed/passphrase (KDF 100k iters, fixed salt)")
	out := fs.String("out", "", "write keypair JSON to file (stdout if empty)")
	_ = fs.Parse(args)

	var seed []byte
	var err error
	if *seedText != "" {
		// Derive deterministic 48-byte seed with PBKDF2-HMAC-SHA512 from text.
		seed = deriveSeed([]byte(*seedText))
	}

	kp, err := GenerateFalconKeyPair(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate keypair: %v\n", err)
		return 2
	}

	obj := keyPairJSON{
		PublicKey:  strings.ToLower(hex.EncodeToString(kp.PublicKey[:])),
		PrivateKey: strings.ToLower(hex.EncodeToString(kp.PrivateKey[:])),
	}
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode keypair JSON: %v\n", err)
		return 2
	}

	if *out == "" {
		os.Stdout.Write(data)
		os.Stdout.Write([]byte("\n"))
		return 0
	}

	if err := writeFileAtomic(*out, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", *out, err)
		return 2
	}
	return 0
}

// Seed derivation parameters from user seedphrase
const (
	kdfIterations = 100000
	kdfKeyLen     = 48
	kdfSaltStr    = "falcon-cli-seed-v1"
)

// deriveSeed maps any input to a 48-byte seed using PBKDF2-HMAC-SHA512.
func deriveSeed(b []byte) []byte {
	return pbkdf2.Key(b, []byte(kdfSaltStr), kdfIterations, kdfKeyLen, sha512.New)
}

// Per-command help (mirrors docs succinctly)
const helpCreate = `# falcon create

Generate a new Falcon-1024 keypair.

Arguments:
  --seedphrase <text>  optional text passphrase (choose at least 12 words for security)
  --out <file>         write keypair JSON (stdout if omitted)

Examples:
  falcon create
  falcon create --seed "my 12 word seed phrase ..."
  falcon create --out mykeys.json
  falcon create --seed "my 12 word seed phrase ..." --out mykeys.json
`
