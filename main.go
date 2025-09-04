package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Help text for top-level usage (kept in sync with docs).
const topHelp = `falcon – Falcon-1024 CLI

Usage:
  falcon <command> [flags]

Commands:
  create   Create a new keypair
  sign     Sign a message
  verify   Verify a signature for a message
  info     Display information about a keypair file
  help     Show help (general or for a command)

Run 'falcon help <command>' for details.
`

type keyPairJSON struct {
	PublicKey  string `json:"public_key,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		// No subcommand -> show help
		fmt.Fprint(os.Stdout, topHelp)
		os.Exit(0)
	}

	cmd := os.Args[1]
	switch cmd {
	case "create":
		runCreate(os.Args[2:])
	case "sign":
		runSign(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "info":
		runInfo(os.Args[2:])
	case "help", "-h", "--help":
		runHelp(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		fmt.Fprint(os.Stderr, topHelp)
		os.Exit(2)
	}
}

// ---- create ----
func runCreate(args []string) {
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
		fatalf("failed to generate keypair: %v", err)
	}

	obj := keyPairJSON{
		PublicKey:  strings.ToLower(hex.EncodeToString(kp.PublicKey[:])),
		PrivateKey: strings.ToLower(hex.EncodeToString(kp.PrivateKey[:])),
	}
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		fatalf("failed to encode keypair JSON: %v", err)
	}

	if *out == "" {
		os.Stdout.Write(data)
		os.Stdout.Write([]byte("\n"))
		return
	}

	if err := writeFileAtomic(*out, data, 0o600); err != nil {
		fatalf("failed to write %s: %v", *out, err)
	}
}

// ---- info ----
func runInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to keypair JSON file")
	_ = fs.Parse(args)

	if *keyPath == "" {
		fatalf("--key is required")
	}

	pub, priv, err := loadKeypairFile(*keyPath)
	if err != nil {
		fatalf("failed to read --key: %v", err)
	}

	if pub == nil && priv == nil {
		fatalf("no keys found in %s", *keyPath)
	}

	if pub != nil {
		fmt.Printf("public_key: %s\n", strings.ToLower(hex.EncodeToString(pub)))
	}
	if priv != nil {
		fmt.Printf("private_key: %s\n", strings.ToLower(hex.EncodeToString(priv)))
	}
}

// ---- sign ----
func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to keypair JSON file")
	inFile := fs.String("in", "", "file containing message (alternative to --msg)")
	msg := fs.String("msg", "", "inline message text (alternative to --in)")
	hexIn := fs.Bool("hex", false, "treat message as hex-encoded bytes")
	out := fs.String("out", "", "write signature bytes to file (stdout hex if empty)")
	_ = fs.Parse(args)

	if *keyPath == "" {
		fatalf("--key is required")
	}
	if (*inFile == "" && *msg == "") || (*inFile != "" && *msg != "") {
		fatalf("provide exactly one of --in or --msg")
	}

	// Load private key
	_, priv, err := loadKeypairFile(*keyPath)
	if err != nil {
		fatalf("failed to read --key: %v", err)
	}
	if priv == nil {
		fatalf("private key not found in %s (required for signing)", *keyPath)
	}
	// Construct keypair struct expected by Sign
	var kp FalconKeyPair
	copy(kp.PrivateKey[:], priv)
	// Public key not needed for signing.

	// Read message
	var msgBytes []byte
	if *inFile != "" {
		b, err := os.ReadFile(*inFile)
		if err != nil {
			fatalf("failed to read --in: %v", err)
		}
		if *hexIn {
			msgBytes, err = parseHex(strings.TrimSpace(string(b)))
			if err != nil {
				fatalf("invalid hex in --in file: %v", err)
			}
		} else {
			msgBytes = b
		}
	} else {
		if *hexIn {
			var err error
			msgBytes, err = parseHex(*msg)
			if err != nil {
				fatalf("invalid --msg hex: %v", err)
			}
		} else {
			msgBytes = []byte(*msg)
		}
	}

	sig, err := kp.Sign(msgBytes)
	if err != nil {
		fatalf("signing failed: %v", err)
	}

	if *out == "" {
		fmt.Println(strings.ToLower(hex.EncodeToString(sig)))
		return
	}

	if err := writeFileAtomic(*out, sig, 0o644); err != nil {
		fatalf("failed to write signature: %v", err)
	}
}

// ---- verify ----
func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to keypair/public key JSON file")
	inFile := fs.String("in", "", "file containing message (alternative to --msg)")
	msg := fs.String("msg", "", "inline message text (alternative to --in)")
	hexIn := fs.Bool("hex", false, "treat message as hex-encoded bytes")
	sigFile := fs.String("sig", "", "file containing signature bytes (alternative to --signature)")
	sigHex := fs.String("signature", "", "hex-encoded signature (alternative to --sig)")
	_ = fs.Parse(args)

	if *keyPath == "" {
		fatalf("--key is required")
	}
	if (*inFile == "" && *msg == "") || (*inFile != "" && *msg != "") {
		fatalf("provide exactly one of --in or --msg")
	}
	if (*sigFile == "" && *sigHex == "") || (*sigFile != "" && *sigHex != "") {
		fatalf("provide exactly one of --sig or --signature")
	}

	pub, _, err := loadKeypairFile(*keyPath)
	if err != nil {
		fatalf("failed to read --key: %v", err)
	}
	if pub == nil {
		fatalf("public key not found in %s", *keyPath)
	}

	// Message
	var msgBytes []byte
	if *inFile != "" {
		b, err := os.ReadFile(*inFile)
		if err != nil {
			fatalf("failed to read --in: %v", err)
		}
		if *hexIn {
			msgBytes, err = parseHex(strings.TrimSpace(string(b)))
			if err != nil {
				fatalf("invalid hex in --in file: %v", err)
			}
		} else {
			msgBytes = b
		}
	} else {
		if *hexIn {
			var err error
			msgBytes, err = parseHex(*msg)
			if err != nil {
				fatalf("invalid --msg hex: %v", err)
			}
		} else {
			msgBytes = []byte(*msg)
		}
	}

	// Signature
	var sigBytes []byte
	if *sigFile != "" {
		b, err := os.ReadFile(*sigFile)
		if err != nil {
			fatalf("failed to read --sig: %v", err)
		}
		sigBytes = b
	} else {
		b, err := parseHex(*sigHex)
		if err != nil {
			fatalf("invalid --signature hex: %v", err)
		}
		sigBytes = b
	}

	// Verify
	var pk FalconKeyPair
	copy(pk.PublicKey[:], pub)
	err = Verify(msgBytes, sigBytes, pk.PublicKey)
	if err != nil {
		fmt.Fprintln(os.Stdout, "INVALID")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "VALID")
}

// ---- help ----
func runHelp(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stdout, topHelp)
		return
	}

	topic := args[0]
	// Try built-in help topics.
	if s, ok := lookupDoc(topic); ok {
		io.Copy(os.Stdout, strings.NewReader(s))
		if !strings.HasSuffix(s, "\n") {
			fmt.Fprintln(os.Stdout)
		}
		return
	}
	// Fallback to simple usage
	fmt.Fprint(os.Stdout, topHelp)
}

// Utilities

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

// deriveSeed maps any input to a 48-byte seed using PBKDF2-HMAC-SHA512.
// Parameters are fixed for reproducibility across environments.
const (
	kdfIterations = 100000
	kdfKeyLen     = 48
	kdfSaltStr    = "falcon-cli-seed-v1"
)

func deriveSeed(b []byte) []byte {
	return pbkdf2.Key(b, []byte(kdfSaltStr), kdfIterations, kdfKeyLen, sha512.New)
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

// lookupDoc returns built-in help text for a command if present.
func lookupDoc(topic string) (string, bool) {
	switch topic {
	case "create":
		return helpCreate, true
	case "sign":
		return helpSign, true
	case "verify":
		return helpVerify, true
	case "info":
		return helpInfo, true
	case "help":
		return helpHelp, true
	default:
		return "", false
	}
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(2)
}

// Per-command help (mirrors docs succinctly)
const helpCreate = `# falcon create

Generate a new Falcon-1024 keypair.

Arguments:
  --seed <text>  deterministically derive from text seed (PBKDF2-HMAC-SHA512, 100k iters, fixed salt)
  --out <file>   write keypair JSON (stdout if omitted)

Examples:
  falcon create
  falcon create --seed "correct horse battery staple"
  falcon create --out mykeys.json
  falcon create --seed "my 12 word seed phrase ..." --out mykeys.json
`

const helpSign = `# falcon sign

Sign a message using a Falcon-1024 private key.

Arguments:
  --key <file>        keypair JSON file
  --in <file> | --msg <string>
  --hex               treat message as hex-encoded
  --out <file>        write signature bytes (stdout hex if omitted)

Examples:
  falcon sign --key mykeys.json --msg "hello world"
  falcon sign --key mykeys.json --in message.bin --hex --out payload.sig
`

const helpVerify = `# falcon verify

Verify a Falcon-1024 signature.

Arguments:
  --key <file>            keypair/public key JSON file
  --in <file> | --msg <string>
  --sig <file> | --signature <hex>
  --hex                   treat message as hex-encoded

Examples:
  falcon verify --key pubkey.json --in message.txt --sig signature.sig
  falcon verify --key pubkey.json --msg deadbeef --hex --signature abcd1234...
`

const helpInfo = `# falcon info

Display info about a keypair JSON file.

Arguments:
  --key <file>   path to keypair JSON

Example:
  falcon info --key mykeys.json
`

const helpHelp = `# falcon help

Show general help or per-command help.

Usage:
  falcon help
  falcon help <command>
`
