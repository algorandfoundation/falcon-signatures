package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

// ---- sign ----
func runSign(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to keypair JSON file")
	inFile := fs.String("in", "", "file containing message (alternative to --msg)")
	msg := fs.String("msg", "", "inline message text (alternative to --in)")
	hexIn := fs.Bool("hex", false, "treat message as hex-encoded bytes")
	out := fs.String("out", "", "write signature bytes to file (stdout hex if empty)")
	_ = fs.Parse(args)

	if *keyPath == "" {
		fmt.Fprintf(os.Stderr, "--key is required\n")
		return 2
	}
	if (*inFile == "" && *msg == "") || (*inFile != "" && *msg != "") {
		fmt.Fprintf(os.Stderr, "provide exactly one of --in or --msg\n")
		return 2
	}

	// Load private key
	_, priv, err := loadKeypairFile(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read --key: %v\n", err)
		return 2
	}
	if priv == nil {
		fmt.Fprintf(os.Stderr, "private key not found in %s (required for signing)\n", *keyPath)
		return 2
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
			fmt.Fprintf(os.Stderr, "failed to read --in: %v\n", err)
			return 2
		}
		if *hexIn {
			msgBytes, err = parseHex(strings.TrimSpace(string(b)))
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid hex in --in file: %v\n", err)
				return 2
			}
		} else {
			msgBytes = b
		}
	} else {
		if *hexIn {
			var err error
			msgBytes, err = parseHex(*msg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid --msg hex: %v\n", err)
				return 2
			}
		} else {
			msgBytes = []byte(*msg)
		}
	}

	sig, err := kp.Sign(msgBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signing failed: %v\n", err)
		return 2
	}

	if *out == "" {
		fmt.Println(strings.ToLower(hex.EncodeToString(sig)))
		return 0
	}

	if err := writeFileAtomic(*out, sig, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write signature: %v\n", err)
		return 2
	}
	return 0
}

const helpSign = `# falcon sign

Sign a message using a Falcon-1024 private key.

Arguments:
  --key <file>        keypair JSON file
  --in <file> | --msg <string>
  --hex               treat message as hex-encoded (utf-8 if omitted)
  --out <file>        write signature bytes (stdout hex if omitted)

Examples:
  falcon sign --key mykeys.json --msg "hello world"
  falcon sign --key mykeys.json --in message.bin --hex --out payload.sig
`
