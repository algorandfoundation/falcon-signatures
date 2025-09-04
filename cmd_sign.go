package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

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
