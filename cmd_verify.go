package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

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

const helpVerify = `# falcon verify

Verify a Falcon-1024 signature.

Arguments:
  --key <file>         keypair/public key JSON file
  --in <file>  | --msg <string>
  --sig <file> | --signature <hex>
  --hex                treat message as hex-encoded (utf-8 if omitted)

Examples:
  falcon verify --key pubkey.json --in message.txt --sig signature.sig
  falcon verify --key pubkey.json --msg deadbeef --hex --signature abcd1234...
`
