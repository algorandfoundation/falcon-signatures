package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/algorand/falcon"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// ---- verify ----
func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to keypair/public key JSON file")
	inFile := fs.String("in", "", "file containing message (alternative to --msg)")
	msg := fs.String("msg", "", "inline message text (alternative to --in)")
	hexIn := fs.Bool("hex", false, "treat message as hex-encoded bytes")
	sigFile := fs.String("sig", "", "file containing signature bytes (alternative to --signature)")
	sigHex := fs.String("signature", "", "hex-encoded signature (alternative to --sig)")
	_ = fs.Parse(args)

	if *keyPath == "" {
		fmt.Fprintf(os.Stderr, "--key is required\n")
		return 2
	}
	if (*inFile == "" && *msg == "") || (*inFile != "" && *msg != "") {
		fmt.Fprintf(os.Stderr, "provide exactly one of --in or --msg\n")
		return 2
	}
	if (*sigFile == "" && *sigHex == "") || (*sigFile != "" && *sigHex != "") {
		fmt.Fprintf(os.Stderr, "provide exactly one of --sig or --signature\n")
		return 2
	}

	pub, _, err := loadKeypairFile(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read --key: %v\n", err)
		return 2
	}
	if pub == nil {
		fmt.Fprintf(os.Stderr, "public key not found in %s\n", *keyPath)
		return 2
	}

	// Message
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

	// Signature
	var sigBytes []byte
	if *sigFile != "" {
		b, err := os.ReadFile(*sigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read --sig: %v\n", err)
			return 2
		}
		sigBytes = b
	} else {
		b, err := parseHex(*sigHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --signature hex: %v\n", err)
			return 2
		}
		sigBytes = b
	}

	// Verify
	var pk falcongo.KeyPair
	copy(pk.PublicKey[:], pub)
	err = falcongo.Verify(msgBytes, falcon.CompressedSignature(sigBytes), pk.PublicKey)
	if err != nil {
		fmt.Fprintln(os.Stdout, "INVALID")
		return 1
	}
	fmt.Fprintln(os.Stdout, "VALID")
	return 0
}

const helpVerify = `# falcon verify

Verify a FALCON-1024 signature.

Arguments:
  --key <file>         keypair/public key JSON file
  --in <file>  | --msg <string>
  --sig <file> | --signature <hex>
  --hex                treat message as hex-encoded (utf-8 if omitted)

Examples:
  falcon verify --key pubkey.json --in message.txt --sig signature.sig
  falcon verify --key pubkey.json --msg deadbeef --hex --signature abcd1234...
`
