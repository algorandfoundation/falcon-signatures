package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strings"
)

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

const helpInfo = `# falcon info

Display info about a keypair JSON file.

Arguments:
  --key <file>   path to keypair JSON

Example:
  falcon info --key mykeys.json
`
