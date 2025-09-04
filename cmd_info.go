package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

// ---- info ----
func runInfo(args []string) int {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to keypair JSON file")
	_ = fs.Parse(args)

	if *keyPath == "" {
		fmt.Fprintf(os.Stderr, "--key is required\n")
		return 2
	}

	pub, priv, err := loadKeypairFile(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read --key: %v\n", err)
		return 2
	}

	if pub == nil && priv == nil {
		fmt.Fprintf(os.Stderr, "no keys found in %s\n", *keyPath)
		return 2
	}

	if pub != nil {
		fmt.Printf("public_key: %s\n", strings.ToLower(hex.EncodeToString(pub)))
	}
	if priv != nil {
		fmt.Printf("private_key: %s\n", strings.ToLower(hex.EncodeToString(priv)))
	}
	return 0
}

const helpInfo = `# falcon info

Display info about a keypair JSON file.

Arguments:
  --key <file>   path to keypair JSON

Example:
  falcon info --key mykeys.json
`
