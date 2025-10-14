package cli

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
	mnemonicPassphrase := fs.String("mnemonic-passphrase", "", "mnemonic passphrase (if used and key file omits it)")
	_ = fs.Parse(args)
	passphraseProvided := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "mnemonic-passphrase" {
			passphraseProvided = true
		}
	})

	if *keyPath == "" {
		fmt.Fprintf(os.Stderr, "--key is required\n")
		return 2
	}

	var override *string
	if passphraseProvided {
		override = mnemonicPassphrase
	}
	pub, priv, meta, err := loadKeypairFile(*keyPath, override)
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
	if meta.Mnemonic != "" {
		fmt.Printf("mnemonic: %s\n", meta.Mnemonic)
		pass := meta.MnemonicPassphrase
		if pass == "" && *mnemonicPassphrase != "" {
			pass = *mnemonicPassphrase
		}
		if pass != "" {
			fmt.Printf("mnemonic_passphrase: %s\n", pass)
		}
	}
	return 0
}

const helpInfo = `# falcon info

Display info about a keypair JSON file.

Arguments:
  --key <file>   path to keypair JSON
  --mnemonic-passphrase <string>
                 mnemonic passphrase if needed and the key file omits it

Example:
  falcon info --key mykeys.json
`
