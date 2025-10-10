package cli

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
	"github.com/algorandfoundation/falcon-signatures/mnemonic"
	"golang.org/x/crypto/pbkdf2"
)

// ---- create ----
func runCreate(args []string) int {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	seedText := fs.String("seed", "", "text seed/passphrase (KDF 100k iters, fixed salt)")
	out := fs.String("out", "", "write keypair JSON to file (stdout if empty)")
	mnemonicPassphrase := fs.String("mnemonic-passphrase", "", "optional mnemonic passphrase used for BIP-39 seed derivation")
	noMnemonic := fs.Bool("no-mnemonic", false, "generate a random keypair without mnemonic (384-bit entropy)")
	fromMnemonic := fs.String("from-mnemonic", "", "recover keypair from a 24-word BIP-39 mnemonic")
	_ = fs.Parse(args)

	recoveryInput := strings.TrimSpace(*fromMnemonic)
	if *seedText != "" && recoveryInput != "" {
		fmt.Fprintln(os.Stderr, "cannot combine --seed with --from-mnemonic")
		return 2
	}
	if *seedText != "" && *noMnemonic {
		fmt.Fprintln(os.Stderr, "cannot combine --seed with --no-mnemonic")
		return 2
	}
	if *seedText != "" && *mnemonicPassphrase != "" {
		fmt.Fprintln(os.Stderr, "cannot combine --seed with --mnemonic-passphrase")
		return 2
	}
	if *mnemonicPassphrase != "" && *noMnemonic {
		fmt.Fprintln(os.Stderr, "cannot combine --mnemonic-passphrase with --no-mnemonic")
		return 2
	}
	if recoveryInput != "" && *noMnemonic {
		fmt.Fprintln(os.Stderr, "cannot combine --from-mnemonic with --no-mnemonic")
		return 2
	}

	useMnemonic := !*noMnemonic && *seedText == "" && recoveryInput == ""

	var kp falcongo.KeyPair
	var err error
	var words []string
	includeMnemonic := false

	switch {
	case recoveryInput != "":
		words = strings.Fields(recoveryInput)
		if len(words) != expectedMnemonicWords {
			fmt.Fprintf(os.Stderr,
				"--from-mnemonic requires exactly %d words (got %d)\n",
				expectedMnemonicWords, len(words))
			return 2
		}
		seedArray, err := mnemonic.SeedFromMnemonic(words, *mnemonicPassphrase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to derive Falcon seed from mnemonic: %v\n",
				err)
			return 2
		}
		if kp, err = falcongo.GenerateKeyPair(seedArray[:]); err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate keypair: %v\n", err)
			return 2
		}
		includeMnemonic = !*noMnemonic
	case *seedText != "":
		if kp, err = falcongo.GenerateKeyPair(deriveSeed([]byte(*seedText))); err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate keypair: %v\n", err)
			return 2
		}
	case useMnemonic:
		entropy := make([]byte, 32)
		if _, err := rand.Read(entropy); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read entropy: %v\n", err)
			return 2
		}
		words, err = mnemonic.EntropyToMnemonic(entropy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to derive mnemonic: %v\n", err)
			return 2
		}
		seedArray, err := mnemonic.SeedFromMnemonic(words, *mnemonicPassphrase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to derive Falcon seed from mnemonic: %v\n",
				err)
			return 2
		}
		if kp, err = falcongo.GenerateKeyPair(seedArray[:]); err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate keypair: %v\n", err)
			return 2
		}
		includeMnemonic = true
	default:
		var generateErr error
		if kp, generateErr = falcongo.GenerateKeyPair(nil); generateErr != nil {
			fmt.Fprintf(os.Stderr, "failed to generate keypair: %v\n", generateErr)
			return 2
		}
	}

	obj := keyPairJSON{
		PublicKey:  strings.ToLower(hex.EncodeToString(kp.PublicKey[:])),
		PrivateKey: strings.ToLower(hex.EncodeToString(kp.PrivateKey[:])),
	}
	if includeMnemonic && len(words) > 0 {
		obj.Mnemonic = strings.Join(words, " ")
		if *mnemonicPassphrase != "" {
			obj.MnemonicPassphrase = *mnemonicPassphrase
		}
	}
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode keypair JSON: %v\n", err)
		return 2
	}

	if *out == "" {
		if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write keypair JSON: %v\n", err)
			return 2
		}
	} else {
		if err := writeFileAtomic(*out, data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", *out, err)
			return 2
		}
	}
	return 0
}

// Seed derivation parameters from user seedphrase
const (
	kdfIterations         = 100000
	kdfKeyLen             = 48
	kdfSaltStr            = "falcon-cli-seed-v1"
	expectedMnemonicWords = 24
)

// deriveSeed maps any input to a 48-byte seed using PBKDF2-HMAC-SHA512.
func deriveSeed(b []byte) []byte {
	return pbkdf2.Key(b, []byte(kdfSaltStr), kdfIterations, kdfKeyLen, sha512.New)
}

const helpCreate = `# falcon create

Generate a new FALCON-1024 keypair.

Arguments:
  --out <file>				  write keypair JSON (stdout if omitted)
  --mnemonic-passphrase <string>
                              optional mnemonic passphrase (stored in JSON when set)
  --no-mnemonic               generate a random keypair with 384-bit entropy (no mnemonic)
  --seed <text>               generate a deterministic keypair from provided passphrase (no mnemonic)
  --from-mnemonic <24 words>  recover keypair from a 24-word BIP-39 mnemonic

Examples:
  falcon create
  falcon create --out mykeys.json
  falcon create --mnemonic-passphrase "TREZOR" --out mykeys.json
  falcon create --no-mnemonic --out mykeys.json
  falcon create --seed "my 12 word seed phrase ..."
  falcon create --from-mnemonic "abandon abandon ... art" --mnemonic-passphrase "TREZOR"
`
