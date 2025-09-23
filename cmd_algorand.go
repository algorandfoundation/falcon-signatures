package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/algorandfoundation/falcon-signatures/algorand"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

// ---- algorand dispatcher ----
func runAlgorand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: falcon algorand <address|send> [flags]\n")
		fmt.Fprintln(os.Stderr, "Run 'falcon help algorand' for details.")
		return 2
	}
	sub := args[0]
	switch sub {
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, helpAlgorand)
		return 0
	case "address":
		return runAlgorandAddress(args[1:])
	case "send":
		return runAlgorandSend(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown algorand subcommand: %s\n", sub)
		fmt.Fprintf(os.Stderr, "usage: falcon algorand <address|send> [flags]\n")
		fmt.Fprintln(os.Stderr, "Run 'falcon help algorand' for details.")
		return 2
	}
}

// ---- algorand address ----
// Parse flags only; functionality is not implemented yet.
func runAlgorandAddress(args []string) int {
	fs := flag.NewFlagSet("algorand address", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to keypair/public key JSON file")
	out := fs.String("out", "", "write derived address to file (stdout if empty)")
	_ = fs.Parse(args)

	if *keyPath == "" {
		fmt.Fprintf(os.Stderr, "--key is required\n")
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

	var pk falcongo.PublicKey
	copy(pk[:], pub)

	address, err := algorand.GetAddressFromPublicKey(pk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error deriving address: %v\n", err)
		return 2
	}

	if *out == "" {
		os.Stdout.Write(address)
		os.Stdout.Write([]byte("\n"))
		return 0
	}

	if err := writeFileAtomic(*out, address, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", *out, err)
		return 2
	}
	return 0
}

// ---- algorand send ----
// Parse flags only; functionality is not implemented yet.
func runAlgorandSend(args []string) int {
	fs := flag.NewFlagSet("algorand send", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to FALCON keypair JSON file")
	to := fs.String("to", "", "Algorand destination address")
	amount := fs.Uint64("amount", 0, "amount to send in microAlgos")
	fee := fs.Uint64("fee", 0, "transaction fee in microAlgos (default: min network fee)")
	note := fs.String("note", "", "optional transaction note")
	networkFlag := fs.String("network", "mainnet", "network: mainnet, testnet, betanet, devnet")
	_ = fs.Parse(args)
	// Track whether the user explicitly set --fee (even if zero)
	feeSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "fee" {
			feeSet = true
		}
	})

	// Validate required flags
	if *keyPath == "" {
		fmt.Fprintf(os.Stderr, "--key is required\n")
		return 2
	}
	if *to == "" {
		fmt.Fprintf(os.Stderr, "--to is required\n")
		return 2
	}
	if *amount == 0 {
		fmt.Fprintf(os.Stderr, "--amount is required and must be > 0\n")
		return 2
	}

	// Parse network
	netw, err := parseAlgorandNetwork(*networkFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --network: %v\n", err)
		return 2
	}

	// Load keypair (must include both public and private keys)
	pub, priv, err := loadKeypairFile(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read --key: %v\n", err)
		return 2
	}
	if pub == nil {
		fmt.Fprintf(os.Stderr, "public key not found in %s (required for sending)\n", *keyPath)
		return 2
	}
	if priv == nil {
		fmt.Fprintf(os.Stderr, "private key not found in %s (required for sending)\n", *keyPath)
		return 2
	}

	var kp falcongo.KeyPair
	copy(kp.PublicKey[:], pub)
	copy(kp.PrivateKey[:], priv)

	opt := algorand.SendOptions{
		Network:    netw,
		Fee:        *fee,
		Note:       []byte(*note),
		UseFlatFee: feeSet,
	}

	txID, err := algorand.Send(kp, *to, *amount, opt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send failed: %v\n", err)
		return 2
	}

	fmt.Fprintf(os.Stdout, "Transaction confirmed with id: %s\n", txID)
	return 0
}

// parseAlgorandNetwork converts a string flag into an algorand.Network value.
func parseAlgorandNetwork(s string) (algorand.Network, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "mainnet":
		return algorand.MainNet, nil
	case "testnet":
		return algorand.TestNet, nil
	case "betanet":
		return algorand.BetaNet, nil
	case "devnet":
		return algorand.DevNet, nil
	default:
		return 0, fmt.Errorf("unknown network %q (valid: mainnet, testnet, betanet, devnet)", s)
	}
}

const helpAlgorand = `# falcon algorand

Algorand utilities powered by FALCON signatures.

Usage:
  falcon algorand address --key <file> [--out <file>]
  falcon algorand send --key <file> --to <address> --amount <number> [--fee <number>] [--note <string>] [--network <name>]

Subcommands:
  address   Derive an Algorand address from a FALCON public key
  send      Send Algos from a FALCON-controlled address

Arguments (address):
  --key <file>   keypair/public key JSON (required)
  --out <file>   write derived address (stdout if omitted)

Arguments (send):
  --key <file>       FALCON keypair JSON (required, must include private key)
  --to <address>     destination Algorand address (required)
  --amount <number>  amount to send in microAlgos (required)
  --fee <number>     fee in microAlgos (default: minimum network transaction fee)
  --note <string>    optional transaction note
  --network <name>   network: mainnet (default), testnet, betanet, devnet
`
