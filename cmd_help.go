package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
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
  algorand Algorand utilities (address, send)
  help     Show help (general or for a command)

Run 'falcon help <command>' for details.
`

// ---- help ----
func runHelp(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stdout, topHelp)
		return 0
	}

	topic := args[0]
	// Try built-in help topics.
	if s, ok := lookupDoc(topic); ok {
		if _, err := io.Copy(os.Stdout, strings.NewReader(s)); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write help: %v\n", err)
			return 2
		}
		if !strings.HasSuffix(s, "\n") {
			fmt.Fprintln(os.Stdout)
		}
		return 0
	}
	// Fallback to simple usage
	fmt.Fprint(os.Stdout, topHelp)
	return 0
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
	case "algorand":
		return helpAlgorand, true
	case "help":
		return helpHelp, true
	default:
		return "", false
	}
}

const helpHelp = `# falcon help

Show general help or per-command help.

Usage:
  falcon help
  falcon help <command>
`

const helpAlgorand = `# falcon algorand

Algorand utilities powered by Falcon signatures.

Usage:
  falcon algorand address --key <file> [--out <file>]
  falcon algorand send --key <file> --to <address> --amount <number> [--fee <number>] [--asset-id <number>] [--note <string>] [--network <name>]

Subcommands:
  address   Derive an Algorand address from a Falcon public key
  send      Send Algos or ASA units from a Falcon-controlled address

Arguments (address):
  --key <file>   keypair/public key JSON (required)
  --out <file>   write derived address (stdout if omitted)

Arguments (send):
  --key <file>       Falcon keypair JSON (required, must include private key)
  --to <address>     destination Algorand address (required)
  --amount <number>  amount to send (microAlgos or asset units) (required)
  --fee <number>     fee in microAlgos (default: minimum network transaction fee)
  --asset-id <num>   ASA ID (omit or 0 for Algos)
  --note <string>    optional transaction note
  --network <name>   network: mainnet (default), testnet, betanet, devnet
`
