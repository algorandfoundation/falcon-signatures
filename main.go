package cli

import (
	"fmt"
	"os"
)

type keyPairJSON struct {
	PublicKey  string `json:"public_key,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

// Main is the CLI entrypoint used by the falcon binary.
func Main() {
	if len(os.Args) < 2 {
		// No subcommand -> show help
		fmt.Fprint(os.Stdout, topHelp)
		os.Exit(0)
	}

	cmd := os.Args[1]
	switch cmd {
	case "create":
		code := runCreate(os.Args[2:])
		os.Exit(code)
	case "sign":
		code := runSign(os.Args[2:])
		os.Exit(code)
	case "verify":
		code := runVerify(os.Args[2:])
		os.Exit(code)
	case "info":
		code := runInfo(os.Args[2:])
		os.Exit(code)
	case "algorand":
		code := runAlgorand(os.Args[2:])
		os.Exit(code)
	case "help", "-h", "--help":
		runHelp(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		fmt.Fprint(os.Stderr, topHelp)
		os.Exit(2)
	}
}
