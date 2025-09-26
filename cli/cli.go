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
	os.Exit(Run(os.Args[1:]))
}

// Run executes the CLI with the provided arguments and returns the exit code.
func Run(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stdout, topHelp)
		return 0
	}

	cmd := args[0]
	remain := args[1:]
	switch cmd {
	case "create":
		return runCreate(remain)
	case "sign":
		return runSign(remain)
	case "verify":
		return runVerify(remain)
	case "info":
		return runInfo(remain)
	case "algorand":
		return runAlgorand(remain)
	case "help", "-h", "--help":
		return runHelp(remain)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		fmt.Fprint(os.Stderr, topHelp)
		return 2
	}
}
