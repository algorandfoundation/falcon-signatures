package main

import (
	"fmt"
	"os"
)

type keyPairJSON struct {
	PublicKey  string `json:"public_key,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		// No subcommand -> show help
		fmt.Fprint(os.Stdout, topHelp)
		os.Exit(0)
	}

	cmd := os.Args[1]
	switch cmd {
	case "create":
		runCreate(os.Args[2:])
	case "sign":
		runSign(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "info":
		runInfo(os.Args[2:])
	case "help", "-h", "--help":
		runHelp(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		fmt.Fprint(os.Stderr, topHelp)
		os.Exit(2)
	}
}
