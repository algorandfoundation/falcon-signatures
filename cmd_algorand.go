package cli

import (
    "flag"
    "fmt"
    "os"
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

    // Stub implementation
    _ = out // parsed but unused in stub
    fmt.Fprintln(os.Stdout, "algorand address: command not yet implemented")
    return 0
}

// ---- algorand send ----
// Parse flags only; functionality is not implemented yet.
func runAlgorandSend(args []string) int {
    fs := flag.NewFlagSet("algorand send", flag.ExitOnError)
    keyPath := fs.String("key", "", "path to Falcon keypair JSON file")
    to := fs.String("to", "", "Algorand destination address")
    amount := fs.Uint64("amount", 0, "amount to send (microAlgos or asset units)")
    fee := fs.Uint64("fee", 1000, "transaction fee in microAlgos")
    assetID := fs.Uint64("asset-id", 0, "asset ID to send (0 = Algos)")
    note := fs.String("note", "", "optional transaction note")
    _ = fs.Parse(args)

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

    // Stub implementation (acknowledge parsed flags to avoid unused warnings)
    _ = fee
    _ = assetID
    _ = note
    fmt.Fprintln(os.Stdout, "algorand send: command not yet implemented")
    return 0
}
