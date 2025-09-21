//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// getFaucetAddress returns the address of the first account listed by
// `goal account list`, which is assumed to be the faucet account.
func getFaucetAddress(t testing.TB) (string, error) {
	out := runCommand(t, "goal", "account", "list")

	for line := range bytes.SplitSeq(out, []byte("\n")) {
		fields := strings.Fields(string(line))
		if len(fields) >= 3 {
			return fields[2], nil
		}
	}
	return "", fmt.Errorf("no account address found in goal output")
}

// fundAddress sends the specified amount of microAlgos from the faucet account
// to the given address.
func fundAddress(t testing.TB, address string, amount int64) {

	faucetAddress, err := getFaucetAddress(t)
	if err != nil {
		t.Fatalf("failed to get faucet address: %v", err)
	}

	_ = runCommand(t, "goal", "clerk", "send",
		"-a", fmt.Sprintf("%d", amount),
		"-f", faucetAddress,
		"-t", address,
	)

	// Check balance.
	out := runCommand(t, "goal", "account", "balance", "-a", address)

	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		t.Fatalf("unexpected balance output: %s", out)
	}
	balance, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		t.Fatalf("failed to parse balance: %v", err)
	}
	if balance < amount {
		t.Fatalf("balance %d is less than expected amount %d", balance, amount)
	}
}
