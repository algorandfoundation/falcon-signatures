//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/algorandfoundation/falcon-signatures/algorand"
)

var (
	localSetupScriptPath    = filepath.Join(".", "local_setup.sh")
	localTeardownScriptPath = filepath.Join(".", "local_teardown.sh")
	falconPath              = filepath.Join("..", "build", "falcon")
)

// TestMain is executed before all tests and checks all prerequisites or fails:
// - ALGORAND_DATA, ALGOD_URL, ALGOD_TOKEN env vars are set
// - falcon binary exists at the expected path
//
// If not running in GitHub CI, will run a local setup script (if present).
// All env vars set by the script will be available to the tests.
// After all tests, if not running in GitHub CI, will run a local teardown script (if present).
func TestMain(m *testing.M) {

	if os.Getenv("GITHUB_ACTIONS") != "true" {
		// If present, source the local setup script and set env vars
		if _, err := os.Stat(localSetupScriptPath); err == nil {
			if err := runLocalSetup(localSetupScriptPath); err != nil {
				fmt.Fprintln(os.Stderr, "warning: could not source local setup:", err)
			}
		}
	}

	// Check prerequisites
	mustBeSet("ALGORAND_DATA", "ALGOD_URL", "ALGOD_TOKEN")
	mustExist(falconPath, true)

	code := m.Run()

	if os.Getenv("GITHUB_ACTIONS") != "true" {
		// If present, run the local teardown script
		if _, err := os.Stat(localTeardownScriptPath); err == nil {
			if err := runLocalTeardown(localTeardownScriptPath); err != nil {
				fmt.Fprintln(os.Stderr, "warning: local teardown failed:", err)
			}
		}
	}

	os.Exit(code)
}

// TestAlgorandSend tests the "falcon algorand send" command.
func TestAlgorandSend(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.json")

	out := runCommand(t, falconPath, "create", "--out", keyFile)
	t.Logf("Created keypair in %s\n", keyFile)

	out = runCommand(t, falconPath, "algorand", "address", "--key", keyFile)
	address := string(bytes.TrimSpace(out))
	t.Logf("Derived address: %s\n", address)

	fundAddress(t, address, 1000_000_000) // Fund with 1000 ALGO
	t.Logf("Funded address %s with 1000 ALGO\n", address)

	_ = runCommand(t, falconPath, "algorand", "send", "--key", keyFile,
		"--to", address, "--amount", "1000", "--network", "devnet")
}

// TestDummyLsigCompilation tests that the precompiled dummyLsig.teal matches
// it source teal.
func TestDummyLsigCompilation(t *testing.T) {
	tealPath := filepath.Join("..", "algorand", "teal", "dummyLsig.teal")
	tealSource, err := os.ReadFile(tealPath)
	if err != nil {
		t.Fatalf("failed to read TEAL source %s: %v", tealPath, err)
	}

	compiled, err := algorand.CompileLogicSig(string(tealSource))
	if err != nil {
		t.Fatalf("failed to compile dummy teal: %v", err)
	}

	expectedPath := filepath.Join("..", "algorand", "teal", "dummyLsig.teal.tok")
	expectedBytes, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read compiled TEAL %s: %v", expectedPath, err)
	}

	if !bytes.Equal(compiled.Lsig.Logic, expectedBytes) {
		t.Fatalf("compiled bytes do not match expected bytes")
	}
}
