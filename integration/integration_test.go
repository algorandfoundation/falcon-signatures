//go:build integration

package integration

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/algorandfoundation/falcon-signatures/algorand"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
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

// TestAlgorandSend tests the "falcon algorand send" command
func TestAlgorandSend(t *testing.T) {
	t.Parallel()
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

// TestPrecompiles tests that the precompiled .tok files match their source teal
func TestPrecompiles(t *testing.T) {
	t.Parallel()

	// teal, tok matching file pairs
	files := [][2]string{
		{
			filepath.Join("..", "algorand", "teal", "dummyLsig.teal"),
			filepath.Join("..", "algorand", "teal", "dummyLsig.teal.tok"),
		},
		{
			filepath.Join("..", "algorand", "teal", "PQlogicsig.teal"),
			filepath.Join("..", "algorand", "teal", "PQlogicsig.teal.tok"),
		},
	}
	for _, pair := range files {
		tealPath, tokPath := pair[0], pair[1]
		tealSource, err := os.ReadFile(tealPath)
		if err != nil {
			t.Fatalf("failed to read TEAL source %s: %v", tealPath, err)
		}
		compiled, err := algorand.CompileLogicSig(string(tealSource))
		if err != nil {
			t.Fatalf("failed to compile dummy teal: %v", err)
		}
		precompiled, err := os.ReadFile(tokPath)
		if err != nil {
			t.Fatalf("failed to read compiled TEAL %s: %v", tokPath, err)
		}
		if !bytes.Equal(compiled.Lsig.Logic, precompiled) {
			t.Fatalf("compiled bytes do not match expected bytes")
		}
	}
}

// TestPQLogicSigDerivationWithPrecompile tests that DerivePQLogicSig which uses
// the precompiled TEAL gives the same result as DerivePQLogicSigWithCompilation
// which compiles the TEAL on the fly with an algod node.
func TestPQLogicSigDerivationWithPrecompile(t *testing.T) {
	t.Parallel()
	iterations := 10
	for range iterations {
		keyPair, err := falcongo.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("failed to generate Falcon keypair: %v", err)
		}
		lsig1, err1 := algorand.DerivePQLogicSig(keyPair.PublicKey)
		if err1 != nil && !errors.Is(err1, algorand.ErrInvalidFalconPublicKey) {
			t.Fatalf("DerivePQLogicSig failed: %v", err1)
		}
		lsig2, err2 := algorand.DerivePQLogicSigWithCompilation(keyPair.PublicKey)
		if err2 != nil && !errors.Is(err2, algorand.ErrInvalidFalconPublicKey) {
			t.Fatalf("DerivePQLogicSigWithCompilation failed: %v", err2)
		}
		// If both functions report the “invalid key” category, that’s a valid outcome.
		if errors.Is(err1, algorand.ErrInvalidFalconPublicKey) &&
			errors.Is(err2, algorand.ErrInvalidFalconPublicKey) {
			continue
		}
		addr1, err := lsig1.Address()
		if err != nil {
			t.Fatalf("lsig1.Address() failed: %v", err)
		}
		addr2, err := lsig2.Address()
		if err != nil {
			t.Fatalf("lsig2.Address() failed: %v", err)
		}
		if addr1 != addr2 {
			t.Fatalf("derived addresses do not match:%s != %s for pubkey %v",
				addr1.String(), addr2.String(), keyPair.PublicKey)
		}
	}
}
