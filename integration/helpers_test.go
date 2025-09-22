//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var (
	execCtxTimeout = 10 * time.Second
)

// runCommand executes cmdName with args and fails the test if it times out or returns an error.
// It returns the combined stdout+stderr for further inspection.
// The timeout is controlled by execCtxTimeout.
func runCommand(t testing.TB, cmdName string, arg ...string) []byte {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), execCtxTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdName, arg...)
	out, err := cmd.CombinedOutput()

	if err != nil {
		// Timeout/canceled: error wraps context.DeadlineExceeded
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("command %q timed out after %s\noutput:\n%s",
				cmd.String(), execCtxTimeout, out)
		}
		// Non-zero exit code: show code and output
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("command %q exited with code %d\noutput:\n%s",
				cmd.String(), ee.ExitCode(), out)
		}
		// Start/exec failure (binary not found, permission, etc.)
		t.Fatalf("command %q failed to start: %v", cmd.String(), err)
	}

	return out
}

// checkEnv ensures the given environment variable is set.
func mustBeSet(varNames ...string) {
	for _, name := range varNames {
		if os.Getenv(name) == "" {
			fmt.Fprintf(os.Stderr, "env var: %s is not set\n", name)
			os.Exit(1)
		}
	}
}

// mustExist ensures the given file exists.
// If requireExec is true, it also ensures it is executable.
func mustExist(path string, requireExec bool) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "file not found at %s\n", path)
		} else {
			fmt.Fprintf(os.Stderr, "stat(%s): %v\n", path, err)
		}
		os.Exit(1)
	}
	if requireExec && info.Mode()&0o111 == 0 {
		fmt.Fprintf(os.Stderr, "%s is not executable\n", path)
		os.Exit(1)
	}
}

// runLocalSetup sources the given script and sets any exported env vars,
// overwriting any existing ones.
// It expects the script to be a bash script, this only works on Unix-like systems
// with bash available.
func runLocalSetup(scriptPath string) error {
	if _, err := exec.LookPath("bash"); err != nil {
		return fmt.Errorf("bash not found in PATH: %w", err)
	}

	// Snapshot current env so we can detect changes to apply.
	before := os.Environ()
	beforeMap := make(map[string]string, len(before))
	for _, kv := range before {
		if i := strings.IndexByte(kv, '='); i > 0 {
			beforeMap[kv[:i]] = kv[i+1:]
		}
	}

	// The script must complete within 120s
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Run bash, source the script, print env as NUL-separated.
	// We pass scriptPath as $1 to avoid shell-escaping issues.
	// set -a: auto-export all assignments so env -0 sees them.
	cmd := exec.CommandContext(ctx, "bash", "-c", `set -a; source "$1"; env -0`, "bash",
		scriptPath)
	cmd.Env = os.Environ()

	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("setup timed out: %q", scriptPath)
		}
		return fmt.Errorf("setup %q failed: %v\nstderr/stdout:\n%s",
			scriptPath, err, string(out))
	}
	// printout for debugging
	fmt.Printf("sourced %s, env:\n%s\n", scriptPath, string(out))

	// Parse NUL-separated KEY=VALUE and apply changes/additions
	for kv := range bytes.SplitSeq(out, []byte{0}) {
		if len(kv) == 0 {
			continue
		}
		i := bytes.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		k := string(kv[:i])
		v := string(kv[i+1:])

		// Set new or changed
		if old, ok := beforeMap[k]; !ok || old != v {
			if err := os.Setenv(k, v); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not set %s: %v\n", k, err)
			}
		}
	}
	return nil
}

// runLocalTeardown runs the given script.
// It expects the script to be a bash script, this only works on Unix-like systems
// with bash available.
func runLocalTeardown(scriptPath string) error {
	if _, err := exec.LookPath("bash"); err != nil {
		return fmt.Errorf("bash not found in PATH: %w", err)
	}

	// The script must complete within 120s
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-eu", scriptPath)
	cmd.Env = os.Environ() // inherits whatever setup established
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("teardown timed out: %s", scriptPath)
		}
		return fmt.Errorf("teardown failed: %s\noutput:\n%s", scriptPath, out)
	}
	return nil
}
