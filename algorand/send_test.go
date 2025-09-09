//go:build integration

package algorand

import (
	"bytes"
	_ "embed"
	"testing"
)

//go:embed teal/dummyLsig.teal
var dummyLsigTeal string

func TestDummyTealCompilation(t *testing.T) {
	compiled, err := CompileLogicSig(dummyLsigTeal)
	if err != nil {
		t.Fatalf("failed to compile dummy teal: %v", err)
	}
	tealBytes := compiled.Lsig.Logic

	if !bytes.Equal(tealBytes, dummyLsigCompiled) {
		t.Fatalf("compiled bytes do not match expected bytes")
	}
}
