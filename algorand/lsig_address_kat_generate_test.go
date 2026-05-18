package algorand

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

const (
	lsigAddressKATSchema            = "falcon-signatures/algorand-lsig-address-kat/v1"
	lsigAddressKATPath              = "testdata/lsig_address_kat.json"
	lsigAddressKATGenerator         = "algorand/lsig_address_kat_generate_test.go"
	lsigAddressKATRegenerateCommand = "UPDATE_LSIG_ADDRESS_KAT=1 go test ./algorand -run TestUpdateLSigAddressKAT -count=1"
	lsigAddressKATSeedHex           = "a4559bec684539e5db98dbe86bba8fe2032d65f1dd9a273fc84c85d7ed610ebeb8a0db25e3ec9301c45b21184d7ad329"
)

func generateLSigAddressKATPublicKey(t testing.TB) falcongo.PublicKey {
	t.Helper()

	seed, err := hex.DecodeString(lsigAddressKATSeedHex)
	if err != nil {
		t.Fatalf("invalid LSig address KAT seed hex: %v", err)
	}
	if len(seed) != 48 {
		t.Fatalf("LSig address KAT seed length = %d, want 48", len(seed))
	}
	kp, err := falcongo.GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("failed to generate Falcon keypair: %v", err)
	}
	return kp.PublicKey
}

func generateLSigCounterCase(publicKey falcongo.PublicKey, counter byte) lsigCounterCase {
	program := patchPrecompiledPQlogicsig(publicKey, counter)
	address := crypto.AddressFromProgram(program)
	reject := isOnTheCurve(address[:])
	return lsigCounterCase{
		Counter:                        int(counter),
		Address:                        address.String(),
		AddressHex:                     hex.EncodeToString(address[:]),
		DecodesToEdwards25519Point:     reject,
		RejectForLSigAddressDerivation: reject,
	}
}

// findProgramCounterOffset records where the mutable counter lives in the
// precompiled LogicSig bytecode. Rejection sampling validates which counter is
// selected behaviorally; this structural check lets the KAT also audit that the
// fixture describes the bytecode template shape correctly.
func findProgramCounterOffset(t testing.TB, publicKey falcongo.PublicKey) int {
	t.Helper()

	counterZero := patchPrecompiledPQlogicsig(publicKey, 0)
	counterOne := patchPrecompiledPQlogicsig(publicKey, 1)
	offset := -1
	for i := range counterZero {
		if counterZero[i] == counterOne[i] {
			continue
		}
		if offset != -1 {
			t.Fatalf("programs for counter 0 and 1 differ at more than one byte")
		}
		offset = i
	}
	if offset == -1 {
		t.Fatalf("programs for counter 0 and 1 are identical")
	}
	return offset
}

func mustMarshalLSigAddressKAT(t testing.TB, kat lsigAddressKAT) string {
	t.Helper()

	data, err := json.MarshalIndent(kat, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal LSig address KAT: %v", err)
	}
	return string(append(data, '\n'))
}

func generateLSigAddressKAT(t testing.TB) lsigAddressKAT {
	t.Helper()

	publicKey := generateLSigAddressKATPublicKey(t)
	program := patchPrecompiledPQlogicsig(publicKey, 0)
	counterOffset := findProgramCounterOffset(t, publicKey)
	publicKeyOffset := bytes.Index(program, publicKey[:])
	if publicKeyOffset < 0 {
		t.Fatalf("generated program does not contain Falcon public key")
	}
	publicKeyEnd := publicKeyOffset + len(publicKey)

	counterCases := []lsigCounterCase{
		generateLSigCounterCase(publicKey, 0),
		generateLSigCounterCase(publicKey, 1),
	}
	if !counterCases[0].RejectForLSigAddressDerivation ||
		counterCases[1].RejectForLSigAddressDerivation {
		t.Fatalf("generated fixture must reject counter 0 and select counter 1")
	}

	return lsigAddressKAT{
		Schema: lsigAddressKATSchema,
		Source: lsigAddressKATSource{
			Generator:         lsigAddressKATGenerator,
			RegenerateCommand: lsigAddressKATRegenerateCommand,
			FalconSeedHex:     lsigAddressKATSeedHex,
		},
		Edwards25519DecodeCases: []edwards25519DecodeCase{
			{
				Name:                            "canonical main-subgroup base point",
				EncodingHex:                     "5866666666666666666666666666666666666666666666666666666666666666",
				DecodesToEdwards25519Point:      true,
				RejectForLSigAddressDerivation:  true,
				LibsodiumCryptoCoreIsValidPoint: true,
				Note:                            "Baseline Ed25519 public key accepted by narrow and broad predicates.",
			},
			{
				Name:                            "canonical small-order identity",
				EncodingHex:                     "0100000000000000000000000000000000000000000000000000000000000000",
				DecodesToEdwards25519Point:      true,
				RejectForLSigAddressDerivation:  true,
				LibsodiumCryptoCoreIsValidPoint: false,
				Note:                            "Small-order points still decode to Edwards25519 curve points and must be rejected.",
			},
			{
				Name:                            "x-zero sign-bit non-canonical identity",
				EncodingHex:                     "0100000000000000000000000000000000000000000000000000000000000080",
				DecodesToEdwards25519Point:      true,
				RejectForLSigAddressDerivation:  true,
				LibsodiumCryptoCoreIsValidPoint: false,
				Note:                            "filippo.io/edwards25519 accepts this ecosystem-compatible non-canonical encoding.",
			},
			{
				Name:                            "non-canonical y equals p",
				EncodingHex:                     "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
				DecodesToEdwards25519Point:      true,
				RejectForLSigAddressDerivation:  true,
				LibsodiumCryptoCoreIsValidPoint: false,
				Note:                            "The field element is non-canonical but reduces to a valid Edwards25519 point.",
			},
			{
				Name:                            "invalid y equals p plus 2",
				EncodingHex:                     "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
				DecodesToEdwards25519Point:      false,
				RejectForLSigAddressDerivation:  false,
				LibsodiumCryptoCoreIsValidPoint: false,
				Note:                            "This value does not decode to an Edwards25519 point under the broad predicate.",
			},
		},
		LSigDerivation: lsigDerivationFixture{
			Name:                   "counter zero rejected, counter one selected",
			FalconPublicKeyHex:     hex.EncodeToString(publicKey[:]),
			ProgramLength:          len(program),
			ProgramPrefixHex:       hex.EncodeToString(program[:publicKeyOffset]),
			ProgramCounterOffset:   counterOffset,
			ProgramPublicKeyOffset: publicKeyOffset,
			ProgramSuffixHex:       hex.EncodeToString(program[publicKeyEnd:]),
			SelectedCounter:        1,
			SelectedAddress:        counterCases[1].Address,
			SelectedAddressHex:     counterCases[1].AddressHex,
			CounterCases:           counterCases,
		},
	}
}

func TestLSigAddressKATMatchesGenerator(t *testing.T) {
	got := loadLSigAddressKAT(t)
	want := generateLSigAddressKAT(t)
	if reflect.DeepEqual(got, want) {
		return
	}

	gotJSON := mustMarshalLSigAddressKAT(t, got)
	wantJSON := mustMarshalLSigAddressKAT(t, want)
	t.Fatalf("LSig address KAT does not match generator\nchecked in:\n%s\nregenerated:\n%s",
		gotJSON, wantJSON)
}

func TestUpdateLSigAddressKAT(t *testing.T) {
	if os.Getenv("UPDATE_LSIG_ADDRESS_KAT") != "1" {
		t.Skip("set UPDATE_LSIG_ADDRESS_KAT=1 to rewrite " + lsigAddressKATPath)
	}

	data := mustMarshalLSigAddressKAT(t, generateLSigAddressKAT(t))
	if err := os.WriteFile(lsigAddressKATPath, []byte(data), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", lsigAddressKATPath, err)
	}
}
