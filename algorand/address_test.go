package algorand

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

type lsigAddressKAT struct {
	Edwards25519DecodeCases []edwards25519DecodeCase `json:"edwards25519_decode_cases"`
	LSigDerivation          lsigDerivationFixture    `json:"lsig_derivation"`
}

type edwards25519DecodeCase struct {
	Name                            string `json:"name"`
	EncodingHex                     string `json:"encoding_hex"`
	DecodesToEdwards25519Point      bool   `json:"decodes_to_edwards25519_point"`
	RejectForLSigAddressDerivation  bool   `json:"reject_for_lsig_address_derivation"`
	LibsodiumCryptoCoreIsValidPoint bool   `json:"libsodium_crypto_core_ed25519_is_valid_point"`
	Note                            string `json:"note"`
}

type lsigDerivationFixture struct {
	Name                     string            `json:"name"`
	FalconPublicKeyHex       string            `json:"falcon_public_key_hex"`
	FalconPublicKeySHA256Hex string            `json:"falcon_public_key_sha256_hex"`
	ProgramLength            int               `json:"program_length"`
	ProgramPrefixHex         string            `json:"program_prefix_hex"`
	ProgramCounterOffset     int               `json:"program_counter_offset"`
	ProgramPublicKeyOffset   int               `json:"program_public_key_offset"`
	ProgramSuffixHex         string            `json:"program_suffix_hex"`
	SelectedCounter          int               `json:"selected_counter"`
	SelectedAddress          string            `json:"selected_address"`
	SelectedAddressHex       string            `json:"selected_address_hex"`
	CounterCases             []lsigCounterCase `json:"counter_cases"`
}

type lsigCounterCase struct {
	Counter                        int    `json:"counter"`
	Address                        string `json:"address"`
	AddressHex                     string `json:"address_hex"`
	DecodesToEdwards25519Point     bool   `json:"decodes_to_edwards25519_point"`
	RejectForLSigAddressDerivation bool   `json:"reject_for_lsig_address_derivation"`
}

func loadLSigAddressKAT(t *testing.T) lsigAddressKAT {
	t.Helper()

	data, err := os.ReadFile("testdata/lsig_address_kat.json")
	if err != nil {
		t.Fatalf("failed to read LSig address KAT: %v", err)
	}

	var kat lsigAddressKAT
	if err := json.Unmarshal(data, &kat); err != nil {
		t.Fatalf("failed to parse LSig address KAT: %v", err)
	}
	return kat
}

// TestIsOnTheCurve_AlgorandAccounts generates random Algorand accounts and
// verifies their 32-byte public keys decode to valid Edwards25519 points.
func TestIsOnTheCurve_AlgorandAccounts(t *testing.T) {
	for i := range 100 {
		acct := crypto.GenerateAccount()
		pub := acct.Address
		if !isOnTheCurve(pub[:]) {
			t.Fatalf("generated account %d has address not on curve: %v", i, pub)
		}
	}
}

func TestDecodesToEdwards25519Point_GoldenCases(t *testing.T) {
	kat := loadLSigAddressKAT(t)
	sawCaseRejectedByNarrowPredicate := false

	for _, tc := range kat.Edwards25519DecodeCases {
		t.Run(tc.Name, func(t *testing.T) {
			value, err := hex.DecodeString(tc.EncodingHex)
			if err != nil {
				t.Fatalf("invalid hex fixture: %v", err)
			}
			got := isOnTheCurve(value)
			if got != tc.DecodesToEdwards25519Point {
				t.Fatalf("decodesToEdwards25519Point() = %v, want %v",
					got, tc.DecodesToEdwards25519Point)
			}
			if got != tc.RejectForLSigAddressDerivation {
				t.Fatalf("LSig rejection fixture says reject=%v, but decode result is %v",
					tc.RejectForLSigAddressDerivation, got)
			}
			if got && !tc.LibsodiumCryptoCoreIsValidPoint {
				sawCaseRejectedByNarrowPredicate = true
			}
		})
	}
	if !sawCaseRejectedByNarrowPredicate {
		t.Fatalf("fixture must include a broad decode case rejected by narrow validators")
	}
}

func TestDerivePQLogicSig_GoldenFixture(t *testing.T) {
	kat := loadLSigAddressKAT(t)
	derivation := kat.LSigDerivation

	publicKeyBytes, err := hex.DecodeString(derivation.FalconPublicKeyHex)
	if err != nil {
		t.Fatalf("invalid Falcon public key hex fixture: %v", err)
	}
	if len(publicKeyBytes) != len(falcongo.PublicKey{}) {
		t.Fatalf("Falcon public key length = %d, want %d",
			len(publicKeyBytes), len(falcongo.PublicKey{}))
	}

	publicKeyHash := sha256.Sum256(publicKeyBytes)
	if got := hex.EncodeToString(publicKeyHash[:]); got != derivation.FalconPublicKeySHA256Hex {
		t.Fatalf("Falcon public key SHA-256 = %s, want %s",
			got, derivation.FalconPublicKeySHA256Hex)
	}

	var publicKey falcongo.PublicKey
	copy(publicKey[:], publicKeyBytes)

	for _, tc := range derivation.CounterCases {
		t.Run(fmt.Sprintf("counter %d", tc.Counter), func(t *testing.T) {
			program := patchPrecompiledPQlogicsig(publicKey, byte(tc.Counter))
			assertFixtureProgramShape(t, program, publicKey, derivation, byte(tc.Counter))

			address := crypto.AddressFromProgram(program)
			if got := hex.EncodeToString(address[:]); got != tc.AddressHex {
				t.Fatalf("counter %d address hex = %s, want %s",
					tc.Counter, got, tc.AddressHex)
			}
			if got := address.String(); got != tc.Address {
				t.Fatalf("counter %d address = %s, want %s",
					tc.Counter, got, tc.Address)
			}

			gotDecode := isOnTheCurve(address[:])
			if gotDecode != tc.DecodesToEdwards25519Point {
				t.Fatalf("counter %d decode = %v, want %v",
					tc.Counter, gotDecode, tc.DecodesToEdwards25519Point)
			}
			if gotDecode != tc.RejectForLSigAddressDerivation {
				t.Fatalf("counter %d reject = %v, want decode result %v",
					tc.Counter, tc.RejectForLSigAddressDerivation, gotDecode)
			}
		})
	}

	lsig, err := DerivePQLogicSig(publicKey)
	if err != nil {
		t.Fatalf("DerivePQLogicSig failed: %v", err)
	}
	if got := int(lsig.Lsig.Logic[derivation.ProgramCounterOffset]); got != derivation.SelectedCounter {
		t.Fatalf("selected counter = %d, want %d", got, derivation.SelectedCounter)
	}
	address, err := lsig.Address()
	if err != nil {
		t.Fatalf("derived LogicSig address failed: %v", err)
	}
	if got := hex.EncodeToString(address[:]); got != derivation.SelectedAddressHex {
		t.Fatalf("selected address hex = %s, want %s",
			got, derivation.SelectedAddressHex)
	}
	if got := address.String(); got != derivation.SelectedAddress {
		t.Fatalf("selected address = %s, want %s", got, derivation.SelectedAddress)
	}
	if isOnTheCurve(address[:]) {
		t.Fatalf("selected address decodes to an Edwards25519 point")
	}
}

func assertFixtureProgramShape(
	t *testing.T,
	program []byte,
	publicKey falcongo.PublicKey,
	derivation lsigDerivationFixture,
	counter byte,
) {
	t.Helper()

	if len(program) != derivation.ProgramLength {
		t.Fatalf("program length = %d, want %d", len(program), derivation.ProgramLength)
	}

	expectedPrefix, err := hex.DecodeString(derivation.ProgramPrefixHex)
	if err != nil {
		t.Fatalf("invalid program_prefix_hex fixture: %v", err)
	}
	prefixEnd := derivation.ProgramPublicKeyOffset
	if prefixEnd != len(expectedPrefix) {
		t.Fatalf("public key offset = %d, want prefix length %d",
			prefixEnd, len(expectedPrefix))
	}
	if derivation.ProgramCounterOffset >= prefixEnd {
		t.Fatalf("counter offset %d outside prefix length %d",
			derivation.ProgramCounterOffset, prefixEnd)
	}
	expectedPrefix[derivation.ProgramCounterOffset] = counter
	if got := program[derivation.ProgramCounterOffset]; got != counter {
		t.Fatalf("program counter = %d, want %d", got, counter)
	}
	prefix := hex.EncodeToString(program[:prefixEnd])
	expectedPrefixHex := hex.EncodeToString(expectedPrefix)
	if prefix != expectedPrefixHex {
		t.Fatalf("program prefix = %s, want %s", prefix, expectedPrefixHex)
	}

	publicKeyEnd := derivation.ProgramPublicKeyOffset + len(publicKey)
	if got := hex.EncodeToString(program[derivation.ProgramPublicKeyOffset:publicKeyEnd]); got !=
		derivation.FalconPublicKeyHex {
		t.Fatalf("program public key does not match fixture")
	}
	if got := hex.EncodeToString(program[publicKeyEnd:]); got != derivation.ProgramSuffixHex {
		t.Fatalf("program suffix = %s, want %s", got, derivation.ProgramSuffixHex)
	}
}
