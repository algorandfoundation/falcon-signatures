package algorand

import (
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

type Network int

const (
	MainNet Network = iota
	TestNet
	BetaNet
	DevNet
)

// GetAddressFromPublicKey derives the Algorand address corresponding to the given
// Falcon public key.
func GetAddressFromPublicKey(publicKey falcongo.PublicKey) ([]byte, error) {
	lsig, err := DerivePQLogicSig(publicKey)
	if err != nil {
		return nil, err
	}
	lsa, err := lsig.Address()
	if err != nil {
		return nil, err
	}
	address := lsa.String()
	return []byte(address), nil
}

// isOnTheCurve returns true if the 32-byte value decodes to a valid edwards25519
// curve point (i.e., could be an ed25519 public key), and false otherwise.
func isOnTheCurve(address []byte) bool {
	_, err := new(edwards25519.Point).SetBytes(address)
	return err == nil
}

var ErrInvalidFalconPublicKey = errors.New(
	"unsuitable Falcon public key for Algorand address")

// DerivePQLogicSig returns a LogicSig that verifies a Falcon signature.
// The LogicSig embeds the Falcon public key and verifies the matching private key
// was used to sign the transaction ID.
// This is a deterministic derivation according to the specification in doc.go
func DerivePQLogicSig(publicKey falcongo.PublicKey) (crypto.LogicSigAccount, error) {
	maxIterations := 256
	for counter := range maxIterations {
		lsig := crypto.LogicSigAccount{
			Lsig: types.LogicSig{
				Logic: patchPrecompiledPQlogicsig(publicKey, byte(counter)),
			},
		}
		lsa, err := lsig.Address()
		if err != nil {
			return crypto.LogicSigAccount{}, err
		}
		if !isOnTheCurve(lsa[:]) {
			return lsig, nil
		}
	}
	return crypto.LogicSigAccount{}, ErrInvalidFalconPublicKey
}

//go:embed teal/PQlogicsig.teal.tok
var PQlogicsigPrecompile []byte

// patchPrecompiledPQlogicsig returns the compiled PQlogicsig TEAL code
// with the given Falcon public key and counter value
//
// The precompiled PQlogicsig with counter=0 and public key all zeroes is
// pointed to by PQlogicsigPrecompile which can be used for testing, and is:
//
//	offset	|	bytes			| teal
//	_______________________________________________________________________
//	      0	|	0c				| #pragma version 12
//	      1	|	26 01 01 00		| bytecblock 0x00
//	      5	|	31 17			| txn TxID
//	      7	|	2d				| arg 0
//	      8	|	80 81 0e 00... 	| pushbytes 0x00... (1793 public key bytes)
//	   1804	|	85				| falcon_verify
func patchPrecompiledPQlogicsig(publicKey falcongo.PublicKey, counter byte) []byte {
	precompiled := []byte{
		0x0c,
		0x26, 0x01, 0x01, 0x00,
		0x31, 0x17,
		0x2d,
		0x80, 0x81, 0x0e,
	}
	precompiled[4] = counter
	precompiled = append(precompiled, publicKey[:]...)
	precompiled = append(precompiled, 0x85)
	return precompiled
}

//go:embed teal/PQlogicsigTMPL.teal
var PQlogicsigTMPL string

// DerivePQLogicSigWithCompilation is like DerivePQLogicSig but compiles the TEAL
// source code on the fly instead of using a precompiled version.
// It requires an algod node to compile the TEAL code,
func DerivePQLogicSigWithCompilation(publicKey falcongo.PublicKey) (crypto.LogicSigAccount, error) {
	pubKeyHex := "0x" + hex.EncodeToString(publicKey[:])
	maxIterations := 256
	teal := strings.Replace(PQlogicsigTMPL, "TMPL_FALCON_PUBLIC_KEY", pubKeyHex, 1)
	teal = strings.Replace(teal, "TMPL_COUNTER", "0x00", 1)
	for counter := range maxIterations {
		lsig, err := CompileLogicSig(teal)
		if err != nil {
			return crypto.LogicSigAccount{}, err
		}
		lsa, err := lsig.Address()
		if err != nil {
			return crypto.LogicSigAccount{}, err
		}
		if !isOnTheCurve(lsa[:]) {
			return lsig, nil // found a counter that works
		}
		oldCounterLine := fmt.Sprintf("0x%02x // counter", counter)
		newCounterLine := fmt.Sprintf("0x%02x // counter", counter+1)
		teal = strings.ReplaceAll(teal, oldCounterLine, newCounterLine)
	}
	return crypto.LogicSigAccount{}, ErrInvalidFalconPublicKey
}
