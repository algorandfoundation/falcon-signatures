package algorand

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"filippo.io/edwards25519"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
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

// ❤️ nodely.dev
const (
	NodelyMainNetAlgodURL = "https://mainnet-api.4160.nodely.dev"
	NodelyTestNetAlgodURL = "https://testnet-api.4160.nodely.dev"
	NodelyBetaNetAlgodURL = "https://betanet-api.4160.nodely.dev"
)

// DeriveLogicSig outputs TEAL code for a LogicSig that verifies a Falcon signature.
// The LogicSig embeds the Falcon public key and verifies the matching private key
// was used to sign the transaction ID.
//
// The dummy counter inserted in the TEAL code is used to guarantee that the LogicSig
// escrow account address, which Algorand derives hashing the TEAL program, is not a
// valid ed25519 public key.
// So even a quantum computer that breaks ed25519 signatures would not be able to
// derive a private key for the LogicSig escrow account.
// On average it will take two attempts to find such a counter value.
func DerivePQLogicSig(publicKey falcongo.PublicKey) (crypto.LogicSigAccount, error) {
	pubKeyHex := hex.EncodeToString(publicKey[:])
	for counter := uint64(0); ; counter++ {
		teal := "#pragma version 12" +
			"\n" + "txn TxID" +
			"\n" + "arg 0" +
			"\n" + "byte 0x" + pubKeyHex +
			"\n" + "falcon_verify" +
			"\n" + "int " + strconv.FormatUint(counter, 10) +
			"\n" + "pop"

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
	}
}

// CompileLogicSig returns a LogicSigAccount compiled from the given TEAL code
// We use BetaNet to get access to the latest TEAL opcodes (i.e., falcon_verify).
func CompileLogicSig(teal string) (crypto.LogicSigAccount, error) {
	algodClient, err := GetAlgodClient(BetaNet)
	if err != nil {
		return crypto.LogicSigAccount{}, err
	}
	result, err := algodClient.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		return crypto.LogicSigAccount{}, err
	}

	lsigBinary, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return crypto.LogicSigAccount{}, err
	}
	lsig := crypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: lsigBinary, Args: nil},
	}
	return lsig, nil
}

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

// GetAlgodClient returns an algod client for the specified network.
// If the ALGOD_URL environment variable is set, it uses that URL and
// the ALGOD_TOKEN environment variable for the token (which may be empty).
// Otherwise, it uses the nodely.dev endpoints for MainNet, TestNet, and BetaNet.
// For DevNet, the ALGOD_URL environment variable must be set.
func GetAlgodClient(network Network) (*algod.Client, error) {
	u := os.Getenv("ALGOD_URL")
	if u != "" {
		// Token may be empty depending on the endpoint setup.
		return algod.MakeClient(u, os.Getenv("ALGOD_TOKEN"))
	}
	var algodURL string
	switch network {
	case MainNet:
		algodURL = NodelyMainNetAlgodURL
	case TestNet:
		algodURL = NodelyTestNetAlgodURL
	case BetaNet:
		algodURL = NodelyBetaNetAlgodURL
	case DevNet:
		return nil, fmt.Errorf("ALGOD_URL not set for DevNet")
	}
	return algod.MakeClient(algodURL, "")
}
