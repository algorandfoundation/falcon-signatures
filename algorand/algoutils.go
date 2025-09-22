package algorand

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// ❤️ nodely.dev
const (
	NodelyMainNetAlgodURL = "https://mainnet-api.4160.nodely.dev"
	NodelyTestNetAlgodURL = "https://testnet-api.4160.nodely.dev"
	NodelyBetaNetAlgodURL = "https://betanet-api.4160.nodely.dev"
)

// CompileLogicSig returns a LogicSigAccount compiled from the given TEAL code
func CompileLogicSig(teal string) (crypto.LogicSigAccount, error) {
	// We use BetaNet to get access to the latest TEAL opcodes (i.e., falcon_verify).
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
