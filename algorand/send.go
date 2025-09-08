package algorand

import (
	"context"
	_ "embed"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/algorandfoundation/falcon-signatures/falcongo"
)

type SendOptions struct {
	Network Network // default MainNet
	Fee     uint64  // in microAlgos
	Note    []byte  // default empty
	// UseFlatFee controls whether to override suggested fee with Fee as a flat fee.
	// If false, suggested params' fee behavior is used.
	UseFlatFee bool
}

// we need extra transactions to cover 3030 bytes of LogicSis since each txn has
// a 1000 bytes limit
const dummyTxnNeeded = 3

func Send(keyPair falcongo.KeyPair, to string, amount uint64, opt SendOptions,
) (txID string, err error) {

	lsig, err := DerivePQLogicSig(keyPair.PublicKey)
	if err != nil {
		return "", err
	}
	lsa, err := lsig.Address()
	if err != nil {
		return "", err
	}
	lsigAddress := lsa.String()

	algodClient, err := GetAlgodClient(opt.Network)
	if err != nil {
		return "", err
	}
	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return "", err
	}
	if opt.UseFlatFee {
		sp.FlatFee = true
		sp.Fee = types.MicroAlgos(opt.Fee)
	}

	var sendTxn types.Transaction
	sendTxn, err = transaction.MakePaymentTxn(
		lsigAddress, // from
		to,          // to
		amount,      // amount
		opt.Note,    // note
		"",          // closeRemainderTo
		sp,          // suggested params
	)
	if err != nil {
		return "", err
	}

	// add dummy transactions to cover the size of the SignLogicSigTransaction
	sendGroup, err := makeSendGroup(&sendTxn, opt.Network, dummyTxnNeeded)
	if err != nil {
		return "", err
	}

	txnToSign := sendGroup[0]
	signature, err := keyPair.SignBytes(crypto.TransactionID(txnToSign))
	if err != nil {
		return "", err
	}
	lsig.Lsig.Args = [][]byte{signature}

	txID, signedTxn, err := crypto.SignLogicSigTransaction(lsig.Lsig, txnToSign)
	if err != nil {
		return "", err
	}

	var sendBytes []byte
	sendBytes = append(sendBytes, signedTxn...)
	for i := 1; i < len(sendGroup); i++ {
		signedDummyTxn, err := signDummyTxn(sendGroup[i])
		if err != nil {
			return "", err
		}
		sendBytes = append(sendBytes, signedDummyTxn...)
	}

	_, err = algodClient.SendRawTransaction(sendBytes).Do(context.Background())
	if err != nil {
		return "", err
	}

	_, err = transaction.WaitForConfirmation(algodClient, txID, 9, context.Background())
	if err != nil {
		return "", err
	}

	return txID, nil
}

//go:embed teal/dummyLsig.teal.tok
var dummyLsigCompiled []byte

// signDummyTxn signs the given transaction with the dummy LogicSig
func signDummyTxn(txn types.Transaction) ([]byte, error) {
	lsig := types.LogicSig{Logic: dummyLsigCompiled, Args: nil}

	_, signedDummyTxn, err := crypto.SignLogicSigTransaction(lsig, txn)
	if err != nil {
		return nil, err
	}
	return signedDummyTxn, nil
}

// makeSendGroup inserts the given transaction in a group adding dummy transactions
// and returns the group with the given transaction as first element
// The given transaction will be modified to include the group ID and the extra fees
func makeSendGroup(txn *types.Transaction, network Network, dummyNeeded int,
) ([]types.Transaction, error) {

	algodClient, err := GetAlgodClient(network)
	if err != nil {
		return nil, err
	}

	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return nil, err
	}
	sp.FlatFee = true
	sp.Fee = 0

	// update fee to cover the extra transactions
	txn.Fee += types.MicroAlgos(uint64(dummyNeeded) * sp.MinFee)

	var txns []types.Transaction
	txns = append(txns, *txn)

	for i := range dummyNeeded {
		dummyLsig := crypto.LogicSigAccount{
			Lsig: types.LogicSig{Logic: dummyLsigCompiled, Args: nil},
		}
		dummyLsa, err := dummyLsig.Address()
		if err != nil {
			return nil, err
		}
		dummyAddress := dummyLsa.String()

		dummyTxn, err := transaction.MakePaymentTxn(
			dummyAddress,    // from
			dummyAddress,    // to
			0,               // amount
			[]byte{byte(i)}, // note
			"",              // closeRemainderTo
			sp,              // suggested params
		)
		if err != nil {
			return nil, err
		}

		txns = append(txns, dummyTxn)
	}

	gid, err := crypto.ComputeGroupID(txns)
	if err != nil {
		return nil, err
	}
	for i := range txns {
		txns[i].Group = gid
	}
	return txns, nil
}
