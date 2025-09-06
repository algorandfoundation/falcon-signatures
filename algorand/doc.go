// Package algorand implements Algorand accounts controlled by a Falcon private key.
//
// These accounts are controlled by a logicsig deterministically derived from a Falcon public key.
// The logicsig only approves transactions "signed" by the corresponding Falcon private key.
// This is accomplished by passing a Falcon signature of the transaction ID as an argument to the logicsig.
//
// An important property of these accounts is that they have an Algorand address that does not correspond to a point
// on the elliptic curve used by Algorand (Ed25519). This means that for these accounts it is impossible to find a
// private key that can sign transactions for them. The only way to authorize transactions for these accounts is by using
// the logicsig with a valid Falcon signature. So even a quantum computer cannot forge signatures for these accounts.
//
// The deterministic derivation of the logicsig from the Falcon public key is defined in the `DerivePQLogicSig` function
// which takes as input a Falcon public key and outputs the following TEAL code:

// 		#pragma version 12
// 		txn TxID
// 		arg 0
// 		byte 0x<$FALCON_PUBLIC_KEY>
// 		falcon_verify
// 		int <$COUNTER>
// 		pop

// where <$FALCON_PUBLIC_KEY> is the hex encoding of the supplied Falcon public key, and <$COUNTER> is an integer
// that starts at 0 and is incremented by one until the resulting logicsig address is not a valid ed25519 public key.
package algorand
