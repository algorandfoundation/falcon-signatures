// Package algorand defines Algorand accounts controlled by FALCON keys.
//
// These accounts are governed by a logicsig deterministically derived from a FALCON public key.
// The logicsig authorizes a transaction only if it is accompanied by a FALCON signature of the
// transaction ID.
//
// Unlike standard accounts, these addresses do not correspond to Ed25519 public keys. Therefore,
// no private key exists that can sign transactions for them; only the logicsig + FALCON signature
// can authorize transactions. This property holds even against quantum adversaries.
//
// The derivation is implemented in `DerivePQLogicSig`, which produces the following TEAL:
//
//	#pragma version 12
//	bytecblock <COUNTER>
//	txn TxID
//	arg 0
//	pushbytes <FALCON_PUBLIC_KEY>
//	falcon_verify
//
// Here, FALCON_PUBLIC_KEY is the input FALCON public key, and COUNTER is a single-byte counter
// incremented until the resulting logicsig address is not a valid Ed25519 key. On average, two
// iterations suffice. In the vanishingly unlikely event that all 256 counters yield valid Ed25519
// keys, the FALCON public key is deemed unsuitable to derive an Algorand account.
package algorand
