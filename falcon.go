package cli

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"github.com/algorand/falcon"
)

type FalconKeyPair struct {
	PublicKey  falcon.PublicKey
	PrivateKey falcon.PrivateKey
}

// Hash computes the SHASum512_256 hash of an array of bytes
func Hash(data []byte) [32]byte {
	return sha512.Sum512_256(data)
}

// GenerateFalconKeyPair generates a new FalconKeyPair from a given seed.
// If the seed has zero length, we generate a random seed
func GenerateFalconKeyPair(seed []byte) (FalconKeyPair, error) {
	if len(seed) == 0 {
		randomSeed := [48]byte{}
		_, err := rand.Read(randomSeed[:])
		if err != nil {
			panic(fmt.Sprintf("crypto/rand should never fail: %s", err))
		}
		seed = randomSeed[:]
	}
	pk, sk, err := falcon.GenerateKey(seed[:])
	return FalconKeyPair{
		PublicKey:  pk,
		PrivateKey: sk,
	}, err
}

// Sign receives a message and generates a signature over that message.
func (d *FalconKeyPair) Sign(message []byte) (falcon.CompressedSignature, error) {
	hs := Hash(message)
	return d.SignBytes(hs[:])
}

// SignBytes receives bytes and signs over them.
func (d *FalconKeyPair) SignBytes(data []byte) (falcon.CompressedSignature, error) {
	signedData, err := (*falcon.PrivateKey)(&d.PrivateKey).SignCompressed(data)
	return falcon.CompressedSignature(signedData), err
}

// Verify follows Falcon algorithm to verify a signature.
func Verify(message []byte, sig falcon.CompressedSignature, pk falcon.PublicKey) error {
	hs := Hash(message)
	return VerifyBytes(hs[:], sig, pk)
}

// VerifyBytes follows falcon algorithm to verify a signature.
func VerifyBytes(data []byte, sig falcon.CompressedSignature, pk falcon.PublicKey) error {
	return pk.Verify(sig, data)
}

// Verify verifies a signature over a message using the public key in the FalconKeyPair.
func (d *FalconKeyPair) Verify(message []byte, sig falcon.CompressedSignature) error {
	return Verify(message, sig, d.PublicKey)
}

// GetFixedLengthSignature returns a the fixed-length signature from a compressed signature
func GetFixedLengthSignature(sig falcon.CompressedSignature) ([]byte, error) {
	ctSignature, err := sig.ConvertToCT()
	return ctSignature[:], err
}
