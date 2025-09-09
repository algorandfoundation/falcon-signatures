package falcongo

import (
	"crypto/rand"
	"fmt"

	"github.com/algorand/falcon"
)

type PublicKey = falcon.PublicKey
type PrivateKey = falcon.PrivateKey

// KeyPair groups a Falcon-1024 public/private key.
type KeyPair struct {
	PublicKey  PublicKey
	PrivateKey PrivateKey
}

// GenerateKeyPair generates a new Falcon keypair from a given seed.
// If the seed is empty, a random 48-byte seed is generated.
func GenerateKeyPair(seed []byte) (KeyPair, error) {
	if len(seed) == 0 {
		randomSeed := [48]byte{}
		_, err := rand.Read(randomSeed[:])
		if err != nil {
			panic(fmt.Sprintf("crypto/rand should never fail: %s", err))
		}
		seed = randomSeed[:]
	}
	pk, sk, err := falcon.GenerateKey(seed[:])
	return KeyPair{PublicKey: pk, PrivateKey: sk}, err
}

// Sign signs the provided bytes using the private key and returns a compressed signature.
func (d *KeyPair) Sign(data []byte) (falcon.CompressedSignature, error) {
	signedData, err := (*falcon.PrivateKey)(&d.PrivateKey).SignCompressed(data)
	return falcon.CompressedSignature(signedData), err
}

// Verify verifies the signature of the provided data using the public key.
func Verify(data []byte, sig falcon.CompressedSignature, pk falcon.PublicKey) error {
	return pk.Verify(sig, data)
}

// GetFixedLengthSignature converts a compressed signature to its fixed-length form.
func GetFixedLengthSignature(sig falcon.CompressedSignature) ([]byte, error) {
	ctSignature, err := sig.ConvertToCT()
	return ctSignature[:], err
}
