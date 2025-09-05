package falcongo

import (
	"crypto/rand"
	"crypto/sha512"
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

// Hash computes the SHA-512/256 hash of the input bytes.
func Hash(data []byte) [32]byte {
	return sha512.Sum512_256(data)
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

// Sign hashes the message with SHA-512/256 and signs the digest.
func (d *KeyPair) Sign(message []byte) (falcon.CompressedSignature, error) {
	hs := Hash(message)
	return d.SignBytes(hs[:])
}

// SignBytes signs the provided bytes directly.
func (d *KeyPair) SignBytes(data []byte) (falcon.CompressedSignature, error) {
	signedData, err := (*falcon.PrivateKey)(&d.PrivateKey).SignCompressed(data)
	return falcon.CompressedSignature(signedData), err
}

// Verify verifies a signature over message using the provided public key.
func Verify(message []byte, sig falcon.CompressedSignature, pk falcon.PublicKey) error {
	hs := Hash(message)
	return VerifyBytes(hs[:], sig, pk)
}

// VerifyBytes verifies a signature over raw bytes using the provided public key.
func VerifyBytes(data []byte, sig falcon.CompressedSignature, pk falcon.PublicKey) error {
	return pk.Verify(sig, data)
}

// GetFixedLengthSignature converts a compressed signature to its fixed-length form.
func GetFixedLengthSignature(sig falcon.CompressedSignature) ([]byte, error) {
	ctSignature, err := sig.ConvertToCT()
	return ctSignature[:], err
}
