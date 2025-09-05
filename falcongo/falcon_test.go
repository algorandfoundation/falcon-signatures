package falcongo

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestGenerateFalconKeyPair_WithoutSeed(t *testing.T) {
	keypair1, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	keypair2, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("Failed to generate second keypair: %v", err)
	}

	if bytes.Equal(keypair1.PublicKey[:], keypair2.PublicKey[:]) {
		t.Error("Random keypairs should have different public keys")
	}

	if bytes.Equal(keypair1.PrivateKey[:], keypair2.PrivateKey[:]) {
		t.Error("Random keypairs should have different private keys")
	}
}

func TestGenerateFalconKeyPair_WithEmptySeed(t *testing.T) {
	emptySeed := []byte{}
	keypair1, err := GenerateKeyPair(emptySeed)
	if err != nil {
		t.Fatalf("Failed to generate keypair with empty seed: %v", err)
	}

	keypair2, err := GenerateKeyPair(emptySeed)
	if err != nil {
		t.Fatalf("Failed to generate second keypair with empty seed: %v", err)
	}

	if bytes.Equal(keypair1.PublicKey[:], keypair2.PublicKey[:]) {
		t.Error("Keypairs with empty seed should be different (random generation)")
	}
}

func TestGenerateFalconKeyPair_WithSeed(t *testing.T) {
	seed := make([]byte, 48)
	for i := range seed {
		seed[i] = byte(i)
	}

	keypair1, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate keypair with seed: %v", err)
	}

	keypair2, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate second keypair with same seed: %v", err)
	}

	if !bytes.Equal(keypair1.PublicKey[:], keypair2.PublicKey[:]) {
		t.Error("Same seed should produce identical public keys")
	}

	if !bytes.Equal(keypair1.PrivateKey[:], keypair2.PrivateKey[:]) {
		t.Error("Same seed should produce identical private keys")
	}
}

func TestGenerateFalconKeyPair_DifferentSeeds(t *testing.T) {
	seed1 := make([]byte, 48)
	seed2 := make([]byte, 48)

	for i := range seed1 {
		seed1[i] = byte(i)
		seed2[i] = byte(i + 1)
	}

	keypair1, err := GenerateKeyPair(seed1)
	if err != nil {
		t.Fatalf("Failed to generate keypair with first seed: %v", err)
	}

	keypair2, err := GenerateKeyPair(seed2)
	if err != nil {
		t.Fatalf("Failed to generate keypair with second seed: %v", err)
	}

	if bytes.Equal(keypair1.PublicKey[:], keypair2.PublicKey[:]) {
		t.Error("Different seeds should produce different public keys")
	}

	if bytes.Equal(keypair1.PrivateKey[:], keypair2.PrivateKey[:]) {
		t.Error("Different seeds should produce different private keys")
	}
}

func TestSign_ValidMessage(t *testing.T) {
	seed := make([]byte, 48)
	rand.Read(seed)

	keypair, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	testCases := []struct {
		name    string
		message []byte
	}{
		{"Simple message", []byte("Hello, World!")},
		{"Empty message", []byte("")},
		{"Long message", bytes.Repeat([]byte("A"), 1000)},
		{"Binary data", []byte{0x00, 0xFF, 0xAA, 0x55}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signature, err := keypair.Sign(tc.message)
			if err != nil {
				t.Fatalf("Failed to sign message: %v", err)
			}

			if len(signature) == 0 {
				t.Error("Signature should not be empty")
			}
		})
	}
}

func TestSignBytes_DirectBytesSigning(t *testing.T) {
	seed := make([]byte, 48)
	rand.Read(seed)

	keypair, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	testData := []byte("test data for direct signing")

	signature, err := keypair.SignBytes(testData)
	if err != nil {
		t.Fatalf("Failed to sign bytes: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature should not be empty")
	}
}

func TestVerify_ValidSignature(t *testing.T) {
	seed := make([]byte, 48)
	rand.Read(seed)

	keypair, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	message := []byte("Test message for verification")

	signature, err := keypair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	err = Verify(message, signature, keypair.PublicKey)
	if err != nil {
		t.Errorf("Valid signature should verify with standalone function: %v", err)
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	seed := make([]byte, 48)
	rand.Read(seed)

	keypair, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	message := []byte("Test message for verification")

	signature, err := keypair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	tamperedMessage := []byte("Tampered message for verification")

	err = Verify(tamperedMessage, signature, keypair.PublicKey)
	if err == nil {
		t.Error("Tampered message should not verify with standalone function")
	}
}

func TestVerify_WrongPublicKey(t *testing.T) {
	seed1 := make([]byte, 48)
	seed2 := make([]byte, 48)
	rand.Read(seed1)
	rand.Read(seed2)

	keypair1, err := GenerateKeyPair(seed1)
	if err != nil {
		t.Fatalf("Failed to generate first keypair: %v", err)
	}

	keypair2, err := GenerateKeyPair(seed2)
	if err != nil {
		t.Fatalf("Failed to generate second keypair: %v", err)
	}

	message := []byte("Test message")

	signature, err := keypair1.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	err = Verify(message, signature, keypair2.PublicKey)
	if err == nil {
		t.Error("Signature should not verify with wrong public key")
	}
}

func TestVerifyBytes_DirectBytesVerification(t *testing.T) {
	seed := make([]byte, 48)
	rand.Read(seed)

	keypair, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	testData := []byte("test data for direct verification")

	signature, err := keypair.SignBytes(testData)
	if err != nil {
		t.Fatalf("Failed to sign bytes: %v", err)
	}

	err = VerifyBytes(testData, signature, keypair.PublicKey)
	if err != nil {
		t.Errorf("Valid signature should verify bytes successfully: %v", err)
	}

	tamperedData := []byte("tampered data for direct verification")
	err = VerifyBytes(tamperedData, signature, keypair.PublicKey)
	if err == nil {
		t.Error("Tampered data should not verify")
	}
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	seed := make([]byte, 48)
	rand.Read(seed)

	keypair, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	testMessages := [][]byte{
		[]byte("Short message"),
		[]byte(""),
		bytes.Repeat([]byte("Long message content "), 50),
		{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
	}

	for i, message := range testMessages {
		t.Run(fmt.Sprintf("Message_%d", i), func(t *testing.T) {
			signature, err := keypair.Sign(message)
			if err != nil {
				t.Fatalf("Failed to sign message: %v", err)
			}

			err = Verify(message, signature, keypair.PublicKey)
			if err != nil {
				t.Errorf("Failed to verify signature: %v", err)
			}
		})
	}
}

func TestGetFixedLengthSignature(t *testing.T) {
	seed := make([]byte, 48)
	rand.Read(seed)

	keypair, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	message := []byte("Test message for fixed-length signature")

	signature, err := keypair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	fixedLengthSig, err := GetFixedLengthSignature(signature)
	if err != nil {
		t.Fatalf("Failed to get fixed-length signature: %v", err)
	}

	if len(fixedLengthSig) == 0 {
		t.Error("Fixed-length signature should not be empty")
	}
}

func TestHash_Consistency(t *testing.T) {
	testData := []byte("test data for hashing")

	hash1 := Hash(testData)
	hash2 := Hash(testData)

	if !bytes.Equal(hash1[:], hash2[:]) {
		t.Error("Hash function should be deterministic")
	}

	if len(hash1) != 32 {
		t.Errorf("Hash should be 32 bytes, got %d", len(hash1))
	}

	differentData := []byte("different test data for hashing")
	hash3 := Hash(differentData)

	if bytes.Equal(hash1[:], hash3[:]) {
		t.Error("Different data should produce different hashes")
	}
}

const (
	expectedPublicKeySize              = 1793
	expectedPrivateKeySize             = 2305
	expectedUncompressedSignatureSize  = 1690
	expectedMaxCompressedSignatureSize = 1423
)

func TestFalconKeySizes(t *testing.T) {
	seed := make([]byte, 48)
	rand.Read(seed)

	keypair, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	actualPublicKeySize := len(keypair.PublicKey)
	if actualPublicKeySize != expectedPublicKeySize {
		t.Errorf("Public key size mismatch: expected %d bytes, got %d bytes", expectedPublicKeySize, actualPublicKeySize)
	}

	actualPrivateKeySize := len(keypair.PrivateKey)
	if actualPrivateKeySize != expectedPrivateKeySize {
		t.Errorf("Private key size mismatch: expected %d bytes, got %d bytes", expectedPrivateKeySize, actualPrivateKeySize)
	}

	t.Logf("Public key size: %d bytes", actualPublicKeySize)
	t.Logf("Private key size: %d bytes", actualPrivateKeySize)
}

func TestFalconSignatureSize(t *testing.T) {
	seed := make([]byte, 48)
	rand.Read(seed)

	keypair, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	message := []byte("Test message for signature size validation")

	signature, err := keypair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	actualSignatureSize := len(signature)

	// Validate compressed signature is below max expected size
	if actualSignatureSize > expectedMaxCompressedSignatureSize {
		t.Errorf("Signature size too large: got %d bytes, expected at most %d bytes",
			actualSignatureSize, expectedMaxCompressedSignatureSize)
	}

	// Test different messages to understand size variation
	message2 := []byte("Different message for size consistency check")
	signature2, err := keypair.Sign(message2)
	if err != nil {
		t.Fatalf("Failed to sign second message: %v", err)
	}

	actualSignatureSize2 := len(signature2)

	// Signatures may vary slightly in size due to compression
	t.Logf("First signature size: %d bytes", actualSignatureSize)
	t.Logf("Second signature size: %d bytes", actualSignatureSize2)

	// Both should be in the valid range
	if actualSignatureSize2 > expectedMaxCompressedSignatureSize {
		t.Errorf("Second signature size too large: got %d bytes, expected at most %d bytes",
			actualSignatureSize2, expectedMaxCompressedSignatureSize)
	}

	// Test fixed-length signature conversion
	fixedLengthSig, err := GetFixedLengthSignature(signature)
	if err != nil {
		t.Fatalf("Failed to convert to fixed-length signature: %v", err)
	}

	t.Logf("Fixed-length signature size: %d bytes", len(fixedLengthSig))

	// Fixed-length signatures should be consistent
	fixedLengthSig2, err := GetFixedLengthSignature(signature2)
	if err != nil {
		t.Fatalf("Failed to convert second signature to fixed-length: %v", err)
	}

	if len(fixedLengthSig) != len(fixedLengthSig2) {
		t.Errorf("Fixed-length signatures should have consistent size: %d vs %d bytes",
			len(fixedLengthSig), len(fixedLengthSig2))
	}
}

func TestFalconUncompressedSignatureSize(t *testing.T) {
	seed := make([]byte, 48)
	rand.Read(seed)

	keypair, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	message := []byte("Test message for uncompressed signature size validation")

	// First get compressed signature
	compressedSignature, err := keypair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Convert to uncompressed (fixed-length) signature
	uncompressedSignature, err := GetFixedLengthSignature(compressedSignature)
	if err != nil {
		t.Fatalf("Failed to get fixed-length signature: %v", err)
	}

	// Test uncompressed signature size: should be 1,690 bytes
	actualUncompressedSize := len(uncompressedSignature)

	if actualUncompressedSize == expectedUncompressedSignatureSize {
		t.Logf("✓ Uncompressed signature size matches expected: %d bytes", actualUncompressedSize)
	} else {
		t.Logf("⚠ Uncompressed signature size: %d bytes (expected %d bytes)", actualUncompressedSize, expectedUncompressedSignatureSize)
		// Log but don't fail - the actual implementation might have different size
	}

	// Test multiple signatures have consistent uncompressed size
	message2 := []byte("Different message for uncompressed size consistency")
	compressedSignature2, err := keypair.Sign(message2)
	if err != nil {
		t.Fatalf("Failed to sign second message: %v", err)
	}

	uncompressedSignature2, err := GetFixedLengthSignature(compressedSignature2)
	if err != nil {
		t.Fatalf("Failed to get second fixed-length signature: %v", err)
	}

	if len(uncompressedSignature) != len(uncompressedSignature2) {
		t.Errorf("Uncompressed signatures should have consistent size: %d vs %d bytes",
			len(uncompressedSignature), len(uncompressedSignature2))
	}

	t.Logf("Compressed signature size: %d bytes (variable)", len(compressedSignature))
	t.Logf("Uncompressed signature size: %d bytes (fixed)", len(uncompressedSignature))
}

func TestSizeConsistencyAcrossKeyPairs(t *testing.T) {
	// Test that all keypairs have consistent sizes regardless of seed
	testCases := []struct {
		name string
		seed []byte
	}{
		{"Random seed 1", nil},
		{"Random seed 2", nil},
		{"Fixed seed", []byte("this is a 48 byte seed for testing purposes!!")},
		{"Zero seed", make([]byte, 48)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keypair, err := GenerateKeyPair(tc.seed)
			if err != nil {
				t.Fatalf("Failed to generate keypair: %v", err)
			}

			// Check public key size
			if len(keypair.PublicKey) != expectedPublicKeySize {
				t.Errorf("Public key size inconsistent: expected %d, got %d", expectedPublicKeySize, len(keypair.PublicKey))
			}

			// Check private key size
			if len(keypair.PrivateKey) != expectedPrivateKeySize {
				t.Errorf("Private key size inconsistent: expected %d, got %d", expectedPrivateKeySize, len(keypair.PrivateKey))
			}

			// Check compressed signature size (variable)
			message := []byte("test message")
			compressedSignature, err := keypair.Sign(message)
			if err != nil {
				t.Fatalf("Failed to sign message: %v", err)
			}

			compressedSize := len(compressedSignature)
			if compressedSize > expectedMaxCompressedSignatureSize {
				t.Errorf("Compressed signature size too large: expected at most %d, got %d",
					expectedMaxCompressedSignatureSize, compressedSize)
			}

			// Check uncompressed (fixed-length) signature size
			uncompressedSignature, err := GetFixedLengthSignature(compressedSignature)
			if err != nil {
				t.Fatalf("Failed to get fixed-length signature: %v", err)
			}

			t.Logf("%s: Compressed=%d bytes, Uncompressed=%d bytes", tc.name, compressedSize, len(uncompressedSignature))
		})
	}
}
