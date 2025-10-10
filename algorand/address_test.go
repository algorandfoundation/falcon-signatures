package algorand

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
)

// TestIsOnTheCurve_AlgorandAccounts generates random Algorand accounts and
// verifies their 32-byte public keys decode to valid Edwards25519 points.
func TestIsOnTheCurve_AlgorandAccounts(t *testing.T) {
	for i := range 100 {
		acct := crypto.GenerateAccount()
		pub := acct.Address
		if !isOnTheCurve(pub[:]) {
			t.Fatalf("generated account %d has address not on curve: %v", i, pub)
		}
	}
}
