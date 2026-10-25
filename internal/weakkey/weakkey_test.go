package weakkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

// A public key built from a tiny scalar must be detected, and the scalar
// recovered, exactly as in the eMudhra compromise.
func TestCheckDetectsSmallScalar(t *testing.T) {
	curve := elliptic.P256()
	d := big.NewInt(42)
	x, y := curve.ScalarBaseMult(d.Bytes())
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	res := Check(pub, 1000)
	if !res.Weak {
		t.Fatal("expected weak key to be detected")
	}
	if res.Scalar == nil || res.Scalar.Int64() != 42 {
		t.Fatalf("expected recovered scalar 42, got %v", res.Scalar)
	}
}

// A properly generated key must not be flagged.
func TestCheckStrongKey(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if res := Check(&k.PublicKey, 1000); res.Weak {
		t.Fatalf("false positive on a strong key (scalar %v)", res.Scalar)
	}
}

// Non-EC inputs are simply not testable.
func TestCheckNonEC(t *testing.T) {
	if res := Check("not a key", 1000); res.Weak {
		t.Fatal("non-EC input should never be reported weak")
	}
}
