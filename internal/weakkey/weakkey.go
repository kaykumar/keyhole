// Package weakkey detects catastrophically weak elliptic-curve keys whose
// public point is a small multiple of the curve base point.
//
// This is the class of failure behind the eMudhra CA key compromise of
// October 2026, where intermediate CA private keys were small integers
// (values like 4, 56, and 115) that could be recovered directly from the
// public certificate. If the public key Q equals d*G for some small scalar
// d, then d IS the private key, and anyone can recompute it.
//
// The detector brute-forces d over a small range and checks whether d*G
// reproduces the certificate's public point. A match is decisive: the key is
// weak and the private scalar is recovered. This catches the whole class of
// low-entropy keys, not just a list of known-bad fingerprints.
package weakkey

import (
	"crypto/ecdsa"
	"math/big"
)

// DefaultBound is how many small scalars to test when the caller passes 0.
// The affected eMudhra keys had an estimated 3-8 bits of entropy, so 2^16
// gives comfortable headroom while staying fast (well under a second per key
// on commodity hardware). Raise it with --max-scalar for a wider search.
const DefaultBound = 1 << 16

// Result describes the outcome of a weak-key check.
type Result struct {
	// Weak is true when the public key was found to be a small multiple of G.
	Weak bool
	// Scalar is the recovered private scalar d (only set when Weak is true).
	Scalar *big.Int
	// Curve is the name of the elliptic curve, when the key was testable.
	Curve string
}

// Check reports whether pub is a small-scalar elliptic-curve key. Only
// *ecdsa.PublicKey values are testable; any other key type returns a
// zero Result with Weak=false. When bound is 0, DefaultBound is used.
func Check(pub any, bound uint64) Result {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve == nil || ec.X == nil || ec.Y == nil {
		return Result{}
	}
	if bound == 0 {
		bound = DefaultBound
	}
	curve := ec.Curve
	k := new(big.Int)
	for d := uint64(1); d <= bound; d++ {
		k.SetUint64(d)
		// ScalarBaseMult computes d*G for the curve's base point G.
		x, y := curve.ScalarBaseMult(k.Bytes())
		if x.Cmp(ec.X) == 0 && y.Cmp(ec.Y) == 0 {
			return Result{Weak: true, Scalar: new(big.Int).SetUint64(d), Curve: curve.Params().Name}
		}
	}
	return Result{Curve: curve.Params().Name}
}
