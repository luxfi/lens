// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/lens/primitives"
)

// TestPedersenCommitVerifyHonest — honest (share, blind) verifies.
func TestPedersenCommitVerifyHonest(t *testing.T) {
	for _, c := range curves() {
		t.Run(c.Name(), func(t *testing.T) {
			secret, _ := c.SampleScalar(rand.Reader)
			f, _ := primitives.NewPolynomial(c, 2, secret, rand.Reader)
			rb, _ := primitives.NewPolynomial(c, 2, nil, rand.Reader)

			commits, err := CommitToPoly(c, f.Coefficients(), rb.Coefficients())
			if err != nil {
				t.Fatalf("CommitToPoly: %v", err)
			}
			x := c.NewScalar().SetUint64(7)
			share := f.Evaluate(x)
			blind := rb.Evaluate(x)
			if err := VerifyShareAgainstCommits(c, share, blind, commits, x); err != nil {
				t.Fatalf("honest verify failed: %v", err)
			}
		})
	}
}

// TestPedersenCommitVerifyTampered — wrong share rejected.
func TestPedersenCommitVerifyTampered(t *testing.T) {
	c := primitives.NewSecp256k1()
	secret, _ := c.SampleScalar(rand.Reader)
	f, _ := primitives.NewPolynomial(c, 2, secret, rand.Reader)
	rb, _ := primitives.NewPolynomial(c, 2, nil, rand.Reader)
	commits, _ := CommitToPoly(c, f.Coefficients(), rb.Coefficients())

	x := c.NewScalar().SetUint64(3)
	share := f.Evaluate(x)
	blind := rb.Evaluate(x)
	tampered := c.NewScalar().Set(share).Add(c.NewScalar().SetUint64(1))
	if err := VerifyShareAgainstCommits(c, tampered, blind, commits, x); err == nil {
		t.Fatal("tampered share accepted")
	}
}

// TestCommitDigestStable — digest is deterministic across calls.
func TestCommitDigestStable(t *testing.T) {
	c := primitives.NewEd25519()
	secret, _ := c.SampleScalar(rand.Reader)
	f, _ := primitives.NewPolynomial(c, 3, secret, rand.Reader)
	rb, _ := primitives.NewPolynomial(c, 3, nil, rand.Reader)
	commits, _ := CommitToPoly(c, f.Coefficients(), rb.Coefficients())
	d1 := CommitDigest(commits, nil)
	d2 := CommitDigest(commits, nil)
	if d1 != d2 {
		t.Fatal("CommitDigest not deterministic")
	}
}
