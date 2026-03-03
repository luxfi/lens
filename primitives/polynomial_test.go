// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"crypto/rand"
	"testing"
)

// TestPolynomialEvaluate sanity-checks Horner evaluation against a
// hand-rolled monomial sum.
func TestPolynomialEvaluate(t *testing.T) {
	for _, tc := range curveCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.curve
			secret, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("SampleScalar: %v", err)
			}
			p, err := NewPolynomial(c, 3, secret, rand.Reader)
			if err != nil {
				t.Fatalf("NewPolynomial: %v", err)
			}
			x := c.NewScalar().SetUint64(7)

			// Horner via Evaluate.
			got := p.Evaluate(x)

			// Hand-rolled monomial sum: a_0 + a_1·7 + a_2·49 + a_3·343.
			coeffs := p.Coefficients()
			want := c.NewScalar().Set(coeffs[0])
			pow := c.NewScalar().SetUint64(1)
			for i := 1; i <= p.Degree(); i++ {
				pow.Mul(x)
				term := c.NewScalar().Set(coeffs[i]).Mul(pow)
				want.Add(term)
			}
			if !got.Equal(want) {
				t.Fatal("polynomial evaluation disagrees with monomial sum")
			}
		})
	}
}

// TestLagrangeReconstructsConstant verifies that Lagrange interpolation
// at zero recovers the polynomial's constant term.
func TestLagrangeReconstructsConstant(t *testing.T) {
	for _, tc := range curveCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.curve
			secret, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("SampleScalar: %v", err)
			}
			const tThr, n = 3, 5
			poly, shares, err := Shamir(c, secret, tThr, n, rand.Reader)
			if err != nil {
				t.Fatalf("Shamir: %v", err)
			}
			_ = poly

			recovered, err := LagrangeRecover(c, shares, tThr)
			if err != nil {
				t.Fatalf("LagrangeRecover: %v", err)
			}
			if !recovered.Equal(secret) {
				t.Fatal("Lagrange recovery did not recover original secret")
			}
		})
	}
}

// TestLagrangeAcrossSubsets verifies that any t-element subset of
// shares recovers the secret.
func TestLagrangeAcrossSubsets(t *testing.T) {
	c := NewSecp256k1()
	secret, err := c.SampleScalar(rand.Reader)
	if err != nil {
		t.Fatalf("SampleScalar: %v", err)
	}
	const tThr, n = 3, 6
	_, shares, err := Shamir(c, secret, tThr, n, rand.Reader)
	if err != nil {
		t.Fatalf("Shamir: %v", err)
	}

	subsets := [][]int{
		{1, 2, 3},
		{1, 4, 6},
		{2, 5, 6},
		{3, 4, 5},
	}
	for _, ids := range subsets {
		sub := make(map[int]Scalar, len(ids))
		for _, id := range ids {
			sub[id] = shares[id]
		}
		got, err := LagrangeRecover(c, sub, tThr)
		if err != nil {
			t.Fatalf("LagrangeRecover %v: %v", ids, err)
		}
		if !got.Equal(secret) {
			t.Errorf("recovery from %v != original secret", ids)
		}
	}
}

// TestLagrangePanicsOnZeroID confirms the safety guard.
func TestLagrangePanicsOnZeroID(t *testing.T) {
	c := NewEd25519()
	if _, err := Lagrange(c, []int{0, 1, 2}); err == nil {
		t.Fatal("expected error on zero ID in Lagrange")
	}
}

// TestPedersenCommitVerify confirms VerifyPedersenShare accepts
// honestly-derived shares and rejects tampered ones.
func TestPedersenCommitVerify(t *testing.T) {
	for _, tc := range curveCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.curve
			secret, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("SampleScalar: %v", err)
			}
			// Build a polynomial f and a matching blinding poly r.
			f, err := NewPolynomial(c, 2, secret, rand.Reader)
			if err != nil {
				t.Fatalf("NewPolynomial f: %v", err)
			}
			rBlind, err := NewPolynomial(c, 2, nil, rand.Reader)
			if err != nil {
				t.Fatalf("NewPolynomial r: %v", err)
			}
			commits, err := PedersenVectorCommit(c, f.Coefficients(), rBlind.Coefficients())
			if err != nil {
				t.Fatalf("PedersenVectorCommit: %v", err)
			}

			// Verify share at evaluation point x = 5.
			x := c.NewScalar().SetUint64(5)
			share := f.Evaluate(x)
			blind := rBlind.Evaluate(x)

			if err := VerifyPedersenShare(c, share, blind, commits, x); err != nil {
				t.Fatalf("VerifyPedersenShare honest: %v", err)
			}

			// Tampered share fails.
			one := c.NewScalar().SetUint64(1)
			tampered := c.NewScalar().Set(share).Add(one)
			if err := VerifyPedersenShare(c, tampered, blind, commits, x); err == nil {
				t.Fatal("VerifyPedersenShare accepted tampered share")
			}
		})
	}
}
