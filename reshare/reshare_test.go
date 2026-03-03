// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/lens/primitives"
)

func curves() []primitives.Curve {
	return []primitives.Curve{
		primitives.NewEd25519(),
		primitives.NewSecp256k1(),
		primitives.NewRistretto255(),
	}
}

// TestReshareSameCommitteeSamesT preserves the master secret when both
// committees are identical and threshold is unchanged.
func TestReshareSameCommitteeSameT(t *testing.T) {
	for _, c := range curves() {
		t.Run(c.Name(), func(t *testing.T) {
			secret, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("SampleScalar: %v", err)
			}
			const tThr, n = 3, 5
			_, oldShares, err := primitives.Shamir(c, secret, tThr, n, rand.Reader)
			if err != nil {
				t.Fatalf("Shamir: %v", err)
			}
			newSet := []int{1, 2, 3, 4, 5}
			newShares, err := Reshare(c, oldShares, tThr, newSet, tThr, rand.Reader)
			if err != nil {
				t.Fatalf("Reshare: %v", err)
			}
			recovered, err := primitives.LagrangeRecover(c, newShares, tThr)
			if err != nil {
				t.Fatalf("LagrangeRecover: %v", err)
			}
			if !recovered.Equal(secret) {
				t.Fatal("Reshare did not preserve master secret")
			}
		})
	}
}

// TestReshareDifferentSet covers a disjoint old → new committee.
func TestReshareDifferentSet(t *testing.T) {
	for _, c := range curves() {
		t.Run(c.Name(), func(t *testing.T) {
			secret, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("SampleScalar: %v", err)
			}
			const tOld, nOld = 3, 4
			_, oldShares, err := primitives.Shamir(c, secret, tOld, nOld, rand.Reader)
			if err != nil {
				t.Fatalf("Shamir: %v", err)
			}
			newSet := []int{10, 11, 12, 13, 14}
			tNew := 4
			newShares, err := Reshare(c, oldShares, tOld, newSet, tNew, rand.Reader)
			if err != nil {
				t.Fatalf("Reshare: %v", err)
			}
			recovered, err := primitives.LagrangeRecover(c, newShares, tNew)
			if err != nil {
				t.Fatalf("LagrangeRecover: %v", err)
			}
			if !recovered.Equal(secret) {
				t.Fatal("Reshare across disjoint set did not preserve master secret")
			}
		})
	}
}

// TestReshareDifferentT covers a threshold change.
func TestReshareDifferentT(t *testing.T) {
	for _, c := range curves() {
		t.Run(c.Name(), func(t *testing.T) {
			secret, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("SampleScalar: %v", err)
			}
			const tOld, nOld = 3, 5
			_, oldShares, err := primitives.Shamir(c, secret, tOld, nOld, rand.Reader)
			if err != nil {
				t.Fatalf("Shamir: %v", err)
			}
			newSet := []int{1, 2, 3, 4, 5, 6, 7}
			const tNew = 5
			newShares, err := Reshare(c, oldShares, tOld, newSet, tNew, rand.Reader)
			if err != nil {
				t.Fatalf("Reshare: %v", err)
			}
			recovered, err := primitives.LagrangeRecover(c, newShares, tNew)
			if err != nil {
				t.Fatalf("LagrangeRecover: %v", err)
			}
			if !recovered.Equal(secret) {
				t.Fatal("Reshare with new threshold did not preserve master secret")
			}
			// Confirm we cannot recover with fewer than tNew.
			subset := make(map[int]primitives.Scalar, tNew-1)
			for j := 1; j <= tNew-1; j++ {
				subset[j] = newShares[j]
			}
			_, err = primitives.LagrangeRecover(c, subset, tNew)
			if err == nil {
				t.Fatal("recovery succeeded with fewer than t shares")
			}
		})
	}
}

// TestRefreshPreservesSecret runs HJKY97 and confirms the master
// secret survives.
func TestRefreshPreservesSecret(t *testing.T) {
	for _, c := range curves() {
		t.Run(c.Name(), func(t *testing.T) {
			secret, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("SampleScalar: %v", err)
			}
			const tThr, n = 3, 5
			_, oldShares, err := primitives.Shamir(c, secret, tThr, n, rand.Reader)
			if err != nil {
				t.Fatalf("Shamir: %v", err)
			}
			newShares, err := Refresh(c, oldShares, tThr, rand.Reader)
			if err != nil {
				t.Fatalf("Refresh: %v", err)
			}
			// Each share differs from its old version (with overwhelming
			// probability — degree ≥ 1 of zero-poly).
			same := 0
			for j := range newShares {
				if newShares[j].Equal(oldShares[j]) {
					same++
				}
			}
			if same > n/2 {
				t.Errorf("too many shares unchanged after Refresh: %d/%d", same, n)
			}
			recovered, err := primitives.LagrangeRecover(c, newShares, tThr)
			if err != nil {
				t.Fatalf("LagrangeRecover: %v", err)
			}
			if !recovered.Equal(secret) {
				t.Fatal("Refresh did not preserve master secret")
			}
		})
	}
}

// TestReshareErrors covers input-validation paths.
func TestReshareErrors(t *testing.T) {
	c := primitives.NewEd25519()
	secret, _ := c.SampleScalar(rand.Reader)
	_, oldShares, _ := primitives.Shamir(c, secret, 3, 3, rand.Reader)

	if _, err := Reshare(c, oldShares, 0, []int{1, 2, 3}, 3, nil); err == nil {
		t.Error("expected error for tOld=0")
	}
	if _, err := Reshare(c, oldShares, 3, []int{1, 2, 3}, 0, nil); err == nil {
		t.Error("expected error for tNew=0")
	}
	if _, err := Reshare(c, nil, 1, []int{1}, 1, nil); err == nil {
		t.Error("expected error for empty old shares")
	}
	if _, err := Reshare(c, oldShares, 3, []int{}, 1, nil); err == nil {
		t.Error("expected error for empty new set")
	}
	if _, err := Reshare(c, oldShares, 3, []int{1, 1, 2}, 2, nil); err == nil {
		t.Error("expected error for duplicate new ID")
	}
	if _, err := Reshare(c, oldShares, 3, []int{0, 1, 2}, 2, nil); err == nil {
		t.Error("expected error for zero new ID")
	}
	if _, err := Reshare(c, oldShares, 5, []int{1, 2, 3}, 3, nil); err == nil {
		t.Error("expected error for tOld > |oldShares|")
	}
	if _, err := Reshare(c, oldShares, 3, []int{1, 2}, 3, nil); err == nil {
		t.Error("expected error for tNew > |newSet|")
	}
}

// TestRefreshErrors covers Refresh validation paths.
func TestRefreshErrors(t *testing.T) {
	c := primitives.NewSecp256k1()
	secret, _ := c.SampleScalar(rand.Reader)
	_, shares, _ := primitives.Shamir(c, secret, 3, 3, rand.Reader)
	if _, err := Refresh(c, shares, 0, nil); err == nil {
		t.Error("expected error for threshold=0")
	}
	if _, err := Refresh(c, nil, 1, nil); err == nil {
		t.Error("expected error for empty shares")
	}
	if _, err := Refresh(c, shares, 5, nil); err == nil {
		t.Error("expected error for threshold > n")
	}
	// threshold=1 is degenerate but valid.
	if _, err := Refresh(c, shares, 1, nil); err != nil {
		t.Errorf("threshold=1 should not error: %v", err)
	}
}
