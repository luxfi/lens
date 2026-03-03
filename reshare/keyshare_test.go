// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/luxfi/lens/primitives"
)

// TestKDFOutputDistinguishesTags — same kex + different tags produce
// different outputs.
func TestKDFOutputDistinguishesTags(t *testing.T) {
	a := KDFOutput(nil, "tagA", []byte("kex"), []byte("c"), []byte("g"), 0, 0, 0, 1, 32)
	b := KDFOutput(nil, "tagB", []byte("kex"), []byte("c"), []byte("g"), 0, 0, 0, 1, 32)
	if bytes.Equal(a, b) {
		t.Fatal("KDFOutput with different tags collided")
	}
}

// TestCanonicalPair — order-invariant mapping.
func TestCanonicalPair(t *testing.T) {
	if got := CanonicalPair(3, 5); got != [2]int{3, 5} {
		t.Errorf("CanonicalPair(3,5) = %v", got)
	}
	if got := CanonicalPair(5, 3); got != [2]int{3, 5} {
		t.Errorf("CanonicalPair(5,3) = %v", got)
	}
	if got := CanonicalPair(3, 3); got != [2]int{3, 3} {
		t.Errorf("CanonicalPair(3,3) = %v", got)
	}
}

// TestEraseScalar — scalar zeroed in place.
func TestEraseScalar(t *testing.T) {
	c := primitives.NewEd25519()
	s, err := c.SampleScalar(rand.Reader)
	if err != nil {
		t.Fatalf("SampleScalar: %v", err)
	}
	if s.IsZero() {
		t.Fatal("sampled zero")
	}
	EraseScalar(s)
	if !s.IsZero() {
		t.Fatal("EraseScalar did not zero scalar")
	}
}
