// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hash

import (
	"bytes"
	"testing"
)

func suites() []HashSuite {
	return []HashSuite{NewLensSHA3(), NewLensBLAKE3()}
}

func TestSuiteIDsAreDistinct(t *testing.T) {
	if NewLensSHA3().ID() == NewLensBLAKE3().ID() {
		t.Fatal("suite IDs must differ across profiles")
	}
}

func TestSuiteOperationsAreDeterministic(t *testing.T) {
	for _, s := range suites() {
		t.Run(s.ID(), func(t *testing.T) {
			a := s.Hc([]byte("test"))
			b := s.Hc([]byte("test"))
			if !bytes.Equal(a, b) {
				t.Fatal("Hc not deterministic")
			}
			if len(a) != 32 {
				t.Fatalf("Hc output length %d, want 32", len(a))
			}
			a2 := s.Hu([]byte("test"), 64)
			b2 := s.Hu([]byte("test"), 64)
			if !bytes.Equal(a2, b2) {
				t.Fatal("Hu not deterministic")
			}
			if len(a2) != 64 {
				t.Fatalf("Hu output length %d, want 64", len(a2))
			}
			a3 := s.TranscriptHash([]byte("a"), []byte("b"))
			b3 := s.TranscriptHash([]byte("a"), []byte("b"))
			if a3 != b3 {
				t.Fatal("TranscriptHash not deterministic")
			}
		})
	}
}

func TestSuitesProduceDifferentBytes(t *testing.T) {
	a := NewLensSHA3().Hc([]byte("test"))
	b := NewLensBLAKE3().Hc([]byte("test"))
	if bytes.Equal(a, b) {
		t.Fatal("suites should not produce identical bytes for the same input")
	}
}

func TestTagsAreDistinct(t *testing.T) {
	for _, s := range suites() {
		t.Run(s.ID(), func(t *testing.T) {
			tr := s.TranscriptHash([]byte("x"))
			prf := s.PRF([]byte("k"), []byte("x"), 32)
			mac := s.MAC([]byte("k"), []byte("x"), 32)
			pairwise := s.DerivePairwise([]byte("k"), []byte("c"), []byte("g"), 0, 0, 0, 1, 32)
			if bytes.Equal(tr[:], prf) || bytes.Equal(prf, mac) || bytes.Equal(mac, pairwise) {
				t.Fatal("operations with distinct tags collided")
			}
		})
	}
}

func TestPairwiseCanonicalizesPair(t *testing.T) {
	for _, s := range suites() {
		t.Run(s.ID(), func(t *testing.T) {
			a := s.DerivePairwise([]byte("k"), []byte("c"), []byte("g"), 1, 2, 3, 5, 32)
			b := s.DerivePairwise([]byte("k"), []byte("c"), []byte("g"), 1, 2, 5, 3, 32)
			if !bytes.Equal(a, b) {
				t.Fatal("DerivePairwise should canonicalize pair order")
			}
		})
	}
}

func TestDerivePairwiseDistinguishesFields(t *testing.T) {
	s := NewLensSHA3()
	base := s.DerivePairwise([]byte("k"), []byte("c"), []byte("g"), 1, 2, 3, 5, 32)
	if v := s.DerivePairwise([]byte("k2"), []byte("c"), []byte("g"), 1, 2, 3, 5, 32); bytes.Equal(base, v) {
		t.Fatal("kex change did not affect output")
	}
	if v := s.DerivePairwise([]byte("k"), []byte("c2"), []byte("g"), 1, 2, 3, 5, 32); bytes.Equal(base, v) {
		t.Fatal("chainID change did not affect output")
	}
	if v := s.DerivePairwise([]byte("k"), []byte("c"), []byte("g2"), 1, 2, 3, 5, 32); bytes.Equal(base, v) {
		t.Fatal("groupID change did not affect output")
	}
	if v := s.DerivePairwise([]byte("k"), []byte("c"), []byte("g"), 99, 2, 3, 5, 32); bytes.Equal(base, v) {
		t.Fatal("eraID change did not affect output")
	}
	if v := s.DerivePairwise([]byte("k"), []byte("c"), []byte("g"), 1, 99, 3, 5, 32); bytes.Equal(base, v) {
		t.Fatal("generation change did not affect output")
	}
	if v := s.DerivePairwise([]byte("k"), []byte("c"), []byte("g"), 1, 2, 99, 5, 32); bytes.Equal(base, v) {
		t.Fatal("party-i change did not affect output")
	}
}
