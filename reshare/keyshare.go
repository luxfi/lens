// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

// KeyShare regeneration for Lens.
//
// The Reshare and Refresh kernels operate on bare scalar shares —
// the SkShare field of the production-grade
// `github.com/luxfi/lens/threshold.KeyShare` struct. A KeyShare is
// MORE than just SkShare; it carries:
//
//	type KeyShare struct {
//	    Index             int
//	    PartyID           int
//	    SkShare           primitives.Scalar
//	    VerificationShare primitives.Point
//	    Lambda            primitives.Scalar
//	    Seeds             map[int][][]byte
//	    MACKeys           map[int][]byte
//	    GroupKey          *threshold.GroupKey
//	}
//
// All KDF derivations use the canonical Lens HashSuite (KMAC256
// under Lens-SHA3, keyed BLAKE3 under the legacy suite). Domain-
// separation tags:
//
//	"lens.reshare.prf-seed.v1"   — for Seeds
//	"lens.reshare.mac-key.v1"    — for MACKeys

import (
	"github.com/luxfi/lens/hash"
	"github.com/luxfi/lens/primitives"
)

// KDFOutput derives a fixed-length output from keying material under
// the supplied HashSuite's pairwise KDF. suite=nil resolves to the
// production default (Lens-SHA3).
//
// The tag is folded into the chainID label with a `|` separator so
// two callers with distinct tags but the same remaining inputs always
// produce distinct bytes.
func KDFOutput(
	suite hash.HashSuite,
	tag string,
	authKex []byte,
	chainID, groupID []byte,
	eraID, generation uint64,
	partyI, partyJ int,
	outLen int,
) []byte {
	s := hash.Resolve(suite)
	labelledChain := make([]byte, 0, len(tag)+1+len(chainID))
	labelledChain = append(labelledChain, []byte(tag)...)
	labelledChain = append(labelledChain, '|')
	labelledChain = append(labelledChain, chainID...)
	return s.DerivePairwise(authKex, labelledChain, groupID, eraID, generation, partyI, partyJ, outLen)
}

// CanonicalPair returns the (i, j) tuple in canonical (smaller-first)
// order. Used as a map key for pairwise material.
func CanonicalPair(i, j int) [2]int {
	if i > j {
		return [2]int{j, i}
	}
	return [2]int{i, j}
}

// EraseScalar overwrites the scalar's binary representation with zero
// bytes. After activation, every old share MUST be erased — failure
// to do so undermines the proactive-security guarantee.
func EraseScalar(s primitives.Scalar) {
	if s == nil {
		return
	}
	zero := s.Curve().NewScalar()
	s.Set(zero)
}
