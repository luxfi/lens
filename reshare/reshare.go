// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package reshare implements the two proactive secret-sharing
// primitives Lens needs to evolve a key era's share distribution
// without changing the persistent group public key.
//
//  1. Refresh — same-committee zero-polynomial proactive update
//     (Herzberg-Jakobsson-Jarecki-Krawczyk-Yung 1997, "PSS"). The
//     committee is fixed; every party samples a random degree-(t-1)
//     polynomial z_i(X) with z_i(0) = 0 and contributes z_i(α_j) to
//     each peer j. Each party updates s'_j = s_j + Σ_i z_i(α_j). The
//     master secret is unchanged because Σ_i z_i(0) = 0. Use case:
//     periodic share-randomization within a stable validator set, to
//     defeat a mobile adversary that compromises < t parties per
//     epoch and accumulates shares across epochs.
//
//  2. Reshare — validator-set resharing. The OLD committee O and NEW
//     committee N are different (potentially disjoint, potentially
//     different threshold). The new committee has no old shares and
//     so cannot apply zero-polynomial deltas. Instead, a qualified
//     subset Q ⊆ O with |Q| ≥ t_old executes a one-shot Shamir-from-
//     Lagrange transformation: each i ∈ Q samples g_i(X) of degree
//     t_new-1 with g_i(0) = s_i (its OWN old share as the constant
//     term), and privately delivers g_i(β_j) to each new party j ∈ N.
//     Each new party j computes
//
//     s'_j = Σ_{i ∈ Q} λ^Q_i · g_i(β_j)
//
//     where λ^Q_i are the Lagrange coefficients for Q evaluated at 0.
//     Define G(X) = Σ_{i ∈ Q} λ^Q_i · g_i(X). Then deg(G) = t_new − 1,
//     and G(0) = s by Lagrange interpolation over Q at X = 0.
//     Use case: validator-set rotation at Quasar epoch boundaries.
//
// Both primitives leave the public key X = s·G unchanged. The genesis
// values (G, H, X) are persistent for the entire key era. Only the
// share distribution changes. This is the property that lets Quasar
// avoid running a full DKG on every validator-set rotation.
//
// # Security model (kernel)
//
// The kernel APIs Refresh / Reshare implement the arithmetic
// correctness of the two primitives, against a HONEST-BUT-CURIOUS
// adversary that may statically corrupt up to t-1 parties.
//
// # VSR — production deployment
//
// The kernel is embedded in a full Verifiable Secret Resharing
// protocol with the following components, implemented in sibling
// files:
//
//   - commit.go    — Pedersen commits (g^c · h^r) to f_i (Refresh)
//     and g_i (Reshare); recipients verify each share
//     against the committed polynomial.
//   - transcript.go — Domain-separated transcript binding the entire
//     resharing exchange.
//   - complaint.go — Complaint format, signed evidence, complaint
//     quorum logic, deterministic disqualification.
//   - keyshare.go  — Wraps reshared scalar shares into complete
//     threshold.KeyShare instances by regenerating
//     Lambda + Seeds + MACKeys + VerificationShare.
//   - pairwise.go  — Authenticated pairwise X25519+Ed25519 KEX → KDF
//     for Seeds / MACKeys under domain-separated tags.
//   - activation.go — Post-reshare activation cert: the new committee
//     threshold-signs the resharing transcript hash
//     under the unchanged GroupKey. The chain accepts
//     the new epoch only when the activation verifies.
package reshare

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/luxfi/lens/primitives"
)

// Errors returned by the package.
var (
	ErrInvalidThresholdOld = errors.New("reshare: t_old must be >= 1")
	ErrInvalidThresholdNew = errors.New("reshare: t_new must be >= 1")
	ErrTOldExceedsOldSet   = errors.New("reshare: t_old exceeds size of old committee")
	ErrTNewExceedsNewSet   = errors.New("reshare: t_new exceeds size of new committee")
	ErrEmptyOldShares      = errors.New("reshare: no old shares supplied")
	ErrEmptyNewSet         = errors.New("reshare: empty new committee")
	ErrZeroPartyID         = errors.New("reshare: party IDs must be 1-indexed (no 0)")
	ErrDuplicateNewID      = errors.New("reshare: duplicate ID in new committee")
	ErrTOldShortfall       = errors.New("reshare: fewer than t_old shares supplied; cannot reconstruct s")
)

// Reshare runs the proactive secret-resharing protocol described in
// the package doc on the supplied curve. Inputs:
//
//   - c          — the curve s lives in (must match the GroupKey's curve).
//   - oldShares  — partyID → secret-share scalar (1-indexed evaluation
//     point). The map MUST contain at least t_old entries.
//   - tOld       — old reconstruction threshold.
//   - newSet     — new committee (slice of distinct 1-indexed party IDs).
//   - tNew       — new reconstruction threshold (≤ |newSet|).
//   - randSource — randomness source for fresh polynomial coefficients
//     (nil → crypto/rand.Reader).
//
// Returns the new share map keyed by new partyID. The output share at
// partyID j satisfies the (t_new, |newSet|)-Shamir relation against the
// SAME master secret s as the input shares.
func Reshare(
	c primitives.Curve,
	oldShares map[int]primitives.Scalar,
	tOld int,
	newSet []int,
	tNew int,
	randSource io.Reader,
) (map[int]primitives.Scalar, error) {
	if randSource == nil {
		randSource = rand.Reader
	}
	if tOld < 1 {
		return nil, ErrInvalidThresholdOld
	}
	if tNew < 1 {
		return nil, ErrInvalidThresholdNew
	}
	if len(oldShares) == 0 {
		return nil, ErrEmptyOldShares
	}
	if len(newSet) == 0 {
		return nil, ErrEmptyNewSet
	}
	if tOld > len(oldShares) {
		return nil, ErrTOldShortfall
	}
	if tNew > len(newSet) {
		return nil, ErrTNewExceedsNewSet
	}

	// Validate new committee.
	seenNew := make(map[int]bool, len(newSet))
	for _, j := range newSet {
		if j == 0 {
			return nil, ErrZeroPartyID
		}
		if seenNew[j] {
			return nil, ErrDuplicateNewID
		}
		seenNew[j] = true
	}
	for id := range oldShares {
		if id == 0 {
			return nil, ErrZeroPartyID
		}
	}

	// Pick the deterministic smallest-ID t_old quorum.
	quorum := selectQuorum(oldShares, tOld)
	quorumIDs := sortedKeys(quorum)

	// Lagrange λ_i^Q at X = 0 for the quorum.
	lambda, err := primitives.Lagrange(c, quorumIDs)
	if err != nil {
		return nil, fmt.Errorf("reshare: lagrange: %w", err)
	}

	// For each i ∈ Q, sample its degree-(t_new-1) polynomial f_i with
	// f_i(0) = λ_i · s_i (so Σ_i f_i(0) = Σ_i λ_i · s_i = s).
	newShares := make(map[int]primitives.Scalar, len(newSet))
	for _, j := range newSet {
		newShares[j] = c.NewScalar()
	}

	for _, i := range quorumIDs {
		c0 := c.NewScalar().Set(lambda[i]).Mul(quorum[i])
		fi, err := primitives.NewPolynomial(c, tNew-1, c0, randSource)
		if err != nil {
			return nil, fmt.Errorf("reshare: NewPolynomial: %w", err)
		}
		for _, j := range newSet {
			x := c.NewScalar().SetUint64(uint64(j))
			contrib := fi.Evaluate(x)
			newShares[j].Add(contrib)
		}
	}
	return newShares, nil
}

// Refresh runs the HJKY97 same-committee proactive update on a fixed
// committee. The set of party IDs and the threshold are unchanged:
// only the share values rotate to fresh independent randomness while
// preserving Σ_j λ^T_j · s_j = s for every threshold subset T.
//
// Algorithm (per HJKY97 §3, "zero-polynomial" form):
//
//  1. Each party i samples a random degree-(t-1) polynomial z_i(X)
//     over the curve's scalar field with z_i(0) = 0 (i.e. no constant
//     term).
//
//  2. Each party i privately delivers z_i(α_j) to every party j in
//     the committee, where α_j is the Shamir evaluation point of
//     party j (here α_j = j, the 1-indexed party ID).
//
//  3. Each party j updates its share:
//
//     s'_j = s_j + Σ_i z_i(α_j) (mod q)
func Refresh(
	c primitives.Curve,
	shares map[int]primitives.Scalar,
	threshold int,
	randSource io.Reader,
) (map[int]primitives.Scalar, error) {
	if randSource == nil {
		randSource = rand.Reader
	}
	if threshold < 1 {
		return nil, ErrInvalidThresholdOld
	}
	if len(shares) == 0 {
		return nil, ErrEmptyOldShares
	}
	if threshold > len(shares) {
		return nil, ErrTOldShortfall
	}
	for id := range shares {
		if id == 0 {
			return nil, ErrZeroPartyID
		}
	}

	parties := sortedKeys(shares)

	// Initialize new shares as a copy of the old shares.
	out := make(map[int]primitives.Scalar, len(shares))
	for _, j := range parties {
		out[j] = c.NewScalar().Set(shares[j])
	}

	// threshold = 1 means every share IS the secret; refresh must be a
	// no-op (the only zero-poly of degree 0 is identically 0).
	if threshold == 1 {
		return out, nil
	}

	// For each party i (canonical order), sample z_i (degree-(t-1),
	// constant term 0), evaluate at every α_j, accumulate into out[j].
	for range parties {
		// z_i has degree (t-1) and constant term 0. Sample t-1 high-
		// degree coefficients (degree 1..t-1).
		coeffs := make([]primitives.Scalar, threshold)
		coeffs[0] = c.NewScalar() // forced zero
		for d := 1; d < threshold; d++ {
			s, err := c.SampleScalar(randSource)
			if err != nil {
				return nil, fmt.Errorf("reshare/refresh: sample: %w", err)
			}
			coeffs[d] = s
		}
		zPoly := primitives.PolynomialFromCoefficients(c, coeffs)
		for _, j := range parties {
			x := c.NewScalar().SetUint64(uint64(j))
			contrib := zPoly.Evaluate(x)
			out[j].Add(contrib)
		}
	}
	return out, nil
}

// Verify is a debugging helper: it Lagrange-interpolates the input
// shares at X=0 (using the smallest-ID t-subset) and returns the
// reconstructed master secret.
//
// IMPORTANT: This recovers s, so it MUST NOT be used in production —
// only in tests and KAT verification. Calling it gives the caller the
// secret.
func Verify(c primitives.Curve, shares map[int]primitives.Scalar, t int) (primitives.Scalar, error) {
	return primitives.LagrangeRecover(c, shares, t)
}

// selectQuorum picks a deterministic t-element subset of oldShares (the
// t entries with the smallest party IDs) and returns it.
func selectQuorum(oldShares map[int]primitives.Scalar, t int) map[int]primitives.Scalar {
	keys := sortedKeys(oldShares)
	out := make(map[int]primitives.Scalar, t)
	for i := 0; i < t; i++ {
		out[keys[i]] = oldShares[keys[i]]
	}
	return out
}

// sortedKeys returns ascending integer keys.
func sortedKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
