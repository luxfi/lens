// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"errors"
	"fmt"
	"io"
)

// Shamir produces a (t, n)-Shamir secret sharing of `secret` over the
// curve's scalar field. Returns:
//
//   - The polynomial f with f(0) = secret and (t-1) random higher-
//     order coefficients drawn from `rand`.
//   - A map partyID → f(partyID) for partyID in [1, n].
//
// The threshold t is the minimum number of shares needed to recover
// the secret (so the polynomial degree is t-1).
//
// Note that party IDs are 1-indexed; ID 0 is reserved (evaluating at 0
// reveals the secret).
func Shamir(
	curve Curve,
	secret Scalar,
	threshold, n int,
	rand io.Reader,
) (*Polynomial, map[int]Scalar, error) {
	if threshold < 1 {
		return nil, nil, fmt.Errorf("lens/primitives: Shamir threshold %d < 1", threshold)
	}
	if n < threshold {
		return nil, nil, fmt.Errorf("lens/primitives: Shamir n=%d < t=%d", n, threshold)
	}
	poly, err := NewPolynomial(curve, threshold-1, secret, rand)
	if err != nil {
		return nil, nil, err
	}
	shares := make(map[int]Scalar, n)
	for j := 1; j <= n; j++ {
		x := curve.NewScalar().SetUint64(uint64(j))
		shares[j] = poly.Evaluate(x)
	}
	return poly, shares, nil
}

// LagrangeRecover reconstructs the secret f(0) from the supplied
// (partyID → share) map, using the smallest-ID t-element subset.
// Intended for tests and KAT verification — calling this in production
// gives the caller the master secret.
func LagrangeRecover(curve Curve, shares map[int]Scalar, threshold int) (Scalar, error) {
	if len(shares) < threshold {
		return nil, fmt.Errorf("lens/primitives: LagrangeRecover need %d shares, got %d",
			threshold, len(shares))
	}
	ids := make([]int, 0, len(shares))
	for id := range shares {
		ids = append(ids, id)
	}
	ids = SortedInts(ids)
	if len(ids) > threshold {
		ids = ids[:threshold]
	}
	lambda, err := Lagrange(curve, ids)
	if err != nil {
		return nil, err
	}
	out := curve.NewScalar()
	for _, id := range ids {
		term := curve.NewScalar().Set(lambda[id]).Mul(shares[id])
		out.Add(term)
	}
	return out, nil
}

// ErrShamirInsufficient is returned when fewer than `threshold` shares
// are supplied to a reconstruction routine.
var ErrShamirInsufficient = errors.New("lens/primitives: insufficient shares for Shamir recovery")
