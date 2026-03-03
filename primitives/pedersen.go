// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"errors"
	"fmt"
	"io"
)

// PedersenCommit returns C = secret·G + blind·H over the supplied
// curve. G is the curve's base point; H is the curve's secondary
// generator (returned by SecondaryGenerator).
//
// The commitment is hiding (when blind is uniform random) and binding
// (under the discrete log assumption between G and H).
func PedersenCommit(curve Curve, secret, blind Scalar) Point {
	left := secret.ActOnBase()
	right := blind.Act(curve.SecondaryGenerator())
	return left.Add(right)
}

// PedersenVectorCommit commits to the t coefficients of a polynomial
// f(X) = c_0 + c_1·X + ... + c_{t-1}·X^{t-1} together with matching
// blinding coefficients r_0, ..., r_{t-1}. Returns the t commitments
// C_k = c_k·G + r_k·H.
func PedersenVectorCommit(curve Curve, coeffs, blinds []Scalar) ([]Point, error) {
	if len(coeffs) != len(blinds) {
		return nil, fmt.Errorf("lens/primitives: PedersenVectorCommit length mismatch: %d coeffs vs %d blinds",
			len(coeffs), len(blinds))
	}
	commits := make([]Point, len(coeffs))
	for k := range coeffs {
		commits[k] = PedersenCommit(curve, coeffs[k], blinds[k])
	}
	return commits, nil
}

// VerifyPedersenShare checks the commitment-equation
//
//	share·G + blind·H ?= Σ_{k=0..t-1} x^k · C_k
//
// where (share, blind) is what the recipient at evaluation point x
// received from the dealer, and the C_k are the dealer's broadcast
// Pedersen commits to its (secretCoeffs, blindCoeffs). Returns nil if
// the share is consistent; ErrCommitMismatch otherwise.
func VerifyPedersenShare(
	curve Curve,
	share, blind Scalar,
	commits []Point,
	x Scalar,
) error {
	if len(commits) == 0 {
		return errors.New("lens/primitives: VerifyPedersenShare with empty commits")
	}

	// LHS: share·G + blind·H
	lhs := PedersenCommit(curve, share, blind)

	// RHS: Σ x^k · C_k via Horner's method.
	rhs := curve.NewPoint()
	for k := len(commits) - 1; k >= 0; k-- {
		rhs = x.Act(rhs)
		rhs = rhs.Add(commits[k])
	}

	if !lhs.Equal(rhs) {
		return ErrCommitMismatch
	}
	return nil
}

// ErrCommitMismatch is returned when a (share, blind) pair fails the
// Pedersen verification equation.
var ErrCommitMismatch = errors.New("lens/primitives: Pedersen commitment verification failed")

// SamplePolynomialBlind draws (degree+1) uniform blinding scalars used
// alongside a Polynomial of the same degree to commit to its
// coefficients.
func SamplePolynomialBlind(curve Curve, degree int, rand io.Reader) ([]Scalar, error) {
	if degree < 0 {
		return nil, fmt.Errorf("lens/primitives: SamplePolynomialBlind degree %d", degree)
	}
	out := make([]Scalar, degree+1)
	for i := range out {
		s, err := curve.SampleScalar(rand)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}
