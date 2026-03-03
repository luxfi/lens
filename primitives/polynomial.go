// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"errors"
	"fmt"
	"io"
	"sort"
)

// Polynomial represents f(X) = a_0 + a_1·X + ... + a_t·X^t with
// coefficients in the curve's scalar field.
type Polynomial struct {
	curve        Curve
	coefficients []Scalar
}

// NewPolynomial constructs a polynomial of the given degree with the
// supplied constant term and (degree) random higher-order coefficients
// drawn from rand.
//
// If constant == nil, the constant term is set to zero (used by
// HJKY97 zero-poly Refresh).
func NewPolynomial(curve Curve, degree int, constant Scalar, rand io.Reader) (*Polynomial, error) {
	if degree < 0 {
		return nil, fmt.Errorf("lens/primitives: negative polynomial degree %d", degree)
	}
	p := &Polynomial{
		curve:        curve,
		coefficients: make([]Scalar, degree+1),
	}
	if constant == nil {
		p.coefficients[0] = curve.NewScalar()
	} else {
		p.coefficients[0] = curve.NewScalar().Set(constant)
	}
	for i := 1; i <= degree; i++ {
		s, err := curve.SampleScalar(rand)
		if err != nil {
			return nil, fmt.Errorf("lens/primitives: polynomial sample: %w", err)
		}
		p.coefficients[i] = s
	}
	return p, nil
}

// PolynomialFromCoefficients wraps an explicit coefficient slice as a
// polynomial. The slice is shared, not copied — the caller is
// responsible for not mutating it externally.
func PolynomialFromCoefficients(curve Curve, coeffs []Scalar) *Polynomial {
	return &Polynomial{curve: curve, coefficients: coeffs}
}

// Degree returns the polynomial's degree.
func (p *Polynomial) Degree() int { return len(p.coefficients) - 1 }

// Coefficients returns the underlying coefficient slice (not a copy).
// Used by the commitment layer to compute Pedersen commits per term.
func (p *Polynomial) Coefficients() []Scalar { return p.coefficients }

// Constant returns a copy of the constant term.
func (p *Polynomial) Constant() Scalar {
	return p.curve.NewScalar().Set(p.coefficients[0])
}

// Evaluate computes f(x) via Horner's method. Panics if x is zero, to
// avoid leaking the secret constant term.
func (p *Polynomial) Evaluate(x Scalar) Scalar {
	if x.IsZero() {
		panic("lens/primitives: polynomial.Evaluate at 0 leaks secret")
	}
	result := p.curve.NewScalar()
	for i := len(p.coefficients) - 1; i >= 0; i-- {
		result.Mul(x).Add(p.coefficients[i])
	}
	return result
}

// EvaluateUnchecked is like Evaluate but allows x = 0. Used in test/KAT
// paths to recover f(0) (the secret) for verification.
func (p *Polynomial) EvaluateUnchecked(x Scalar) Scalar {
	result := p.curve.NewScalar()
	for i := len(p.coefficients) - 1; i >= 0; i-- {
		result.Mul(x).Add(p.coefficients[i])
	}
	return result
}

// Lagrange returns the Lagrange basis coefficients λ_i^T evaluated at
// X = 0 for the set of one-indexed party IDs T:
//
//	λ_i = Π_{j ∈ T, j ≠ i} (-x_j) / (x_i - x_j)
//
// where x_k is the scalar representation of party ID k. Used to
// reconstruct s = Σ_i λ_i · s_i over the curve.
//
// IDs MUST be distinct, non-zero, and < group order.
func Lagrange(curve Curve, ids []int) (map[int]Scalar, error) {
	if len(ids) == 0 {
		return nil, errors.New("lens/primitives: Lagrange on empty set")
	}
	for _, id := range ids {
		if id == 0 {
			return nil, errors.New("lens/primitives: Lagrange at zero ID leaks secret")
		}
	}
	out := make(map[int]Scalar, len(ids))
	for _, i := range ids {
		xi := curve.NewScalar().SetUint64(uint64(i))
		num := curve.NewScalar().SetUint64(1)
		den := curve.NewScalar().SetUint64(1)
		for _, j := range ids {
			if i == j {
				continue
			}
			xj := curve.NewScalar().SetUint64(uint64(j))
			// num *= -x_j
			negXj := curve.NewScalar().Set(xj).Negate()
			num.Mul(negXj)
			// den *= (x_i - x_j)
			diff := curve.NewScalar().Set(xi).Sub(xj)
			den.Mul(diff)
		}
		if den.IsZero() {
			return nil, errors.New("lens/primitives: Lagrange denominator is zero (duplicate IDs?)")
		}
		coeff := curve.NewScalar().Set(num).Mul(curve.NewScalar().Set(den).Invert())
		out[i] = coeff
	}
	return out, nil
}

// LagrangeAt returns Lagrange coefficients evaluated at an arbitrary
// scalar `x` (rather than at 0). Used during VSR to evaluate the
// composite polynomial G(x_j) = Σ_i λ_i · g_i(x_j).
func LagrangeAt(curve Curve, ids []int, x Scalar) (map[int]Scalar, error) {
	if len(ids) == 0 {
		return nil, errors.New("lens/primitives: LagrangeAt on empty set")
	}
	out := make(map[int]Scalar, len(ids))
	for _, i := range ids {
		xi := curve.NewScalar().SetUint64(uint64(i))
		num := curve.NewScalar().SetUint64(1)
		den := curve.NewScalar().SetUint64(1)
		for _, j := range ids {
			if i == j {
				continue
			}
			xj := curve.NewScalar().SetUint64(uint64(j))
			diffNum := curve.NewScalar().Set(x).Sub(xj)
			num.Mul(diffNum)
			diffDen := curve.NewScalar().Set(xi).Sub(xj)
			den.Mul(diffDen)
		}
		if den.IsZero() {
			return nil, errors.New("lens/primitives: LagrangeAt denominator zero")
		}
		out[i] = curve.NewScalar().Set(num).Mul(curve.NewScalar().Set(den).Invert())
	}
	return out, nil
}

// SortedInts returns a copy of `ids` sorted ascending.
func SortedInts(ids []int) []int {
	out := append([]int(nil), ids...)
	sort.Ints(out)
	return out
}
