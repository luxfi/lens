// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

// Ed25519 is the RFC 8032 / FIPS 186-5 Edwards-form curve. The
// prime-order subgroup has order ℓ = 2^252 + 27742317777372353535851937790883648493.
//
// G is the conventional Ed25519 base point.
// H is derived deterministically via hash-to-curve from a Lens-specific
// nothing-up-my-sleeve tag, then cleared to the prime-order subgroup
// via multiplication by the cofactor.
type Ed25519 struct{}

// NewEd25519 returns the singleton Ed25519 curve.
func NewEd25519() Curve { return Ed25519{} }

const (
	ed25519ScalarSize = 32
	ed25519PointSize  = 32
)

// Lazy initializers for G and H.
var (
	ed25519BaseOnce  ed25519Point
	ed25519H         *edwards25519.Point
	ed25519BaseInit  bool
	ed25519HBaseInit bool
)

func ed25519Base() *edwards25519.Point {
	if !ed25519BaseInit {
		ed25519BaseOnce.p = edwards25519.NewGeneratorPoint()
		ed25519BaseInit = true
	}
	return ed25519BaseOnce.p
}

// ed25519GetH is the secondary Pedersen generator. Derived deterministically
// via try-and-increment: hash a counter-extended nothing-up-my-sleeve tag,
// attempt SetBytes; if it fails (the encoding is not a valid curve point),
// bump the counter. Once a valid point is found we multiply by 8 to clear
// the cofactor and land in the prime-order subgroup. The discrete log
// of H with respect to G is unknown to anyone (no party constructs H by
// scalar multiplication), which is the only property the Pedersen
// commitment binding requires.
func ed25519GetH() *edwards25519.Point {
	if !ed25519HBaseInit {
		for ctr := uint64(0); ctr < 1<<20; ctr++ {
			h := sha512.New()
			_, _ = h.Write([]byte("lens.ed25519.h-base.v1"))
			var ctrBuf [8]byte
			for i := 0; i < 8; i++ {
				ctrBuf[i] = byte(ctr >> (8 * i))
			}
			_, _ = h.Write(ctrBuf[:])
			seed := h.Sum(nil)
			p, err := new(edwards25519.Point).SetBytes(seed[:32])
			if err != nil {
				continue
			}
			// Multiply by 8 to clear cofactor and land in prime-order
			// subgroup. p must not be the identity after clearing.
			cleared := new(edwards25519.Point).MultByCofactor(p)
			if cleared.Equal(edwards25519.NewIdentityPoint()) == 1 {
				continue
			}
			ed25519H = cleared
			ed25519HBaseInit = true
			return ed25519H
		}
		panic("lens/primitives: ed25519 H derivation exhausted counter")
	}
	return ed25519H
}

// Ed25519 implements Curve.
func (Ed25519) Name() string     { return "ed25519" }
func (Ed25519) ScalarBytes() int { return ed25519ScalarSize }
func (Ed25519) PointBytes() int  { return ed25519PointSize }

func (Ed25519) NewScalar() Scalar { return &ed25519Scalar{s: edwards25519.NewScalar()} }
func (Ed25519) NewPoint() Point   { return &ed25519Point{p: edwards25519.NewIdentityPoint()} }
func (Ed25519) BasePoint() Point  { return &ed25519Point{p: ed25519Base()} }
func (c Ed25519) SecondaryGenerator() Point {
	return &ed25519Point{p: ed25519GetH()}
}

// SampleScalar draws a uniform scalar from a 64-byte read which is
// reduced mod ℓ via SetUniformBytes (statistically unbiased).
func (Ed25519) SampleScalar(rand io.Reader) (Scalar, error) {
	var buf [64]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return nil, fmt.Errorf("lens/primitives: ed25519 sample: %w", err)
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		return nil, fmt.Errorf("lens/primitives: ed25519 reduce: %w", err)
	}
	return &ed25519Scalar{s: s}, nil
}

// HashToScalar maps a byte string to a uniform scalar via SHA-512 +
// SetUniformBytes (the standard reduction for ℓ).
func (Ed25519) HashToScalar(data []byte) Scalar {
	h := sha512.New()
	_, _ = h.Write([]byte("lens.ed25519.hash-to-scalar.v1"))
	_, _ = h.Write(data)
	digest := h.Sum(nil)
	s, err := edwards25519.NewScalar().SetUniformBytes(digest)
	if err != nil {
		panic(fmt.Sprintf("lens/primitives: ed25519 hash-to-scalar: %v", err))
	}
	return &ed25519Scalar{s: s}
}

// ed25519Scalar wraps filippo.io/edwards25519.Scalar to satisfy Scalar.
type ed25519Scalar struct {
	s *edwards25519.Scalar
}

func (e *ed25519Scalar) Curve() Curve { return Ed25519{} }

func (e *ed25519Scalar) Set(other Scalar) Scalar {
	o := other.(*ed25519Scalar)
	e.s.Set(o.s)
	return e
}

func (e *ed25519Scalar) MarshalBinary() ([]byte, error) {
	return e.s.Bytes(), nil
}

func (e *ed25519Scalar) UnmarshalBinary(data []byte) error {
	if len(data) != ed25519ScalarSize {
		return fmt.Errorf("lens/primitives: ed25519 scalar size %d, want %d", len(data), ed25519ScalarSize)
	}
	if _, err := e.s.SetCanonicalBytes(data); err != nil {
		return fmt.Errorf("lens/primitives: ed25519 scalar non-canonical: %w", err)
	}
	return nil
}

func (e *ed25519Scalar) SetBytes(bytes []byte) error {
	return e.UnmarshalBinary(bytes)
}

func (e *ed25519Scalar) SetUint64(v uint64) Scalar {
	var buf [32]byte
	for i := 0; i < 8; i++ {
		buf[i] = byte(v >> (8 * i))
	}
	if _, err := e.s.SetCanonicalBytes(buf[:]); err != nil {
		panic(fmt.Sprintf("lens/primitives: ed25519 SetUint64: %v", err))
	}
	return e
}

func (e *ed25519Scalar) Add(other Scalar) Scalar {
	o := other.(*ed25519Scalar)
	e.s.Add(e.s, o.s)
	return e
}

func (e *ed25519Scalar) Sub(other Scalar) Scalar {
	o := other.(*ed25519Scalar)
	e.s.Subtract(e.s, o.s)
	return e
}

func (e *ed25519Scalar) Mul(other Scalar) Scalar {
	o := other.(*ed25519Scalar)
	e.s.Multiply(e.s, o.s)
	return e
}

func (e *ed25519Scalar) Negate() Scalar {
	e.s.Negate(e.s)
	return e
}

func (e *ed25519Scalar) Invert() Scalar {
	e.s.Invert(e.s)
	return e
}

func (e *ed25519Scalar) IsZero() bool {
	return e.s.Equal(edwards25519.NewScalar()) == 1
}

func (e *ed25519Scalar) Equal(other Scalar) bool {
	o := other.(*ed25519Scalar)
	return e.s.Equal(o.s) == 1
}

func (e *ed25519Scalar) ActOnBase() Point {
	p := edwards25519.NewIdentityPoint()
	p.ScalarBaseMult(e.s)
	return &ed25519Point{p: p}
}

func (e *ed25519Scalar) Act(pp Point) Point {
	pt := pp.(*ed25519Point)
	out := edwards25519.NewIdentityPoint()
	out.ScalarMult(e.s, pt.p)
	return &ed25519Point{p: out}
}

// ed25519Point wraps filippo.io/edwards25519.Point to satisfy Point.
type ed25519Point struct {
	p *edwards25519.Point
}

func (e *ed25519Point) Curve() Curve { return Ed25519{} }

func (e *ed25519Point) MarshalBinary() ([]byte, error) {
	return e.p.Bytes(), nil
}

func (e *ed25519Point) UnmarshalBinary(data []byte) error {
	if len(data) != ed25519PointSize {
		return fmt.Errorf("lens/primitives: ed25519 point size %d, want %d", len(data), ed25519PointSize)
	}
	if _, err := e.p.SetBytes(data); err != nil {
		return fmt.Errorf("lens/primitives: ed25519 point unmarshal: %w", err)
	}
	return nil
}

func (e *ed25519Point) Add(other Point) Point {
	o := other.(*ed25519Point)
	out := edwards25519.NewIdentityPoint()
	out.Add(e.p, o.p)
	return &ed25519Point{p: out}
}

func (e *ed25519Point) Sub(other Point) Point {
	o := other.(*ed25519Point)
	out := edwards25519.NewIdentityPoint()
	out.Subtract(e.p, o.p)
	return &ed25519Point{p: out}
}

func (e *ed25519Point) Negate() Point {
	out := edwards25519.NewIdentityPoint()
	out.Negate(e.p)
	return &ed25519Point{p: out}
}

func (e *ed25519Point) IsIdentity() bool {
	return e.p.Equal(edwards25519.NewIdentityPoint()) == 1
}

func (e *ed25519Point) Equal(other Point) bool {
	o, ok := other.(*ed25519Point)
	if !ok {
		return false
	}
	return e.p.Equal(o.p) == 1
}

// errCanonicalEd25519 is returned when an ed25519 point fails canonical
// decoding. Exported for callers that want to test for this case.
var errCanonicalEd25519 = errors.New("lens/primitives: ed25519 non-canonical encoding")
