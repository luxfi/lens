// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
)

// Ristretto255 is the prime-order group from RFC 9496, built on
// Curve25519 via the Ristretto encoding. Group order is identical to
// Ed25519's ℓ.
type Ristretto255 struct{}

// NewRistretto255 returns the singleton Ristretto255 curve.
func NewRistretto255() Curve { return Ristretto255{} }

const (
	ristretto255ScalarSize = 32
	ristretto255PointSize  = 32
)

var (
	ristretto255H     *ristretto255.Element
	ristretto255HOnce bool
)

// Ristretto255 implements Curve.
func (Ristretto255) Name() string     { return "ristretto255" }
func (Ristretto255) ScalarBytes() int { return ristretto255ScalarSize }
func (Ristretto255) PointBytes() int  { return ristretto255PointSize }

func (Ristretto255) NewScalar() Scalar {
	return &ristrettoScalar{s: ristretto255.NewScalar()}
}
func (Ristretto255) NewPoint() Point {
	return &ristrettoPoint{p: ristretto255.NewIdentityElement()}
}
func (Ristretto255) BasePoint() Point {
	return &ristrettoPoint{p: ristretto255.NewGeneratorElement()}
}

// SecondaryGenerator derives H from a fixed nothing-up-my-sleeve tag
// expanded to 64 uniform bytes via SHA-512, then mapped to the group
// via the FromUniformBytes Elligator construction (the standard
// hash-to-curve for Ristretto255).
func (Ristretto255) SecondaryGenerator() Point {
	if !ristretto255HOnce {
		seed := sha512.Sum512([]byte("lens.ristretto255.h-base.v1"))
		e := ristretto255.NewElement().FromUniformBytes(seed[:])
		ristretto255H = e
		ristretto255HOnce = true
	}
	out := ristretto255.NewIdentityElement().Add(ristretto255H, ristretto255.NewIdentityElement())
	return &ristrettoPoint{p: out}
}

// SampleScalar draws a uniform scalar via 64-byte read + reduction.
func (Ristretto255) SampleScalar(rand io.Reader) (Scalar, error) {
	var buf [64]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return nil, fmt.Errorf("lens/primitives: ristretto255 sample: %w", err)
	}
	s := ristretto255.NewScalar().FromUniformBytes(buf[:])
	return &ristrettoScalar{s: s}, nil
}

// HashToScalar produces a uniform scalar via SHA-512 + reduction.
func (Ristretto255) HashToScalar(data []byte) Scalar {
	h := sha512.New()
	_, _ = h.Write([]byte("lens.ristretto255.hash-to-scalar.v1"))
	_, _ = h.Write(data)
	digest := h.Sum(nil)
	s := ristretto255.NewScalar().FromUniformBytes(digest)
	return &ristrettoScalar{s: s}
}

// ristrettoScalar wraps ristretto255.Scalar to satisfy Scalar.
type ristrettoScalar struct {
	s *ristretto255.Scalar
}

func (r *ristrettoScalar) Curve() Curve { return Ristretto255{} }

func (r *ristrettoScalar) Set(other Scalar) Scalar {
	o := other.(*ristrettoScalar)
	r.s.Set(o.s)
	return r
}

func (r *ristrettoScalar) MarshalBinary() ([]byte, error) {
	return r.s.Encode(nil), nil
}

func (r *ristrettoScalar) UnmarshalBinary(data []byte) error {
	if len(data) != ristretto255ScalarSize {
		return fmt.Errorf("lens/primitives: ristretto255 scalar size %d, want %d",
			len(data), ristretto255ScalarSize)
	}
	if _, err := r.s.SetCanonicalBytes(data); err != nil {
		return fmt.Errorf("lens/primitives: ristretto255 scalar non-canonical: %w", err)
	}
	return nil
}

func (r *ristrettoScalar) SetBytes(data []byte) error {
	return r.UnmarshalBinary(data)
}

func (r *ristrettoScalar) SetUint64(v uint64) Scalar {
	var buf [32]byte
	for i := 0; i < 8; i++ {
		buf[i] = byte(v >> (8 * i))
	}
	if _, err := r.s.SetCanonicalBytes(buf[:]); err != nil {
		panic(fmt.Sprintf("lens/primitives: ristretto255 SetUint64: %v", err))
	}
	return r
}

func (r *ristrettoScalar) Add(other Scalar) Scalar {
	o := other.(*ristrettoScalar)
	r.s.Add(r.s, o.s)
	return r
}

func (r *ristrettoScalar) Sub(other Scalar) Scalar {
	o := other.(*ristrettoScalar)
	r.s.Subtract(r.s, o.s)
	return r
}

func (r *ristrettoScalar) Mul(other Scalar) Scalar {
	o := other.(*ristrettoScalar)
	r.s.Multiply(r.s, o.s)
	return r
}

func (r *ristrettoScalar) Negate() Scalar {
	r.s.Negate(r.s)
	return r
}

func (r *ristrettoScalar) Invert() Scalar {
	r.s.Invert(r.s)
	return r
}

func (r *ristrettoScalar) IsZero() bool {
	return r.s.Equal(ristretto255.NewScalar()) == 1
}

func (r *ristrettoScalar) Equal(other Scalar) bool {
	o, ok := other.(*ristrettoScalar)
	if !ok {
		return false
	}
	return r.s.Equal(o.s) == 1
}

func (r *ristrettoScalar) ActOnBase() Point {
	out := ristretto255.NewIdentityElement().ScalarBaseMult(r.s)
	return &ristrettoPoint{p: out}
}

func (r *ristrettoScalar) Act(p Point) Point {
	pt := p.(*ristrettoPoint)
	out := ristretto255.NewIdentityElement().ScalarMult(r.s, pt.p)
	return &ristrettoPoint{p: out}
}

// ristrettoPoint wraps ristretto255.Element to satisfy Point.
type ristrettoPoint struct {
	p *ristretto255.Element
}

func (r *ristrettoPoint) Curve() Curve { return Ristretto255{} }

func (r *ristrettoPoint) MarshalBinary() ([]byte, error) {
	return r.p.Encode(nil), nil
}

func (r *ristrettoPoint) UnmarshalBinary(data []byte) error {
	if len(data) != ristretto255PointSize {
		return fmt.Errorf("lens/primitives: ristretto255 point size %d, want %d",
			len(data), ristretto255PointSize)
	}
	if _, err := r.p.SetCanonicalBytes(data); err != nil {
		return fmt.Errorf("lens/primitives: ristretto255 point unmarshal: %w", err)
	}
	return nil
}

func (r *ristrettoPoint) Add(other Point) Point {
	o := other.(*ristrettoPoint)
	out := ristretto255.NewIdentityElement().Add(r.p, o.p)
	return &ristrettoPoint{p: out}
}

func (r *ristrettoPoint) Sub(other Point) Point {
	o := other.(*ristrettoPoint)
	out := ristretto255.NewIdentityElement().Subtract(r.p, o.p)
	return &ristrettoPoint{p: out}
}

func (r *ristrettoPoint) Negate() Point {
	out := ristretto255.NewIdentityElement().Negate(r.p)
	return &ristrettoPoint{p: out}
}

func (r *ristrettoPoint) IsIdentity() bool {
	return r.p.Equal(ristretto255.NewIdentityElement()) == 1
}

func (r *ristrettoPoint) Equal(other Point) bool {
	o, ok := other.(*ristrettoPoint)
	if !ok {
		return false
	}
	return r.p.Equal(o.p) == 1
}
