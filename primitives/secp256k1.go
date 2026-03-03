// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Secp256k1 is the SEC2 / Bitcoin curve.
type Secp256k1 struct{}

// NewSecp256k1 returns the singleton Secp256k1 curve.
func NewSecp256k1() Curve { return Secp256k1{} }

const (
	secp256k1ScalarSize = 32
	secp256k1PointSize  = 33 // compressed
)

var (
	// Group order n.
	secp256k1OrderHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
	secp256k1OrderBig *big.Int

	// Field modulus p.
	secp256k1FieldHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
	secp256k1FieldBig *big.Int

	secp256k1BaseX, secp256k1BaseY secp256k1.FieldVal
	secp256k1H                     *secp256k1Point
	secp256k1HOnce                 bool
)

func init() {
	secp256k1OrderBig, _ = new(big.Int).SetString(secp256k1OrderHex, 16)
	secp256k1FieldBig, _ = new(big.Int).SetString(secp256k1FieldHex, 16)

	gx, _ := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	gy, _ := hex.DecodeString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	secp256k1BaseX.SetByteSlice(gx)
	secp256k1BaseY.SetByteSlice(gy)
}

// Secp256k1 implements Curve.
func (Secp256k1) Name() string     { return "secp256k1" }
func (Secp256k1) ScalarBytes() int { return secp256k1ScalarSize }
func (Secp256k1) PointBytes() int  { return secp256k1PointSize }

func (Secp256k1) NewScalar() Scalar { return new(secp256k1Scalar) }

func (Secp256k1) NewPoint() Point {
	out := new(secp256k1Point)
	out.value.Z.SetInt(0)
	out.value.X.SetInt(0)
	out.value.Y.SetInt(0)
	return out
}

func (Secp256k1) BasePoint() Point {
	out := new(secp256k1Point)
	out.value.X.Set(&secp256k1BaseX)
	out.value.Y.Set(&secp256k1BaseY)
	out.value.Z.SetInt(1)
	return out
}

// SecondaryGenerator returns H, an independent generator for Pedersen
// commits. Derived deterministically via try-and-increment hash-to-curve
// over a Lens-specific nothing-up-my-sleeve tag.
func (Secp256k1) SecondaryGenerator() Point {
	if !secp256k1HOnce {
		secp256k1H = secp256k1DeriveH()
		secp256k1HOnce = true
	}
	out := new(secp256k1Point)
	out.value.Set(&secp256k1H.value)
	return out
}

func secp256k1DeriveH() *secp256k1Point {
	for ctr := uint64(0); ctr < 1<<20; ctr++ {
		h := sha256.New()
		_, _ = h.Write([]byte("lens.secp256k1.h-base.v1"))
		var ctrBuf [8]byte
		for i := 0; i < 8; i++ {
			ctrBuf[i] = byte(ctr >> (8 * i))
		}
		_, _ = h.Write(ctrBuf[:])
		seed := h.Sum(nil)

		var x secp256k1.FieldVal
		if x.SetByteSlice(seed) {
			continue
		}
		var y secp256k1.FieldVal
		if !secp256k1.DecompressY(&x, false, &y) {
			continue
		}
		out := new(secp256k1Point)
		out.value.X.Set(&x)
		out.value.Y.Set(&y)
		out.value.Z.SetInt(1)
		if out.IsIdentity() {
			continue
		}
		return out
	}
	panic("lens/primitives: secp256k1 H derivation exhausted counter")
}

// SampleScalar draws a uniform scalar in [0, n) via rejection sampling.
func (Secp256k1) SampleScalar(rand io.Reader) (Scalar, error) {
	for i := 0; i < 256; i++ {
		var buf [32]byte
		if _, err := io.ReadFull(rand, buf[:]); err != nil {
			return nil, fmt.Errorf("lens/primitives: secp256k1 sample: %w", err)
		}
		v := new(big.Int).SetBytes(buf[:])
		if v.Sign() != 0 && v.Cmp(secp256k1OrderBig) < 0 {
			s := new(secp256k1Scalar)
			var b [32]byte
			vBytes := v.Bytes()
			copy(b[32-len(vBytes):], vBytes)
			if s.value.SetBytes(&b) != 0 {
				continue
			}
			return s, nil
		}
	}
	return nil, fmt.Errorf("lens/primitives: secp256k1 sample exhausted")
}

// HashToScalar maps a byte string to a scalar via SHA-512 + reduction.
func (Secp256k1) HashToScalar(data []byte) Scalar {
	h := sha256.New()
	_, _ = h.Write([]byte("lens.secp256k1.hash-to-scalar.v1"))
	_, _ = h.Write(data)
	d1 := h.Sum(nil)
	h2 := sha256.New()
	_, _ = h2.Write([]byte("lens.secp256k1.hash-to-scalar.v1.tag2"))
	_, _ = h2.Write(data)
	d2 := h2.Sum(nil)
	wide := append(d1, d2...) // 64-byte uniform string
	v := new(big.Int).SetBytes(wide)
	v.Mod(v, secp256k1OrderBig)

	s := new(secp256k1Scalar)
	var b [32]byte
	vBytes := v.Bytes()
	copy(b[32-len(vBytes):], vBytes)
	s.value.SetBytes(&b)
	return s
}

// secp256k1Scalar wraps secp256k1.ModNScalar.
type secp256k1Scalar struct {
	value secp256k1.ModNScalar
}

func (*secp256k1Scalar) Curve() Curve { return Secp256k1{} }

func (s *secp256k1Scalar) MarshalBinary() ([]byte, error) {
	d := s.value.Bytes()
	return d[:], nil
}

func (s *secp256k1Scalar) UnmarshalBinary(data []byte) error {
	if len(data) != secp256k1ScalarSize {
		return fmt.Errorf("lens/primitives: secp256k1 scalar size %d, want %d", len(data), secp256k1ScalarSize)
	}
	var exact [32]byte
	copy(exact[:], data)
	if s.value.SetBytes(&exact) != 0 {
		return fmt.Errorf("lens/primitives: secp256k1 scalar overflow")
	}
	return nil
}

func (s *secp256k1Scalar) SetBytes(data []byte) error {
	return s.UnmarshalBinary(data)
}

func (s *secp256k1Scalar) SetUint64(v uint64) Scalar {
	var buf [32]byte
	for i := 0; i < 8; i++ {
		buf[31-i] = byte(v >> (8 * i))
	}
	s.value.SetBytes(&buf)
	return s
}

func (s *secp256k1Scalar) Set(other Scalar) Scalar {
	o := other.(*secp256k1Scalar)
	s.value.Set(&o.value)
	return s
}

func (s *secp256k1Scalar) Add(other Scalar) Scalar {
	o := other.(*secp256k1Scalar)
	s.value.Add(&o.value)
	return s
}

func (s *secp256k1Scalar) Sub(other Scalar) Scalar {
	o := other.(*secp256k1Scalar)
	neg := new(secp256k1Scalar)
	neg.value.Set(&o.value)
	neg.value.Negate()
	s.value.Add(&neg.value)
	return s
}

func (s *secp256k1Scalar) Mul(other Scalar) Scalar {
	o := other.(*secp256k1Scalar)
	s.value.Mul(&o.value)
	return s
}

func (s *secp256k1Scalar) Negate() Scalar {
	s.value.Negate()
	return s
}

func (s *secp256k1Scalar) Invert() Scalar {
	s.value.InverseNonConst()
	return s
}

func (s *secp256k1Scalar) IsZero() bool {
	return s.value.IsZero()
}

func (s *secp256k1Scalar) Equal(other Scalar) bool {
	o, ok := other.(*secp256k1Scalar)
	if !ok {
		return false
	}
	return s.value.Equals(&o.value)
}

func (s *secp256k1Scalar) ActOnBase() Point {
	out := new(secp256k1Point)
	secp256k1.ScalarBaseMultNonConst(&s.value, &out.value)
	return out
}

func (s *secp256k1Scalar) Act(p Point) Point {
	pt := p.(*secp256k1Point)
	out := new(secp256k1Point)
	secp256k1.ScalarMultNonConst(&s.value, &pt.value, &out.value)
	return out
}

// secp256k1Point wraps secp256k1.JacobianPoint.
type secp256k1Point struct {
	value secp256k1.JacobianPoint
}

func (*secp256k1Point) Curve() Curve { return Secp256k1{} }

func (p *secp256k1Point) MarshalBinary() ([]byte, error) {
	if p.IsIdentity() {
		out := make([]byte, secp256k1PointSize)
		out[0] = 0x00
		return out, nil
	}
	out := make([]byte, secp256k1PointSize)
	v := p.value
	v.ToAffine()
	out[0] = byte(v.Y.IsOddBit()) + 2
	x := v.X.Bytes()
	copy(out[1:], x[:])
	return out, nil
}

func (p *secp256k1Point) UnmarshalBinary(data []byte) error {
	if len(data) != secp256k1PointSize {
		return fmt.Errorf("lens/primitives: secp256k1 point size %d, want %d", len(data), secp256k1PointSize)
	}
	if data[0] == 0x00 {
		p.value.X.SetInt(0)
		p.value.Y.SetInt(0)
		p.value.Z.SetInt(0)
		return nil
	}
	if data[0] != 0x02 && data[0] != 0x03 {
		return fmt.Errorf("lens/primitives: secp256k1 unrecognized prefix 0x%02x", data[0])
	}
	p.value.Z.SetInt(1)
	if p.value.X.SetByteSlice(data[1:]) {
		return fmt.Errorf("lens/primitives: secp256k1 x out of range")
	}
	if !secp256k1.DecompressY(&p.value.X, data[0] == 3, &p.value.Y) {
		return fmt.Errorf("lens/primitives: secp256k1 x not on curve")
	}
	return nil
}

func (p *secp256k1Point) Add(other Point) Point {
	o := other.(*secp256k1Point)
	if p.IsIdentity() {
		out := new(secp256k1Point)
		out.value.Set(&o.value)
		return out
	}
	if o.IsIdentity() {
		out := new(secp256k1Point)
		out.value.Set(&p.value)
		return out
	}
	out := new(secp256k1Point)
	secp256k1.AddNonConst(&p.value, &o.value, &out.value)
	return out
}

func (p *secp256k1Point) Sub(other Point) Point {
	return p.Add(other.Negate())
}

func (p *secp256k1Point) Negate() Point {
	out := new(secp256k1Point)
	out.value.Set(&p.value)
	out.value.Y.Negate(1)
	out.value.Y.Normalize()
	return out
}

func (p *secp256k1Point) IsIdentity() bool {
	if p == nil {
		return true
	}
	if p.value.Z.IsZero() {
		return true
	}
	return p.value.X.IsZero() && p.value.Y.IsZero()
}

func (p *secp256k1Point) Equal(other Point) bool {
	o, ok := other.(*secp256k1Point)
	if !ok {
		return false
	}
	if p.IsIdentity() && o.IsIdentity() {
		return true
	}
	if p.IsIdentity() != o.IsIdentity() {
		return false
	}
	pa := p.value
	oa := o.value
	pa.ToAffine()
	oa.ToAffine()
	return pa.X.Equals(&oa.X) && pa.Y.Equals(&oa.Y)
}
