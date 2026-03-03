// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// curveCases is the list of curves every shared test runs over.
var curveCases = []struct {
	name  string
	curve Curve
}{
	{"ed25519", NewEd25519()},
	{"secp256k1", NewSecp256k1()},
	{"ristretto255", NewRistretto255()},
}

// TestScalarArithmetic exercises Add/Sub/Mul/Negate/Invert/IsZero on
// each curve's scalar field.
func TestScalarArithmetic(t *testing.T) {
	for _, tc := range curveCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.curve

			// 0 + 0 == 0
			z := c.NewScalar()
			if !z.IsZero() {
				t.Fatal("NewScalar should return zero")
			}

			a, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("SampleScalar: %v", err)
			}
			if a.IsZero() {
				t.Fatal("sampled scalar collided with zero")
			}

			// a - a == 0
			diff := c.NewScalar().Set(a).Sub(a)
			if !diff.IsZero() {
				t.Fatal("a - a != 0")
			}

			// a + (-a) == 0
			negA := c.NewScalar().Set(a).Negate()
			sum := c.NewScalar().Set(a).Add(negA)
			if !sum.IsZero() {
				t.Fatal("a + (-a) != 0")
			}

			// a · a^-1 == 1
			one := c.NewScalar().SetUint64(1)
			inv := c.NewScalar().Set(a).Invert()
			prod := c.NewScalar().Set(a).Mul(inv)
			if !prod.Equal(one) {
				t.Fatal("a · a^-1 != 1")
			}
		})
	}
}

// TestScalarSerialization round-trips a sampled scalar through
// Marshal/Unmarshal.
func TestScalarSerialization(t *testing.T) {
	for _, tc := range curveCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.curve
			a, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("SampleScalar: %v", err)
			}
			data, err := a.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if got := len(data); got != c.ScalarBytes() {
				t.Fatalf("scalar marshal length %d, want %d", got, c.ScalarBytes())
			}

			b := c.NewScalar()
			if err := b.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			if !a.Equal(b) {
				t.Fatal("round-tripped scalar differs from original")
			}
		})
	}
}

// TestPointArithmetic exercises Add/Negate/Equal/IsIdentity on each curve.
func TestPointArithmetic(t *testing.T) {
	for _, tc := range curveCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.curve

			id := c.NewPoint()
			if !id.IsIdentity() {
				t.Fatal("NewPoint not identity")
			}

			a, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("SampleScalar: %v", err)
			}
			A := a.ActOnBase()

			// A + (-A) == identity
			negA := A.Negate()
			diff := A.Add(negA)
			if !diff.IsIdentity() {
				t.Fatal("A + (-A) != identity")
			}

			// A - A == identity (Sub agrees with Add+Negate).
			diff2 := A.Sub(A)
			if !diff2.IsIdentity() {
				t.Fatal("A - A != identity")
			}

			// G + G == 2·G computed two ways.
			two := c.NewScalar().SetUint64(2)
			doubleG := two.ActOnBase()
			G := c.BasePoint()
			GpG := G.Add(G)
			if !doubleG.Equal(GpG) {
				t.Fatal("G + G != 2·G")
			}
		})
	}
}

// TestPointSerialization round-trips a sampled point through
// Marshal/Unmarshal.
func TestPointSerialization(t *testing.T) {
	for _, tc := range curveCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.curve
			a, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("SampleScalar: %v", err)
			}
			A := a.ActOnBase()
			data, err := A.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if got := len(data); got != c.PointBytes() {
				t.Fatalf("point marshal length %d, want %d", got, c.PointBytes())
			}
			B := c.NewPoint()
			if err := B.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			if !A.Equal(B) {
				t.Fatal("round-tripped point differs from original")
			}
		})
	}
}

// TestSecondaryGenerator confirms H is a deterministic, non-identity
// point distinct from G on every curve.
func TestSecondaryGenerator(t *testing.T) {
	for _, tc := range curveCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.curve
			H := c.SecondaryGenerator()
			if H.IsIdentity() {
				t.Fatal("H is identity")
			}
			if H.Equal(c.BasePoint()) {
				t.Fatal("H equals G — violates Pedersen binding assumption")
			}
			// Determinism: two calls produce equal points.
			H2 := c.SecondaryGenerator()
			if !H.Equal(H2) {
				t.Fatal("SecondaryGenerator not deterministic")
			}
			// Marshalled representation is stable.
			d1, _ := H.MarshalBinary()
			d2, _ := H2.MarshalBinary()
			if !bytes.Equal(d1, d2) {
				t.Fatal("SecondaryGenerator marshalling not stable")
			}
		})
	}
}

// TestHashToScalar produces non-zero, deterministic scalars.
func TestHashToScalar(t *testing.T) {
	for _, tc := range curveCases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.curve
			a := c.HashToScalar([]byte("lens-test"))
			b := c.HashToScalar([]byte("lens-test"))
			if !a.Equal(b) {
				t.Fatal("HashToScalar not deterministic")
			}
			if a.IsZero() {
				t.Fatal("HashToScalar produced zero")
			}
			d := c.HashToScalar([]byte("different"))
			if a.Equal(d) {
				t.Fatal("HashToScalar collided on distinct inputs")
			}
		})
	}
}
