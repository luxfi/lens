// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package primitives provides the curve abstraction Lens uses for all
// elliptic-curve-based threshold operations.
//
// The package is deliberately small. Three concrete curves are shipped:
//
//   - Ed25519        — RFC 8032 / FIPS 186-5 EdDSA curve (filippo.io/edwards25519)
//   - secp256k1      — SEC 2 / Bitcoin curve (decred/dcrd/dcrec/secp256k1)
//   - Ristretto255   — RFC 9496 prime-order group over Curve25519 (gtank/ristretto255)
//
// All three implement the [Curve] interface below. Two curves never share
// Scalar / Point types — each curve owns its concrete types and casts
// internally; the interfaces exist so generic threshold code can treat
// them uniformly.
//
// # Why a separate curve package
//
// Lens deliberately does NOT depend on github.com/luxfi/threshold for
// curve operations: the Lens kernel must be importable by the LSS-Lens
// adapter inside the threshold module without creating a circular
// dependency. The curve interface is small enough that re-implementing
// it costs less than the dependency tangle.
//
// # No bias, no leakage
//
// Scalar sampling rejects until the drawn bytes interpret to a value in
// [0, order). Point operations never panic on invalid inputs — they
// return errors that propagate to the protocol layer.
package primitives

import (
	"encoding"
	"io"
)

// Curve is the abstract elliptic-curve group Lens operates on. Each
// concrete implementation pins one curve identity (Ed25519, secp256k1,
// Ristretto255) and carries the corresponding Scalar / Point types.
type Curve interface {
	// Name returns the curve identifier (e.g. "ed25519",
	// "secp256k1", "ristretto255"). Used in transcript binding and
	// activation cert serialization. MUST be unique across curves.
	Name() string

	// ScalarBytes returns the canonical byte length of an encoded
	// Scalar.
	ScalarBytes() int

	// PointBytes returns the canonical byte length of an encoded Point.
	PointBytes() int

	// NewScalar returns the additive identity (zero) Scalar.
	NewScalar() Scalar

	// NewPoint returns the identity Point.
	NewPoint() Point

	// BasePoint returns the canonical generator G of the prime-order
	// subgroup of the curve.
	BasePoint() Point

	// SecondaryGenerator returns the canonical Pedersen-binding
	// generator H. H is independent of G — neither is a known scalar
	// multiple of the other. Derived deterministically per curve via
	// hash-to-curve from a domain-separated nothing-up-my-sleeve tag
	// (see lens.<curve>.h-base.v1 in the per-curve implementation).
	SecondaryGenerator() Point

	// SampleScalar draws a uniform Scalar in [0, order) from rand.
	// Uses rejection sampling so the distribution is unbiased.
	SampleScalar(rand io.Reader) (Scalar, error)

	// HashToScalar maps the byte string `data` to a Scalar via a
	// curve-specific domain-separated wide-reduction hash. Output
	// distribution is statistically indistinguishable from uniform on
	// [0, order).
	HashToScalar(data []byte) Scalar
}

// Scalar is a value modulo the curve's group order. Operations are
// constant-time where the underlying implementation supports it.
//
// The operations mutate the receiver and return it for chaining,
// mirroring filippo.io/edwards25519 and threshold's curve.Scalar
// conventions. To preserve a value across an operation, copy it first
// via Set on a fresh NewScalar.
type Scalar interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler

	// Curve returns the curve this scalar belongs to.
	Curve() Curve

	// Set copies other into the receiver and returns the receiver.
	Set(other Scalar) Scalar

	// SetBytes interprets `bytes` (big-endian, padded to ScalarBytes())
	// as a value mod the group order and assigns it. Returns an error
	// if `bytes` has the wrong length.
	SetBytes(bytes []byte) error

	// SetUint64 assigns the receiver to the value `v`.
	SetUint64(v uint64) Scalar

	// Add computes receiver = receiver + other (mod order) and returns
	// the receiver.
	Add(other Scalar) Scalar

	// Sub computes receiver = receiver - other (mod order) and returns
	// the receiver.
	Sub(other Scalar) Scalar

	// Mul computes receiver = receiver * other (mod order) and returns
	// the receiver.
	Mul(other Scalar) Scalar

	// Negate computes receiver = -receiver (mod order) and returns the
	// receiver.
	Negate() Scalar

	// Invert computes receiver = receiver^-1 (mod order) and returns
	// the receiver. If receiver is zero, the result is undefined and
	// the implementation may panic — callers MUST check IsZero first
	// or guarantee non-zero by construction.
	Invert() Scalar

	// IsZero returns true iff the receiver is the additive identity.
	IsZero() bool

	// Equal returns true iff receiver == other in constant time.
	Equal(other Scalar) bool

	// ActOnBase returns receiver * G (the base point), without
	// mutating the receiver.
	ActOnBase() Point

	// Act returns receiver * P, without mutating either input.
	Act(p Point) Point
}

// Point is an element of the curve group. Point operations are
// non-mutating — every method returns a fresh point.
type Point interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler

	// Curve returns the curve this point belongs to.
	Curve() Curve

	// Add returns receiver + other (group operation).
	Add(other Point) Point

	// Sub returns receiver - other.
	Sub(other Point) Point

	// Negate returns -receiver.
	Negate() Point

	// IsIdentity returns true iff this is the identity element.
	IsIdentity() bool

	// Equal returns true iff receiver == other.
	Equal(other Point) bool
}
