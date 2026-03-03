// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package threshold defines the public types Lens exposes for a
// threshold-signing group: GroupKey, KeyShare, Signer, Signature.
//
// A Lens GroupKey is the persistent public key of one threshold group
// over one elliptic curve. The key consists of:
//
//   - X — the group public key (the discrete-log image of the master
//     secret s under G).
//   - G — the curve's base generator.
//   - H — the secondary Pedersen generator (independent of G).
//
// The same (G, H, X) survives every Refresh / Reshare within a key era.
// Reanchor (rare governance event) opens a new era with a fresh X.
//
// A KeyShare is one validator's view of the group key. It carries:
//
//   - Index           — 0-indexed position in the new committee.
//   - PartyID         — 1-indexed Shamir evaluation point (= Index+1).
//   - SkShare         — the validator's secret-key Shamir share.
//   - VerificationShare — X·s_i = sum of (verification commits) for this party.
//   - Lambda          — Lagrange coefficient λ_i evaluated at 0 for the
//     validator's set (cached for the signing path).
//   - Seeds, MACKeys  — per-pair PRF / MAC material for the new committee.
//   - GroupKey        — pointer back to the persistent group key.
//
// A Signer wraps a KeyShare and exposes the FROST 2-round signing
// protocol (RFC 9591) plus a one-shot helper for testing.
package threshold

import (
	"errors"
	"fmt"

	"github.com/luxfi/lens/primitives"
)

// Errors returned by the threshold package.
var (
	ErrInvalidThreshold  = errors.New("threshold: t must satisfy 1 <= t <= n")
	ErrInvalidPartyCount = errors.New("threshold: need at least 2 parties")
	ErrInvalidPartyIndex = errors.New("threshold: party index out of range")
	ErrShareMissing      = errors.New("threshold: share missing")
	ErrInsufficientData  = errors.New("threshold: insufficient round data")
	ErrCurveMismatch     = errors.New("threshold: curve mismatch")
)

// GroupKey holds the persistent public parameters for one threshold
// group:
//
//	G       — base generator of the curve.
//	H       — secondary Pedersen generator (independent of G).
//	X       — group public key, X = s·G where s is the (hidden) master
//	          secret.
//	Curve   — the curve identity. (G, H) are stored for fast access; on
//	          deserialization they can be re-derived from Curve.
//
// Within a key era the GroupKey is byte-identical across every Refresh
// / Reshare. Reanchor opens a new GroupKey.
type GroupKey struct {
	Curve primitives.Curve
	G     primitives.Point
	H     primitives.Point
	X     primitives.Point
}

// NewGroupKey constructs a GroupKey from a freshly-sampled curve and
// the supplied master public key X. (G, H) are derived from the curve
// directly.
func NewGroupKey(c primitives.Curve, X primitives.Point) *GroupKey {
	return &GroupKey{
		Curve: c,
		G:     c.BasePoint(),
		H:     c.SecondaryGenerator(),
		X:     X,
	}
}

// Bytes returns the canonical serialization of the GroupKey.
//
// Layout: curveName(uvarint-prefixed) || X(point-bytes).
// (G and H are not serialized — they are derived from the curve.)
func (gk *GroupKey) Bytes() []byte {
	if gk == nil || gk.X == nil {
		return nil
	}
	xb, err := gk.X.MarshalBinary()
	if err != nil {
		return nil
	}
	name := []byte(gk.Curve.Name())
	out := make([]byte, 0, 1+len(name)+len(xb))
	out = append(out, byte(len(name)))
	out = append(out, name...)
	out = append(out, xb...)
	return out
}

// KeyShare holds one validator's view of the group key.
type KeyShare struct {
	// Index is the 0-indexed position of this party in the current
	// committee. The Shamir evaluation point is Index+1.
	Index int

	// PartyID is the 1-indexed Shamir evaluation point. Always equal
	// to Index+1; carried explicitly because some callers (LSS adapter)
	// know only the wire-identity string and need the numeric ID.
	PartyID int

	// SkShare is the secret-key Shamir share s_i = f(PartyID).
	SkShare primitives.Scalar

	// VerificationShare is X_i = s_i·G — the public commitment to
	// SkShare. Used during signing to validate partial responses.
	VerificationShare primitives.Point

	// Lambda is λ_i evaluated at 0 for the current signing set,
	// cached for fast Sign1/Sign2.
	Lambda primitives.Scalar

	// Seeds[i][j] holds per-pair PRF seeds for the new committee.
	// Symmetric across (i, j) for off-diagonal entries; the diagonal
	// holds party-i's local seed.
	Seeds map[int][][]byte

	// MACKeys[j] holds the symmetric MAC key shared with party j.
	// Present for j != Index.
	MACKeys map[int][]byte

	// GroupKey is a back-pointer to the persistent group key. All
	// shares within an era share the same pointer.
	GroupKey *GroupKey
}

// CheckConsistency verifies that the KeyShare's VerificationShare
// equals SkShare·G — i.e. SkShare and VerificationShare were generated
// from the same secret. Returns nil if consistent.
func (ks *KeyShare) CheckConsistency() error {
	if ks == nil || ks.SkShare == nil || ks.VerificationShare == nil {
		return ErrShareMissing
	}
	expected := ks.SkShare.ActOnBase()
	if !expected.Equal(ks.VerificationShare) {
		return fmt.Errorf("threshold: VerificationShare != SkShare·G")
	}
	return nil
}

// VerificationShares returns the public verification share map keyed by
// 1-indexed PartyID for the supplied list of shares. Used by the
// signing protocol to reconstruct partial commitments.
func VerificationShares(shares map[int]*KeyShare) map[int]primitives.Point {
	out := make(map[int]primitives.Point, len(shares))
	for pid, ks := range shares {
		out[pid] = ks.VerificationShare
	}
	return out
}
