// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

// Pedersen polynomial commitments for VSR over the curve.
//
// The Reshare kernel in reshare.go gives the arithmetic core of
// Desmedt-Jajodia '97. To make Reshare verifiable in a permissionless
// setting we also commit each old party i's resharing polynomial
// g_i(X) and let the new committee verify the values g_i(β_j) it
// receives against the commitment. The same commitment scheme covers
// Refresh's z_i(X).
//
// Public commitment to f_i(X) = c_{i,0} + c_{i,1}·X + ... + c_{i,t-1}·X^{t-1}:
//
//	C_{i,k} = c_{i,k}·G + r_{i,k}·H
//
// where G is the curve's base point and H is the curve's secondary
// generator (lens.<curve>.h-base.v1 nothing-up-my-sleeve point).
//
// The recipient at evaluation point x verifies its (share, blind) pair
// against the commitment vector via:
//
//	share·G + blind·H ?= Σ_{k=0..t-1} x^k · C_{i,k}

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/luxfi/lens/hash"
	"github.com/luxfi/lens/primitives"
)

// Errors specific to commitment verification.
var (
	ErrCommitMismatch      = errors.New("reshare: commitment verification failed")
	ErrCommitWrongLength   = errors.New("reshare: commit vector has wrong length")
	ErrInconsistentDigests = errors.New("reshare: cross-recipient commit digest mismatch")
)

// CommitToPoly produces the t Pedersen commitments to the secret-poly
// coefficients c_k together with the matching blinding-poly
// coefficients r_k.
func CommitToPoly(
	c primitives.Curve,
	secretCoeffs, blindCoeffs []primitives.Scalar,
) ([]primitives.Point, error) {
	return primitives.PedersenVectorCommit(c, secretCoeffs, blindCoeffs)
}

// VerifyShareAgainstCommits checks the recipient-side equation
//
//	share·G + blind·H ?= Σ_{k=0..t-1} x^k · C_k
func VerifyShareAgainstCommits(
	c primitives.Curve,
	share, blind primitives.Scalar,
	commits []primitives.Point,
	x primitives.Scalar,
) error {
	return primitives.VerifyPedersenShare(c, share, blind, commits, x)
}

// CommitDigest returns the canonical 32-byte digest over a commit
// vector under the supplied HashSuite. suite=nil resolves to the
// production default (Lens-SHA3).
func CommitDigest(commits []primitives.Point, suite hash.HashSuite) [32]byte {
	s := hash.Resolve(suite)
	parts := make([][]byte, 0, 1+len(commits))
	parts = append(parts, []byte("lens.reshare.commit-digest.v1"))
	for _, p := range commits {
		var buf bytes.Buffer
		bytes, _ := p.MarshalBinary()
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(bytes)))
		buf.Write(lenBuf[:])
		buf.Write(bytes)
		parts = append(parts, buf.Bytes())
	}
	return s.TranscriptHash(parts...)
}
