// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package sign implements the FROST 2-round Schnorr threshold signing
// protocol (RFC 9591). The math is upstream-equivalent — the only
// Lens-specific decisions are:
//
//   - Domain-separation tags for the binding factor and challenge
//     ("LENS-RHO-v1", "LENS-CHALLENGE-v1") so that a Lens signature
//     cannot be replayed under any other Schnorr profile.
//   - The hash transcript uses BLAKE3 over canonical point and party-ID
//     encodings to match the Lens hash suite contract.
//
// Round 1: every party samples (d_i, e_i), broadcasts (D_i = d_i·G,
//
//	E_i = e_i·G).
//
// Round 2: every party computes
//   - the binding factors ρ_i = H_rho(message, B, i)
//   - R_shares[i] = D_i + ρ_i · E_i
//   - R = Σ R_shares[l]
//   - challenge c = H_c(R, X, message)
//   - z_i = d_i + ρ_i · e_i + λ_i · s_i · c
//
// and broadcasts z_i.
// Aggregate: any party computes z = Σ z_l. (R, z) is a Schnorr
// signature under the unchanged group public key X.
//
// The Verify routine takes the canonical (R, z) signature, recomputes
// c, and checks z·G ?= R + c·X.
package sign

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/threshold"

	"github.com/zeebo/blake3"
)

// Domain-separation tags for FROST signing on Lens. Distinct from
// dkg / reshare / activation tags so a Lens Sign transcript can never
// collide with any other Lens transcript on the byte level.
const (
	tagNonceDerive = "lens.sign.nonce-derive.v1"
	tagBindingRho  = "QUASAR-LENS-SIGN1-v1"
	tagChallenge   = "QUASAR-LENS-SIGN2-v1"
	tagAggregate   = "QUASAR-LENS-AGGREGATE-v1"
)

// Errors returned by the sign package.
var (
	ErrIdentityCommit    = errors.New("sign: nonce commitment is the identity point")
	ErrSignerSetMismatch = errors.New("sign: signer set mismatch between rounds")
	ErrMissingCommit     = errors.New("sign: missing commit from signer")
	ErrMissingResponse   = errors.New("sign: missing response from signer")
	ErrInvalidResponse   = errors.New("sign: partial response failed verification")
	ErrInvalidSignature  = errors.New("sign: signature failed Schnorr verification")
)

// CommitMsg is one signer's Round-1 broadcast.
type CommitMsg struct {
	PartyID int
	D       primitives.Point
	E       primitives.Point
}

// ResponseMsg is one signer's Round-2 broadcast.
type ResponseMsg struct {
	PartyID int
	Z       primitives.Scalar
}

// Signature is the aggregated Schnorr signature.
type Signature struct {
	R primitives.Point
	Z primitives.Scalar
}

// Bytes returns the canonical serialization of the signature
// (R || Z, fixed-width).
func (sig *Signature) Bytes() ([]byte, error) {
	if sig == nil || sig.R == nil || sig.Z == nil {
		return nil, errors.New("sign: nil signature")
	}
	rb, err := sig.R.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("sign: R marshal: %w", err)
	}
	zb, err := sig.Z.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("sign: Z marshal: %w", err)
	}
	out := make([]byte, 0, len(rb)+len(zb))
	out = append(out, rb...)
	out = append(out, zb...)
	return out, nil
}

// Signer holds the per-round state of one party in the FROST signing
// protocol.
type Signer struct {
	share *threshold.KeyShare
	curve primitives.Curve

	// Round-1 state
	dI     primitives.Scalar
	eI     primitives.Scalar
	commit *CommitMsg

	// Cached canonical signer ordering and binding factors after Round 2.
	signers []int
}

// NewSigner constructs a Signer from a KeyShare. The Lambda field on
// the share is used during Round 2 — it MUST be set to the Lagrange
// coefficient λ_i evaluated at 0 over the current signing set.
func NewSigner(share *threshold.KeyShare) *Signer {
	if share == nil || share.GroupKey == nil {
		return nil
	}
	return &Signer{
		share: share,
		curve: share.GroupKey.Curve,
	}
}

// Round1 produces the (d_i, e_i) nonces and (D_i, E_i) commitments for
// this signer. The CommitMsg is broadcast to every signer in the set.
//
// The randomness is hedged: a deterministic component derived from the
// secret share + message + signer set, XORed with fresh randomness
// from `rand`. This protects against bad randomness without sacrificing
// determinism for KAT replay (use a deterministic `rand` for replay).
func (s *Signer) Round1(message []byte, signers []int, randSource io.Reader) (*CommitMsg, error) {
	if randSource == nil {
		randSource = rand.Reader
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("sign.Round1: empty signer set")
	}
	sortedSigners := append([]int(nil), signers...)
	sort.Ints(sortedSigners)
	s.signers = sortedSigners

	// Hedged nonce derivation: H(tag || sk_i || party_id || message ||
	// signers || rand_bytes) → 64-byte stream → two scalars.
	skBytes, err := s.share.SkShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("sign.Round1: skShare marshal: %w", err)
	}

	h := blake3.New()
	_, _ = h.Write([]byte(tagNonceDerive))
	_, _ = h.Write(skBytes)
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], uint64(s.share.PartyID))
	_, _ = h.Write(u8[:])
	binary.BigEndian.PutUint32(u8[:4], uint32(len(message)))
	_, _ = h.Write(u8[:4])
	_, _ = h.Write(message)
	binary.BigEndian.PutUint32(u8[:4], uint32(len(sortedSigners)))
	_, _ = h.Write(u8[:4])
	for _, id := range sortedSigners {
		binary.BigEndian.PutUint32(u8[:4], uint32(id))
		_, _ = h.Write(u8[:4])
	}
	saltLen := 32
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(randSource, salt); err != nil {
		return nil, fmt.Errorf("sign.Round1: salt: %w", err)
	}
	_, _ = h.Write(salt)

	xof := h.Digest()
	dI, err := s.curve.SampleScalar(xof)
	if err != nil {
		return nil, fmt.Errorf("sign.Round1: dI: %w", err)
	}
	eI, err := s.curve.SampleScalar(xof)
	if err != nil {
		return nil, fmt.Errorf("sign.Round1: eI: %w", err)
	}
	if dI.IsZero() || eI.IsZero() {
		return nil, fmt.Errorf("sign.Round1: zero nonce")
	}
	s.dI = dI
	s.eI = eI

	D := dI.ActOnBase()
	E := eI.ActOnBase()
	if D.IsIdentity() || E.IsIdentity() {
		return nil, ErrIdentityCommit
	}
	s.commit = &CommitMsg{PartyID: s.share.PartyID, D: D, E: E}
	return s.commit, nil
}

// Round2 consumes the collected Round-1 commits, computes the binding
// factor + challenge, and produces the partial response z_i.
func (s *Signer) Round2(message []byte, commits map[int]*CommitMsg) (*ResponseMsg, error) {
	if s.dI == nil || s.eI == nil {
		return nil, fmt.Errorf("sign.Round2: Round1 was not run")
	}
	if len(s.signers) == 0 {
		return nil, fmt.Errorf("sign.Round2: empty signer set")
	}
	for _, id := range s.signers {
		c, ok := commits[id]
		if !ok || c == nil || c.D == nil || c.E == nil {
			return nil, fmt.Errorf("%w: %d", ErrMissingCommit, id)
		}
		if c.D.IsIdentity() || c.E.IsIdentity() {
			return nil, ErrIdentityCommit
		}
	}

	rho, R, err := computeBindingAndR(s.curve, message, s.signers, commits)
	if err != nil {
		return nil, fmt.Errorf("sign.Round2: %w", err)
	}

	c := computeChallenge(s.curve, R, s.share.GroupKey.X, message)

	// z_i = d_i + ρ_i · e_i + λ_i · s_i · c
	myRho := rho[s.share.PartyID]
	if myRho == nil {
		return nil, fmt.Errorf("sign.Round2: missing self rho for %d", s.share.PartyID)
	}
	eRho := s.curve.NewScalar().Set(s.eI).Mul(myRho)
	lamSc := s.curve.NewScalar().Set(s.share.Lambda).Mul(s.share.SkShare).Mul(c)

	zI := s.curve.NewScalar().Set(s.dI)
	zI.Add(eRho)
	zI.Add(lamSc)

	return &ResponseMsg{PartyID: s.share.PartyID, Z: zI}, nil
}

// Aggregate combines the Round-1 commits and Round-2 responses into a
// final (R, z) Schnorr signature under the GroupKey. Any signer can
// run this — the result is byte-identical regardless of who computes it.
func Aggregate(
	gk *threshold.GroupKey,
	message []byte,
	signers []int,
	commits map[int]*CommitMsg,
	responses map[int]*ResponseMsg,
	verShares map[int]primitives.Point,
) (*Signature, error) {
	if gk == nil {
		return nil, fmt.Errorf("sign.Aggregate: nil group key")
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("sign.Aggregate: empty signer set")
	}
	sorted := append([]int(nil), signers...)
	sort.Ints(sorted)

	for _, id := range sorted {
		if commits[id] == nil {
			return nil, fmt.Errorf("%w: %d", ErrMissingCommit, id)
		}
		if responses[id] == nil {
			return nil, fmt.Errorf("%w: %d", ErrMissingResponse, id)
		}
	}

	rho, R, err := computeBindingAndR(gk.Curve, message, sorted, commits)
	if err != nil {
		return nil, fmt.Errorf("sign.Aggregate: %w", err)
	}
	c := computeChallenge(gk.Curve, R, gk.X, message)

	// Verify each partial: z_i·G ?= D_i + ρ_i·E_i + (λ_i · c) · X_i.
	lambda, err := primitives.Lagrange(gk.Curve, sorted)
	if err != nil {
		return nil, fmt.Errorf("sign.Aggregate: lagrange: %w", err)
	}
	for _, id := range sorted {
		zG := responses[id].Z.ActOnBase()
		eRho := rho[id].Act(commits[id].E)
		dPlusERho := commits[id].D.Add(eRho)

		var Xi primitives.Point
		if verShares != nil {
			Xi = verShares[id]
		}
		if Xi != nil {
			lamC := gk.Curve.NewScalar().Set(lambda[id]).Mul(c)
			lamCX := lamC.Act(Xi)
			expected := dPlusERho.Add(lamCX)
			if !zG.Equal(expected) {
				return nil, fmt.Errorf("%w: %d", ErrInvalidResponse, id)
			}
		}
	}

	z := gk.Curve.NewScalar()
	for _, id := range sorted {
		z.Add(responses[id].Z)
	}
	return &Signature{R: R, Z: z}, nil
}

// Verify checks a (R, z) Schnorr signature against `message` under the
// group public key in `gk`. Returns nil if valid.
func Verify(gk *threshold.GroupKey, message []byte, sig *Signature) error {
	if gk == nil || sig == nil {
		return ErrInvalidSignature
	}
	c := computeChallenge(gk.Curve, sig.R, gk.X, message)

	// LHS: z·G
	lhs := sig.Z.ActOnBase()
	// RHS: R + c·X
	cX := c.Act(gk.X)
	rhs := sig.R.Add(cX)
	if !lhs.Equal(rhs) {
		return ErrInvalidSignature
	}
	return nil
}

// computeBindingAndR derives the per-party binding factor ρ_i for each
// signer and the joint commitment R = Σ (D_i + ρ_i·E_i).
func computeBindingAndR(
	c primitives.Curve,
	message []byte,
	signers []int,
	commits map[int]*CommitMsg,
) (map[int]primitives.Scalar, primitives.Point, error) {
	preHash := blake3.New()
	_, _ = preHash.Write([]byte(tagBindingRho))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(message)))
	_, _ = preHash.Write(lenBuf[:])
	_, _ = preHash.Write(message)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(signers)))
	_, _ = preHash.Write(lenBuf[:])
	for _, l := range signers {
		var idBuf [4]byte
		binary.BigEndian.PutUint32(idBuf[:], uint32(l))
		_, _ = preHash.Write(idBuf[:])
		dB, _ := commits[l].D.MarshalBinary()
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(dB)))
		_, _ = preHash.Write(lenBuf[:])
		_, _ = preHash.Write(dB)
		eB, _ := commits[l].E.MarshalBinary()
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(eB)))
		_, _ = preHash.Write(lenBuf[:])
		_, _ = preHash.Write(eB)
	}
	preDigest := preHash.Sum(nil)

	rho := make(map[int]primitives.Scalar, len(signers))
	for _, l := range signers {
		h := blake3.New()
		_, _ = h.Write([]byte(tagBindingRho))
		_, _ = h.Write(preDigest)
		var idBuf [4]byte
		binary.BigEndian.PutUint32(idBuf[:], uint32(l))
		_, _ = h.Write(idBuf[:])
		// Wide reduction: pull 64 bytes of XOF.
		var wide [64]byte
		_, _ = io.ReadFull(h.Digest(), wide[:])
		rho[l] = c.HashToScalar(wide[:])
	}

	R := c.NewPoint()
	for _, l := range signers {
		eRho := rho[l].Act(commits[l].E)
		R = R.Add(commits[l].D).Add(eRho)
	}
	return rho, R, nil
}

// computeChallenge derives c = H(R, X, message) → scalar.
func computeChallenge(c primitives.Curve, R, X primitives.Point, message []byte) primitives.Scalar {
	h := blake3.New()
	_, _ = h.Write([]byte(tagChallenge))
	rb, _ := R.MarshalBinary()
	xb, _ := X.MarshalBinary()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(rb)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(rb)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(xb)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(xb)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(message)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(message)
	var wide [64]byte
	_, _ = io.ReadFull(h.Digest(), wide[:])
	return c.HashToScalar(wide[:])
}
