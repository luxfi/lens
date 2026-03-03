// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dkg implements distributed FROST-style key generation over
// the curve. No trusted dealer is required: every party samples its
// own secret polynomial f_i, broadcasts Pedersen commits to the
// coefficients, and privately delivers f_i(j) to every other party j.
// Each party j then sums the received shares to form its own share of
// the joint master secret s = Σ_i f_i(0).
//
// Protocol (3 logical rounds; one round-trip pair if pipelined):
//
//	Round 1:
//	  Each party i samples a random polynomial f_i of degree (t-1) and
//	  a matching blinding polynomial r_i. It broadcasts Pedersen
//	  commits C_{i,k} = c_{i,k}·G + r_{i,k}·H to every coefficient.
//
//	Round 2 (private):
//	  Each party i sends (share_{i→j}, blind_{i→j}) = (f_i(j), r_i(j))
//	  to every party j over an authenticated channel.
//
//	Round 3 (verify + aggregate):
//	  Each party j checks every received (share_{i→j}, blind_{i→j})
//	  against the commitment vector C_i. On success, j computes its
//	  final share s_j = Σ_i share_{i→j} and the joint group public key
//	  X = Σ_i C_{i,0} - r_aggregate·H. Equivalently, X = (Σ_i f_i(0))·G,
//	  obtained by aggregating the constant-term commits and subtracting
//	  the aggregate blinding factor (which the parties recover via a
//	  second Pedersen-style commitment opening).
//
// In this implementation we follow the simpler "Pedersen commit to
// public coefficients of f_i alone" path: instead of (G, H)-Pedersen
// commits with a blinding polynomial, every party broadcasts
// commitments to the public coefficient images A_{i,k} = c_{i,k}·G.
// Verification is then share_{i→j}·G ?= Σ_k j^k · A_{i,k}, which is
// the canonical Feldman VSS check. The Pedersen scheme is reserved for
// the resharing path where blinding is required to avoid leaking
// constant-term scalar information across rounds.
package dkg

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/threshold"
)

// Errors returned by the dkg package.
var (
	ErrInvalidThreshold  = errors.New("dkg: threshold must satisfy 1 <= t <= n")
	ErrInvalidPartyCount = errors.New("dkg: need at least 2 parties")
	ErrInvalidPartyID    = errors.New("dkg: party ID out of range")
	ErrShareVerification = errors.New("dkg: share verification failed")
	ErrMissingData       = errors.New("dkg: missing share or commitment data")
)

// Round1Output is the data a party produces in Round 1.
type Round1Output struct {
	// Commits[k] = c_{i,k}·G — public Feldman commitment to the k-th
	// coefficient of f_i.
	Commits []primitives.Point

	// Shares maps recipient party ID j → f_i(j), the secret share for
	// party j.
	Shares map[int]primitives.Scalar
}

// Session tracks the state of one DKG run for a single party.
type Session struct {
	curve   primitives.Curve
	partyID int
	n       int
	t       int

	// Secret polynomial f_i (kept until Round 2 finishes; erased on
	// Finalize).
	poly *primitives.Polynomial
}

// NewSession initializes a DKG session for the given party.
func NewSession(c primitives.Curve, partyID, n, t int) (*Session, error) {
	if n < 2 {
		return nil, ErrInvalidPartyCount
	}
	if t < 1 || t > n {
		return nil, ErrInvalidThreshold
	}
	if partyID < 1 || partyID > n {
		return nil, ErrInvalidPartyID
	}
	return &Session{curve: c, partyID: partyID, n: n, t: t}, nil
}

// Round1 samples the party's secret polynomial f_i, computes the
// public Feldman commitments to its coefficients, and the shares
// f_i(j) for every recipient.
//
// Uses crypto/rand by default. Pass a deterministic source for KAT
// replay.
func (d *Session) Round1(randSource io.Reader) (*Round1Output, error) {
	if randSource == nil {
		randSource = rand.Reader
	}
	// Random secret f_i with f_i(0) = some random scalar (the party's
	// contribution to the joint master secret).
	contribution, err := d.curve.SampleScalar(randSource)
	if err != nil {
		return nil, fmt.Errorf("dkg.Round1: contribution: %w", err)
	}
	poly, err := primitives.NewPolynomial(d.curve, d.t-1, contribution, randSource)
	if err != nil {
		return nil, fmt.Errorf("dkg.Round1: polynomial: %w", err)
	}
	d.poly = poly

	// Feldman commits: A_k = c_k·G.
	coeffs := poly.Coefficients()
	commits := make([]primitives.Point, len(coeffs))
	for k := range coeffs {
		commits[k] = coeffs[k].ActOnBase()
	}

	// Shares f_i(j) for every j ∈ [1, n].
	shares := make(map[int]primitives.Scalar, d.n)
	for j := 1; j <= d.n; j++ {
		x := d.curve.NewScalar().SetUint64(uint64(j))
		shares[j] = poly.Evaluate(x)
	}

	return &Round1Output{Commits: commits, Shares: shares}, nil
}

// Round2 verifies received shares against the senders' commitments
// and produces this party's final aggregated share + the joint group
// public key X = Σ_i A_{i,0}.
//
// receivedShares maps sender party ID i → f_i(this party's ID).
// receivedCommits maps sender party ID i → that sender's Feldman
// commitment vector.
//
// Returns:
//
//   - aggregateShare s_j = Σ_i f_i(j)
//   - groupPublicKey X = Σ_i A_{i,0}
//
// On any verification failure, returns the offending sender's ID in
// the wrapped error.
func (d *Session) Round2(
	receivedShares map[int]primitives.Scalar,
	receivedCommits map[int][]primitives.Point,
) (primitives.Scalar, primitives.Point, error) {
	if len(receivedShares) != d.n {
		return nil, nil, fmt.Errorf("%w: received %d shares, expected %d",
			ErrMissingData, len(receivedShares), d.n)
	}
	if len(receivedCommits) != d.n {
		return nil, nil, fmt.Errorf("%w: received %d commits, expected %d",
			ErrMissingData, len(receivedCommits), d.n)
	}

	x := d.curve.NewScalar().SetUint64(uint64(d.partyID))

	for i := 1; i <= d.n; i++ {
		share, ok := receivedShares[i]
		if !ok {
			return nil, nil, fmt.Errorf("%w: missing share from party %d", ErrMissingData, i)
		}
		commits, ok := receivedCommits[i]
		if !ok {
			return nil, nil, fmt.Errorf("%w: missing commits from party %d", ErrMissingData, i)
		}
		if len(commits) != d.t {
			return nil, nil, fmt.Errorf("%w: party %d sent %d commits, expected %d",
				ErrShareVerification, i, len(commits), d.t)
		}

		// Feldman check: share·G ?= Σ_k x^k · A_k via Horner.
		lhs := share.ActOnBase()
		rhs := d.curve.NewPoint()
		for k := len(commits) - 1; k >= 0; k-- {
			rhs = x.Act(rhs)
			rhs = rhs.Add(commits[k])
		}
		if !lhs.Equal(rhs) {
			return nil, nil, fmt.Errorf("%w: party %d", ErrShareVerification, i)
		}
	}

	// Aggregate share s_j = Σ_i f_i(j).
	s := d.curve.NewScalar()
	for i := 1; i <= d.n; i++ {
		s.Add(receivedShares[i])
	}

	// Joint group public key X = Σ_i A_{i,0}.
	X := d.curve.NewPoint()
	for i := 1; i <= d.n; i++ {
		X = X.Add(receivedCommits[i][0])
	}

	// Erase the local secret polynomial.
	for _, c := range d.poly.Coefficients() {
		c.Set(d.curve.NewScalar())
	}
	d.poly = nil

	return s, X, nil
}

// Run is a single-process driver that runs all n parties through
// Round 1 and Round 2 and returns the per-party KeyShare set + the
// resulting GroupKey. It is the in-process integration test path; in
// a distributed deployment, each party runs its Session locally and
// exchanges Round1Output messages over the wire.
//
// Returns one *threshold.KeyShare per party (1-indexed), all sharing
// the same GroupKey pointer.
func Run(c primitives.Curve, n, t int, randSource io.Reader) (map[int]*threshold.KeyShare, *threshold.GroupKey, error) {
	if randSource == nil {
		randSource = rand.Reader
	}
	if n < 2 {
		return nil, nil, ErrInvalidPartyCount
	}
	if t < 1 || t > n {
		return nil, nil, ErrInvalidThreshold
	}

	sessions := make(map[int]*Session, n)
	round1 := make(map[int]*Round1Output, n)
	for j := 1; j <= n; j++ {
		s, err := NewSession(c, j, n, t)
		if err != nil {
			return nil, nil, fmt.Errorf("dkg.Run: NewSession %d: %w", j, err)
		}
		sessions[j] = s
		out, err := s.Round1(randSource)
		if err != nil {
			return nil, nil, fmt.Errorf("dkg.Run: party %d Round1: %w", j, err)
		}
		round1[j] = out
	}

	// Aggregate views per receiver.
	groupKey := (*threshold.GroupKey)(nil)
	keyShares := make(map[int]*threshold.KeyShare, n)
	signerIDs := make([]int, n)
	for j := 1; j <= n; j++ {
		signerIDs[j-1] = j
	}
	lambda, err := primitives.Lagrange(c, signerIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("dkg.Run: lagrange: %w", err)
	}

	for j := 1; j <= n; j++ {
		recvShares := make(map[int]primitives.Scalar, n)
		recvCommits := make(map[int][]primitives.Point, n)
		for i := 1; i <= n; i++ {
			recvShares[i] = round1[i].Shares[j]
			recvCommits[i] = round1[i].Commits
		}
		s, X, err := sessions[j].Round2(recvShares, recvCommits)
		if err != nil {
			return nil, nil, fmt.Errorf("dkg.Run: party %d Round2: %w", j, err)
		}
		if groupKey == nil {
			groupKey = threshold.NewGroupKey(c, X)
		} else {
			if !groupKey.X.Equal(X) {
				return nil, nil, fmt.Errorf("dkg.Run: party %d disagreed on group key X", j)
			}
		}
		keyShares[j] = &threshold.KeyShare{
			Index:             j - 1,
			PartyID:           j,
			SkShare:           s,
			VerificationShare: s.ActOnBase(),
			Lambda:            lambda[j],
			GroupKey:          groupKey,
		}
	}
	return keyShares, groupKey, nil
}
