// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

// Complaint workflow and disqualification logic for VSR.
//
// During Round 1, every old (or refresh-participating) party i
// broadcasts its commitment vector C_i and privately delivers
// (share_{i→j}, blind_{i→j}) to every recipient j. In Round 1.5,
// every recipient j independently runs VerifyShareAgainstCommits — if
// any check fails, j emits a signed Complaint naming sender i and the
// failing slot.
//
// The complaint workflow exists for three failure modes:
//
//  (a) Bad delivery — sender i ships a (share, blind) pair that does
//      not satisfy the commitment equation.
//
//  (b) Cross-recipient equivocation — sender i ships commits C_a to
//      recipient a and a different C_b to recipient b. Detected via
//      the CommitDigest broadcast in Round 1.5.
//
//  (c) Silence — sender i fails to deliver to recipient j by the
//      Round 1 deadline. Detected by absence in j's view.
//
// Disqualification rule (deterministic, identical on every honest party):
//
//  - Complaints from the same complainer about the same sender are
//    deduplicated by (sender, complainer) tuple.
//  - A sender i is DISQUALIFIED iff at least DisqualificationThreshold
//    distinct complainers signed valid complaints against i. Default
//    threshold is t_old - 1.
//  - After the Round 2 deadline, every honest party computes the SAME
//    set Q' = Q \ {disqualified senders} and uses it as the new
//    quorum.
//  - If |Q'| < t_old, the resharing FAILS and the chain stays at the
//    old epoch. The activation circuit-breaker enforces this.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/zeebo/blake3"
)

// ComplaintReason enumerates the failure modes that justify a complaint.
type ComplaintReason uint8

const (
	// ComplaintBadDelivery — share_{i→j} fails the commitment check.
	ComplaintBadDelivery ComplaintReason = 1

	// ComplaintEquivocation — sender i shipped different commits to
	// different recipients (detected via Round 1.5 digest cross-check).
	ComplaintEquivocation ComplaintReason = 2

	// ComplaintMissing — sender i failed to deliver share_{i→j} by
	// the round-1 deadline.
	ComplaintMissing ComplaintReason = 3

	// ComplaintMalformedCommit — sender i's commit vector has the
	// wrong length, has nil entries, or fails internal sanity checks.
	ComplaintMalformedCommit ComplaintReason = 4
)

// String returns a human-readable name for the reason.
func (r ComplaintReason) String() string {
	switch r {
	case ComplaintBadDelivery:
		return "bad-delivery"
	case ComplaintEquivocation:
		return "equivocation"
	case ComplaintMissing:
		return "missing"
	case ComplaintMalformedCommit:
		return "malformed-commit"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// Complaint is a signed assertion that sender PartyID misbehaved
// during the resharing protocol.
type Complaint struct {
	TranscriptHash [32]byte
	SenderID       int
	ComplainerID   int
	Reason         ComplaintReason
	Evidence       []byte
	Signature      []byte
	ComplainerKey  ed25519.PublicKey
}

// Bytes returns the canonical signed payload for a complaint. The
// Signature field is excluded (it is computed OVER these bytes).
func (c *Complaint) Bytes() []byte {
	var buf bytes.Buffer
	buf.WriteString("lens.reshare.complaint.v1")
	buf.Write(c.TranscriptHash[:])
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(c.SenderID))
	buf.Write(b4[:])
	binary.BigEndian.PutUint32(b4[:], uint32(c.ComplainerID))
	buf.Write(b4[:])
	buf.WriteByte(byte(c.Reason))
	binary.BigEndian.PutUint32(b4[:], uint32(len(c.Evidence)))
	buf.Write(b4[:])
	buf.Write(c.Evidence)
	return buf.Bytes()
}

// Sign produces a complaint signature using the provided Ed25519
// private key.
func (c *Complaint) Sign(priv ed25519.PrivateKey) {
	c.Signature = ed25519.Sign(priv, c.Bytes())
	c.ComplainerKey = priv.Public().(ed25519.PublicKey)
}

// Verify checks the Ed25519 signature against ComplainerKey. Returns
// nil iff the signature is valid.
func (c *Complaint) Verify() error {
	if c == nil || len(c.Signature) == 0 || len(c.ComplainerKey) == 0 {
		return errors.New("reshare: complaint missing signature or key")
	}
	if !ed25519.Verify(c.ComplainerKey, c.Bytes(), c.Signature) {
		return errors.New("reshare: complaint signature invalid")
	}
	return nil
}

// ComplaintHash returns BLAKE3 over the complaint's canonical bytes
// (signature included).
func ComplaintHash(c *Complaint) [32]byte {
	h := blake3.New()
	_, _ = h.Write([]byte("lens.reshare.complaint-hash.v1"))
	_, _ = h.Write(c.Bytes())
	_, _ = h.Write(c.Signature)
	var out [32]byte
	copy(out[:], h.Sum(nil)[:32])
	return out
}

// DisqualificationThreshold returns the minimum number of distinct,
// validly-signed complaints needed to disqualify a sender.
//
// Default: t_old - 1. Rationale: any single Byzantine validator can
// emit one false complaint to slow the protocol, but to disqualify an
// honest sender the adversary needs t_old - 1 collaborators —
// exceeding the static-corruption threshold of t_old - 1 by exactly
// one.
func DisqualificationThreshold(thresholdOld int) int {
	if thresholdOld <= 1 {
		return 1
	}
	return thresholdOld - 1
}

// ComputeDisqualifiedSet takes a slice of validated complaints and
// returns the set of sender IDs that meet the disqualification
// threshold. Every honest party that processes the same complaint set
// returns the same disqualified set.
//
// Complaints are deduplicated by (sender, complainer) tuple.
func ComputeDisqualifiedSet(complaints []*Complaint, thresholdOld int) map[int]struct{} {
	threshold := DisqualificationThreshold(thresholdOld)
	seen := make(map[[2]int]bool)
	count := make(map[int]int)
	for _, c := range complaints {
		key := [2]int{c.SenderID, c.ComplainerID}
		if seen[key] {
			continue
		}
		seen[key] = true
		count[c.SenderID]++
	}
	out := make(map[int]struct{})
	for sender, n := range count {
		if n >= threshold {
			out[sender] = struct{}{}
		}
	}
	return out
}

// FilterQualifiedQuorum returns the survivor set Q' = Q \ disqualified.
// Returns ErrInsufficientQuorum if |Q'| < tOld.
func FilterQualifiedQuorum(
	originalQuorum []int,
	disqualified map[int]struct{},
	tOld int,
) ([]int, error) {
	out := make([]int, 0, len(originalQuorum))
	for _, id := range originalQuorum {
		if _, dq := disqualified[id]; dq {
			continue
		}
		out = append(out, id)
	}
	if len(out) < tOld {
		return nil, fmt.Errorf("%w: %d survivors < threshold %d",
			ErrInsufficientQuorum, len(out), tOld)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out, nil
}

// ErrInsufficientQuorum signals that too many resharing parties were
// disqualified for the protocol to recover.
var ErrInsufficientQuorum = errors.New("reshare: qualified quorum below t_old after disqualification")
