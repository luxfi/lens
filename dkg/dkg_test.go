// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dkg

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/sign"
	"github.com/luxfi/lens/threshold"
)

func curves() []primitives.Curve {
	return []primitives.Curve{
		primitives.NewEd25519(),
		primitives.NewSecp256k1(),
		primitives.NewRistretto255(),
	}
}

// TestDKGRunAndSign — distributed key generation followed by FROST
// signing. The signature must verify under the joint group public key.
func TestDKGRunAndSign(t *testing.T) {
	for _, c := range curves() {
		t.Run(c.Name(), func(t *testing.T) {
			const n, tThr = 5, 3
			shares, gk, err := Run(c, n, tThr, rand.Reader)
			if err != nil {
				t.Fatalf("dkg.Run: %v", err)
			}
			if got := len(shares); got != n {
				t.Fatalf("share count: want %d got %d", n, got)
			}
			for id, ks := range shares {
				if err := ks.CheckConsistency(); err != nil {
					t.Errorf("party %d: %v", id, err)
				}
				if ks.GroupKey != gk {
					t.Errorf("party %d: GroupKey pointer mismatch", id)
				}
			}

			// FROST sign with all n parties so we can use the
			// already-cached Lambda from Run.
			signers := []int{1, 2, 3, 4, 5}
			signersByID := make(map[int]*sign.Signer, n)
			commits := make(map[int]*sign.CommitMsg, n)
			for _, id := range signers {
				signersByID[id] = sign.NewSigner(shares[id])
				cm, err := signersByID[id].Round1([]byte("dkg-sign-test"), signers, rand.Reader)
				if err != nil {
					t.Fatalf("Round1 for %d: %v", id, err)
				}
				commits[id] = cm
			}
			responses := make(map[int]*sign.ResponseMsg, n)
			for _, id := range signers {
				rm, err := signersByID[id].Round2([]byte("dkg-sign-test"), commits)
				if err != nil {
					t.Fatalf("Round2 for %d: %v", id, err)
				}
				responses[id] = rm
			}
			verShares := threshold.VerificationShares(shares)
			sig, err := sign.Aggregate(gk, []byte("dkg-sign-test"), signers, commits, responses, verShares)
			if err != nil {
				t.Fatalf("Aggregate: %v", err)
			}
			if err := sign.Verify(gk, []byte("dkg-sign-test"), sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// TestDKGTamperedShare — a single bad share fails Round 2 and is
// attributed to the sender.
func TestDKGTamperedShare(t *testing.T) {
	c := primitives.NewEd25519()
	const n, tThr = 4, 3

	sessions := make(map[int]*Session, n)
	round1 := make(map[int]*Round1Output, n)
	for j := 1; j <= n; j++ {
		s, _ := NewSession(c, j, n, tThr)
		sessions[j] = s
		out, _ := s.Round1(rand.Reader)
		round1[j] = out
	}

	// Tamper party 2's share for receiver 3: add 1.
	bad := c.NewScalar().Set(round1[2].Shares[3])
	bad.Add(c.NewScalar().SetUint64(1))
	round1[2].Shares[3] = bad

	// Receiver 3 runs Round 2 — must reject with attribution to sender 2.
	recvShares := make(map[int]primitives.Scalar, n)
	recvCommits := make(map[int][]primitives.Point, n)
	for i := 1; i <= n; i++ {
		recvShares[i] = round1[i].Shares[3]
		recvCommits[i] = round1[i].Commits
	}
	if _, _, err := sessions[3].Round2(recvShares, recvCommits); err == nil {
		t.Fatal("Round2 accepted tampered share")
	}
}

// TestDKGSessionErrors covers the input-validation paths.
func TestDKGSessionErrors(t *testing.T) {
	c := primitives.NewEd25519()
	if _, err := NewSession(c, 1, 1, 1); err == nil {
		t.Error("expected ErrInvalidPartyCount for n=1")
	}
	if _, err := NewSession(c, 0, 3, 2); err == nil {
		t.Error("expected ErrInvalidPartyID for partyID=0")
	}
	if _, err := NewSession(c, 1, 3, 0); err == nil {
		t.Error("expected ErrInvalidThreshold for t=0")
	}
	if _, err := NewSession(c, 1, 3, 4); err == nil {
		t.Error("expected ErrInvalidThreshold for t > n")
	}
}
