// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sign

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/threshold"
)

// trustedSetup is a single-process test helper that creates t-of-n
// threshold-shared key material from a freshly-sampled master secret.
// Tests use it to generate inputs to the FROST signing path; production
// code uses keyera.Bootstrap or dkg.Run instead.
func trustedSetup(t *testing.T, c primitives.Curve, tThr, n int) *trustedKey {
	t.Helper()
	secret, err := c.SampleScalar(rand.Reader)
	if err != nil {
		t.Fatalf("sample secret: %v", err)
	}
	X := secret.ActOnBase()
	gk := threshold.NewGroupKey(c, X)

	_, shares, err := primitives.Shamir(c, secret, tThr, n, rand.Reader)
	if err != nil {
		t.Fatalf("Shamir: %v", err)
	}

	signerIDs := make([]int, 0, n)
	for j := 1; j <= n; j++ {
		signerIDs = append(signerIDs, j)
	}
	lambda, err := primitives.Lagrange(c, signerIDs)
	if err != nil {
		t.Fatalf("Lagrange: %v", err)
	}

	keyShares := make(map[int]*threshold.KeyShare, n)
	for j := 1; j <= n; j++ {
		ks := &threshold.KeyShare{
			Index:             j - 1,
			PartyID:           j,
			SkShare:           shares[j],
			VerificationShare: shares[j].ActOnBase(),
			Lambda:            lambda[j],
			GroupKey:          gk,
		}
		keyShares[j] = ks
	}

	return &trustedKey{
		curve:     c,
		groupKey:  gk,
		shares:    keyShares,
		threshold: tThr,
		secret:    secret,
	}
}

type trustedKey struct {
	curve     primitives.Curve
	groupKey  *threshold.GroupKey
	shares    map[int]*threshold.KeyShare
	threshold int
	secret    primitives.Scalar
}

// TestFROSTSignVerifies runs the full 2-round FROST signing flow and
// verifies the resulting signature on each curve.
func TestFROSTSignVerifies(t *testing.T) {
	const tThr, n = 3, 3
	curves := []struct {
		name string
		c    primitives.Curve
	}{
		{"ed25519", primitives.NewEd25519()},
		{"secp256k1", primitives.NewSecp256k1()},
		{"ristretto255", primitives.NewRistretto255()},
	}
	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			tk := trustedSetup(t, tc.c, tThr, n)
			signers := []int{1, 2, 3}
			message := []byte("lens-sign-test-message")

			signersByID := make(map[int]*Signer, n)
			commits := make(map[int]*CommitMsg, n)
			responses := make(map[int]*ResponseMsg, n)

			for _, id := range signers {
				signersByID[id] = NewSigner(tk.shares[id])
				cm, err := signersByID[id].Round1(message, signers, rand.Reader)
				if err != nil {
					t.Fatalf("Round1 for %d: %v", id, err)
				}
				commits[id] = cm
			}
			for _, id := range signers {
				rm, err := signersByID[id].Round2(message, commits)
				if err != nil {
					t.Fatalf("Round2 for %d: %v", id, err)
				}
				responses[id] = rm
			}

			verShares := threshold.VerificationShares(tk.shares)
			sig, err := Aggregate(tk.groupKey, message, signers, commits, responses, verShares)
			if err != nil {
				t.Fatalf("Aggregate: %v", err)
			}
			if err := Verify(tk.groupKey, message, sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			// Sanity: signature bytes round-trip cleanly.
			b, err := sig.Bytes()
			if err != nil {
				t.Fatalf("sig.Bytes: %v", err)
			}
			if got := len(b); got != tc.c.PointBytes()+tc.c.ScalarBytes() {
				t.Fatalf("sig length: want %d got %d", tc.c.PointBytes()+tc.c.ScalarBytes(), got)
			}
		})
	}
}

// TestFROSTSignWrongMessageFails confirms that swapping the verifier's
// message rejects the signature.
func TestFROSTSignWrongMessageFails(t *testing.T) {
	c := primitives.NewEd25519()
	tk := trustedSetup(t, c, 3, 3)
	signers := []int{1, 2, 3}
	msg := []byte("real")

	commits, responses, signersByID := runFROST(t, tk, signers, msg)
	_ = signersByID
	verShares := threshold.VerificationShares(tk.shares)
	sig, err := Aggregate(tk.groupKey, msg, signers, commits, responses, verShares)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	if err := Verify(tk.groupKey, []byte("forged"), sig); err == nil {
		t.Fatal("Verify accepted signature on wrong message")
	}
}

// TestFROSTSignTamperedResponse confirms Aggregate rejects an invalid
// partial response.
func TestFROSTSignTamperedResponse(t *testing.T) {
	c := primitives.NewSecp256k1()
	tk := trustedSetup(t, c, 3, 3)
	signers := []int{1, 2, 3}
	msg := []byte("test")

	commits, responses, _ := runFROST(t, tk, signers, msg)
	// Flip one bit in party 2's response.
	responses[2].Z.Add(c.NewScalar().SetUint64(1))

	verShares := threshold.VerificationShares(tk.shares)
	if _, err := Aggregate(tk.groupKey, msg, signers, commits, responses, verShares); err == nil {
		t.Fatal("Aggregate accepted tampered response")
	}
}

// runFROST drives Round1 + Round2 for a t-of-n setup and returns the
// collected commits + responses.
func runFROST(t *testing.T, tk *trustedKey, signers []int, msg []byte) (
	map[int]*CommitMsg, map[int]*ResponseMsg, map[int]*Signer,
) {
	t.Helper()
	signersByID := make(map[int]*Signer, len(signers))
	commits := make(map[int]*CommitMsg, len(signers))
	for _, id := range signers {
		signersByID[id] = NewSigner(tk.shares[id])
		cm, err := signersByID[id].Round1(msg, signers, rand.Reader)
		if err != nil {
			t.Fatalf("Round1 for %d: %v", id, err)
		}
		commits[id] = cm
	}
	responses := make(map[int]*ResponseMsg, len(signers))
	for _, id := range signers {
		rm, err := signersByID[id].Round2(msg, commits)
		if err != nil {
			t.Fatalf("Round2 for %d: %v", id, err)
		}
		responses[id] = rm
	}
	return commits, responses, signersByID
}
