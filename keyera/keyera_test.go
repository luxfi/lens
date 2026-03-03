// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyera

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/sign"
	"github.com/luxfi/lens/threshold"

	"github.com/zeebo/blake3"
)

func curves() []primitives.Curve {
	return []primitives.Curve{
		primitives.NewEd25519(),
		primitives.NewSecp256k1(),
		primitives.NewRistretto255(),
	}
}

// TestBootstrapBuildsAndSigns confirms Bootstrap returns a complete
// KeyShare set that produces a verifying FROST signature under the
// produced GroupKey.
func TestBootstrapBuildsAndSigns(t *testing.T) {
	for _, c := range curves() {
		t.Run(c.Name(), func(t *testing.T) {
			const tThr, n = 3, 3
			validators := []string{"validator-A", "validator-B", "validator-C"}
			era, err := Bootstrap(c, tThr, validators, 0, 0, deterministicRand("bootstrap-genesis"))
			if err != nil {
				t.Fatalf("Bootstrap: %v", err)
			}
			if era.GroupKey == nil {
				t.Fatal("Bootstrap returned nil GroupKey")
			}
			if got := era.State.Threshold; got != tThr {
				t.Fatalf("threshold: want %d got %d", tThr, got)
			}
			if got := len(era.State.Shares); got != n {
				t.Fatalf("share count: want %d got %d", n, got)
			}
			if !signAndVerify(t, era, validators) {
				t.Fatal("genesis signature failed to verify under GroupKey")
			}
		})
	}
}

// TestReshareSameSetPreservesGroupKey runs Bootstrap then Reshare
// against the same validator set with the same threshold.
func TestReshareSameSetPreservesGroupKey(t *testing.T) {
	c := primitives.NewEd25519()
	const tThr = 3
	validators := []string{"v1", "v2", "v3"}
	era, err := Bootstrap(c, tThr, validators, 0, 0, deterministicRand("genesis-A"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	gkBefore := era.GroupKey

	if _, err := era.Reshare(validators, tThr, deterministicRand("reshare-1")); err != nil {
		t.Fatalf("Reshare: %v", err)
	}
	if era.GroupKey != gkBefore {
		t.Fatal("GroupKey pointer changed across Reshare; era invariant broken")
	}
	if got := era.State.Epoch; got != 1 {
		t.Fatalf("epoch: want 1 got %d", got)
	}
	if !signAndVerify(t, era, validators) {
		t.Fatal("post-reshare signature failed to verify under unchanged GroupKey")
	}
}

// TestReshareNewCommitteePreservesGroupKey rotates onto a different
// validator set with a different threshold.
func TestReshareNewCommitteePreservesGroupKey(t *testing.T) {
	c := primitives.NewSecp256k1()
	const tOld = 3
	const tNew = 5
	oldSet := []string{"v1", "v2", "v3"}
	newSet := []string{"v4", "v5", "v6", "v7", "v8"}

	era, err := Bootstrap(c, tOld, oldSet, 0, 0, deterministicRand("genesis-B"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	gkBefore := era.GroupKey

	if _, err := era.Reshare(newSet, tNew, deterministicRand("reshare-set")); err != nil {
		t.Fatalf("Reshare: %v", err)
	}
	if era.GroupKey != gkBefore {
		t.Fatal("GroupKey pointer changed across Reshare")
	}
	if got := len(era.State.Validators); got != len(newSet) {
		t.Fatalf("validator count: want %d got %d", len(newSet), got)
	}
	if got := era.State.Threshold; got != tNew {
		t.Fatalf("threshold: want %d got %d", tNew, got)
	}
	if !signAndVerify(t, era, newSet) {
		t.Fatal("new-committee signature failed to verify under unchanged GroupKey")
	}
}

// TestReanchorOpensNewEra verifies Reanchor produces a fresh GroupKey
// while monotonically advancing the epoch and bumping the EraID.
func TestReanchorOpensNewEra(t *testing.T) {
	c := primitives.NewRistretto255()
	era, err := Bootstrap(c, 3, []string{"a", "b", "c"}, 0, 1, deterministicRand("era-1"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if _, err := era.Reshare([]string{"a", "b", "c"}, 3, deterministicRand("reshare-x")); err != nil {
		t.Fatalf("Reshare: %v", err)
	}
	prevEpoch := era.State.Epoch
	prevGK := era.GroupKey
	prevEraID := era.EraID

	era2, err := Reanchor(era, c, 3, []string{"d", "e", "f"}, 0, deterministicRand("era-2"))
	if err != nil {
		t.Fatalf("Reanchor: %v", err)
	}
	if era2.GroupKey == prevGK {
		t.Fatal("Reanchor returned the same GroupKey pointer")
	}
	if got := era2.GenesisEpoch; got != prevEpoch+1 {
		t.Fatalf("genesis epoch: want %d got %d", prevEpoch+1, got)
	}
	if got := era2.State.Epoch; got != prevEpoch+1 {
		t.Fatalf("state epoch: want %d got %d", prevEpoch+1, got)
	}
	if got := era2.EraID; got != prevEraID+1 {
		t.Fatalf("era id: want %d got %d", prevEraID+1, got)
	}
}

// TestReshareErrors covers the input-validation surface.
func TestReshareErrors(t *testing.T) {
	c := primitives.NewEd25519()
	era, err := Bootstrap(c, 3, []string{"a", "b", "c"}, 0, 0, deterministicRand("err"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if _, err := era.Reshare(nil, 2, nil); err == nil {
		t.Error("expected error for empty validators")
	}
	if _, err := era.Reshare([]string{"x", "y"}, 0, nil); err == nil {
		t.Error("expected error for threshold < 1")
	}
	if _, err := era.Reshare([]string{"x", "y"}, 3, nil); err == nil {
		t.Error("expected error for threshold > n")
	}
	var nilEra *KeyEra
	if _, err := nilEra.Reshare([]string{"a", "b"}, 1, nil); err == nil {
		t.Error("expected error for nil receiver")
	}
}

// TestBootstrapErrors covers Bootstrap input-validation paths.
func TestBootstrapErrors(t *testing.T) {
	c := primitives.NewEd25519()
	if _, err := Bootstrap(c, 1, nil, 0, 0, nil); err == nil {
		t.Error("expected error for empty validators")
	}
	if _, err := Bootstrap(c, 0, []string{"a"}, 0, 0, nil); err == nil {
		t.Error("expected error for threshold = 0")
	}
	if _, err := Bootstrap(c, 5, []string{"a", "b"}, 0, 0, nil); err == nil {
		t.Error("expected error for threshold > n")
	}
}

// signAndVerify drives the FROST signing protocol on the era's current
// state and returns true iff the resulting signature verifies under
// the era's GroupKey.
func signAndVerify(t *testing.T, era *KeyEra, validators []string) bool {
	t.Helper()
	signers := make([]int, 0, len(validators))
	signersByID := make(map[int]*sign.Signer, len(validators))
	keysByID := make(map[int]*threshold.KeyShare, len(validators))
	for _, v := range validators {
		ks := era.State.Shares[v]
		if ks == nil {
			t.Fatalf("missing share for %s", v)
		}
		keysByID[ks.PartyID] = ks
		signersByID[ks.PartyID] = sign.NewSigner(ks)
		signers = append(signers, ks.PartyID)
	}

	const message = "lens-keyera-test-message"
	commits := make(map[int]*sign.CommitMsg, len(signers))
	for _, id := range signers {
		cm, err := signersByID[id].Round1([]byte(message), signers, rand.Reader)
		if err != nil {
			t.Fatalf("Round1 for %d: %v", id, err)
		}
		commits[id] = cm
	}
	responses := make(map[int]*sign.ResponseMsg, len(signers))
	for _, id := range signers {
		rm, err := signersByID[id].Round2([]byte(message), commits)
		if err != nil {
			t.Fatalf("Round2 for %d: %v", id, err)
		}
		responses[id] = rm
	}

	verShares := make(map[int]primitives.Point, len(keysByID))
	for id, ks := range keysByID {
		verShares[id] = ks.VerificationShare
	}
	sig, err := sign.Aggregate(era.GroupKey, []byte(message), signers, commits, responses, verShares)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	return sign.Verify(era.GroupKey, []byte(message), sig) == nil
}

// deterministicRand returns an unbounded byte stream derived from a
// seed string for KAT-replay tests.
func deterministicRand(seed string) io.Reader {
	h := blake3.New()
	_, _ = h.Write([]byte("lens.keyera.test.rng.v1"))
	_, _ = h.Write([]byte(seed))
	return h.Digest()
}
