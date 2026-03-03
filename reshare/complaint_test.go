// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestComplaintSignAndVerify — sign+verify round-trips cleanly.
func TestComplaintSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c := &Complaint{
		TranscriptHash: [32]byte{0xAA, 0xBB},
		SenderID:       3,
		ComplainerID:   5,
		Reason:         ComplaintBadDelivery,
		Evidence:       []byte("bad-share-bytes"),
	}
	c.Sign(priv)
	if err := c.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(c.ComplainerKey) != string(pub) {
		t.Fatal("ComplainerKey not pinned to signer")
	}

	// Tampered: changing reason invalidates signature.
	c.Reason = ComplaintMissing
	if err := c.Verify(); err == nil {
		t.Fatal("tampered complaint accepted")
	}
}

// TestDisqualificationThreshold matches the rule t_old - 1 (default).
func TestDisqualificationThreshold(t *testing.T) {
	if got := DisqualificationThreshold(5); got != 4 {
		t.Errorf("threshold(5): want 4 got %d", got)
	}
	if got := DisqualificationThreshold(2); got != 1 {
		t.Errorf("threshold(2): want 1 got %d", got)
	}
	if got := DisqualificationThreshold(1); got != 1 {
		t.Errorf("threshold(1): want 1 got %d", got)
	}
}

// TestComputeDisqualifiedSet deduplicates and applies the threshold.
func TestComputeDisqualifiedSet(t *testing.T) {
	mk := func(sender, complainer int) *Complaint {
		return &Complaint{SenderID: sender, ComplainerID: complainer, Reason: ComplaintBadDelivery}
	}
	complaints := []*Complaint{
		// sender 1: 3 distinct complainers (>= t_old-1 = 4)? no, 3 < 4 so NOT disqualified
		mk(1, 2), mk(1, 3), mk(1, 4),
		// sender 2: 4 distinct complainers >= 4
		mk(2, 1), mk(2, 3), mk(2, 4), mk(2, 5),
		// duplicate complainer for sender 2 — does not count again
		mk(2, 1),
	}
	dq := ComputeDisqualifiedSet(complaints, 5)
	if _, ok := dq[1]; ok {
		t.Error("sender 1 wrongly disqualified")
	}
	if _, ok := dq[2]; !ok {
		t.Error("sender 2 should be disqualified")
	}
}

// TestFilterQualifiedQuorum removes disqualified, errors if too few left.
func TestFilterQualifiedQuorum(t *testing.T) {
	dq := map[int]struct{}{2: {}, 4: {}}
	out, err := FilterQualifiedQuorum([]int{1, 2, 3, 4, 5}, dq, 3)
	if err != nil {
		t.Fatalf("FilterQualifiedQuorum: %v", err)
	}
	want := []int{1, 3, 5}
	if len(out) != len(want) {
		t.Fatalf("want %d survivors got %d", len(want), len(out))
	}
	for i, id := range want {
		if out[i] != id {
			t.Errorf("survivor[%d]: want %d got %d", i, id, out[i])
		}
	}

	// Too few survivors: error.
	if _, err := FilterQualifiedQuorum([]int{1, 2}, map[int]struct{}{1: {}}, 2); err == nil {
		t.Fatal("expected ErrInsufficientQuorum")
	}
}
