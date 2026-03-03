// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/lens/primitives"
)

func TestNewGroupKeyHasGAndH(t *testing.T) {
	for _, c := range []primitives.Curve{
		primitives.NewEd25519(),
		primitives.NewSecp256k1(),
		primitives.NewRistretto255(),
	} {
		t.Run(c.Name(), func(t *testing.T) {
			s, _ := c.SampleScalar(rand.Reader)
			X := s.ActOnBase()
			gk := NewGroupKey(c, X)
			if gk.G.IsIdentity() {
				t.Error("G is identity")
			}
			if gk.H.IsIdentity() {
				t.Error("H is identity")
			}
			if gk.G.Equal(gk.H) {
				t.Error("G == H")
			}
			if !gk.X.Equal(X) {
				t.Error("X mismatch")
			}
		})
	}
}

func TestGroupKeyBytesStable(t *testing.T) {
	c := primitives.NewEd25519()
	s, _ := c.SampleScalar(rand.Reader)
	gk := NewGroupKey(c, s.ActOnBase())
	a := gk.Bytes()
	b := gk.Bytes()
	if string(a) != string(b) {
		t.Fatal("Bytes() not deterministic")
	}
	if len(a) == 0 {
		t.Fatal("Bytes() empty")
	}
}

func TestKeyShareConsistency(t *testing.T) {
	c := primitives.NewSecp256k1()
	s, _ := c.SampleScalar(rand.Reader)
	gk := NewGroupKey(c, s.ActOnBase())
	skShare, _ := c.SampleScalar(rand.Reader)
	ks := &KeyShare{
		Index:             0,
		PartyID:           1,
		SkShare:           skShare,
		VerificationShare: skShare.ActOnBase(),
		GroupKey:          gk,
	}
	if err := ks.CheckConsistency(); err != nil {
		t.Errorf("honest share failed: %v", err)
	}
	// Tamper VerificationShare.
	other, _ := c.SampleScalar(rand.Reader)
	ks.VerificationShare = other.ActOnBase()
	if err := ks.CheckConsistency(); err == nil {
		t.Error("inconsistent share accepted")
	}
}
