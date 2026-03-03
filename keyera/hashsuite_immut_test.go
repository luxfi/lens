// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package keyera — HashSuite immutability tests for Lens (Gate 3
// mirror of the Mar-3-2026 PQ Consensus Architecture Freeze).
//
// The same era-pinning property the Pulsar lattice kernel proves over
// {Pulsar-SHA3, Pulsar-BLAKE3} applies on the curve-side sister kernel
// over {Lens-SHA3, Lens-BLAKE3}. Bootstrap pins the suite, Reshare
// propagates it without parameterisation, and Reanchor MAY pin a new
// suite when opening a fresh era.
//
// Citations (canonical proof bucket):
//
//   proofs/definitions/transcript-binding.tex
//     Definition ref:pulsar-transcript (the lens transcript layout is
//     symmetric with the pulsar one)
//   proofs/pulsar/hash-suite-separation.tex
//     Theorem ref:hash-suite-separation (Pulsar; the curve-side
//     argument is structurally identical and lives in the proofs/lens
//     bucket as a mirror reference)
package keyera

import (
	"reflect"
	"testing"

	"github.com/luxfi/lens/hash"
	"github.com/luxfi/lens/primitives"
)

// TestLensBootstrapPinsSuiteSHA3 — Bootstrap with Lens-SHA3 →
// era.HashSuiteID == "Lens-SHA3".
func TestLensBootstrapPinsSuiteSHA3(t *testing.T) {
	c := primitives.NewEd25519()
	era, err := BootstrapWithSuite(
		c,
		hash.NewLensSHA3(),
		3,
		[]string{"a", "b", "c"},
		0, 0,
		deterministicRand("lens-hashsuite-immut-sha3"),
	)
	if err != nil {
		t.Fatalf("BootstrapWithSuite: %v", err)
	}
	if era.HashSuiteID != hash.DefaultID {
		t.Fatalf("era.HashSuiteID: want %q got %q", hash.DefaultID, era.HashSuiteID)
	}
	if got := era.State.HashSuiteID; got != hash.DefaultID {
		t.Fatalf("state.HashSuiteID: want %q got %q", hash.DefaultID, got)
	}
}

// TestLensBootstrapPinsSuiteBLAKE3 — Bootstrap with Lens-BLAKE3 →
// era.HashSuiteID == "Lens-BLAKE3".
func TestLensBootstrapPinsSuiteBLAKE3(t *testing.T) {
	c := primitives.NewSecp256k1()
	era, err := BootstrapWithSuite(
		c,
		hash.NewLensBLAKE3(),
		3,
		[]string{"a", "b", "c"},
		0, 0,
		deterministicRand("lens-hashsuite-immut-blake3"),
	)
	if err != nil {
		t.Fatalf("BootstrapWithSuite: %v", err)
	}
	if era.HashSuiteID != hash.LegacyBLAKE3ID {
		t.Fatalf("era.HashSuiteID: want %q got %q", hash.LegacyBLAKE3ID, era.HashSuiteID)
	}
	if got := era.State.HashSuiteID; got != hash.LegacyBLAKE3ID {
		t.Fatalf("state.HashSuiteID: want %q got %q", hash.LegacyBLAKE3ID, got)
	}
}

// TestLensBootstrapDefaultsToSHA3 confirms the no-suite Bootstrap
// entrypoint pins the production default.
func TestLensBootstrapDefaultsToSHA3(t *testing.T) {
	c := primitives.NewEd25519()
	era, err := Bootstrap(c, 3, []string{"a", "b", "c"}, 0, 0,
		deterministicRand("lens-hashsuite-default"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if era.HashSuiteID != hash.DefaultID {
		t.Fatalf("default suite: want %q got %q", hash.DefaultID, era.HashSuiteID)
	}
}

// TestLensReshareCannotChangeSuiteSHA3 — the Lens Reshare API
// propagates HashSuiteID unchanged across share rotation.
func TestLensReshareCannotChangeSuiteSHA3(t *testing.T) {
	c := primitives.NewEd25519()
	era, err := BootstrapWithSuite(
		c,
		hash.NewLensSHA3(),
		3,
		[]string{"v1", "v2", "v3"},
		0, 0,
		deterministicRand("lens-reshare-sha3"),
	)
	if err != nil {
		t.Fatalf("BootstrapWithSuite: %v", err)
	}
	priorID := era.HashSuiteID

	next, err := era.Reshare([]string{"v1", "v2", "v3"}, 3, deterministicRand("lens-reshare-1"))
	if err != nil {
		t.Fatalf("Reshare: %v", err)
	}
	if era.HashSuiteID != priorID {
		t.Fatalf("era.HashSuiteID changed across Reshare: was %q now %q", priorID, era.HashSuiteID)
	}
	if next.HashSuiteID != priorID {
		t.Fatalf("post-Reshare state.HashSuiteID: want %q got %q", priorID, next.HashSuiteID)
	}
}

// TestLensReshareCannotChangeSuiteBLAKE3 — same on the legacy profile.
func TestLensReshareCannotChangeSuiteBLAKE3(t *testing.T) {
	c := primitives.NewRistretto255()
	era, err := BootstrapWithSuite(
		c,
		hash.NewLensBLAKE3(),
		3,
		[]string{"v1", "v2", "v3"},
		0, 0,
		deterministicRand("lens-reshare-blake3"),
	)
	if err != nil {
		t.Fatalf("BootstrapWithSuite: %v", err)
	}
	priorID := era.HashSuiteID
	if priorID != hash.LegacyBLAKE3ID {
		t.Fatalf("setup: era.HashSuiteID want %q got %q", hash.LegacyBLAKE3ID, priorID)
	}

	next, err := era.Reshare([]string{"v4", "v5", "v6"}, 2, deterministicRand("lens-reshare-blake3-2"))
	if err != nil {
		t.Fatalf("Reshare: %v", err)
	}
	if era.HashSuiteID != priorID {
		t.Fatalf("era.HashSuiteID changed across Reshare: was %q now %q", priorID, era.HashSuiteID)
	}
	if next.HashSuiteID != priorID {
		t.Fatalf("post-Reshare state.HashSuiteID: want %q got %q", priorID, next.HashSuiteID)
	}
}

// TestLensReshareAPIHasNoHashSuiteParameter mirrors the Pulsar pin: the
// Reshare method on a Lens KeyEra MUST NOT accept a hash.HashSuite,
// closing the door on per-call suite-changes at the type level.
func TestLensReshareAPIHasNoHashSuiteParameter(t *testing.T) {
	era := &KeyEra{}
	rt := reflect.ValueOf(era).MethodByName("Reshare").Type()
	hashSuiteIface := reflect.TypeOf((*hash.HashSuite)(nil)).Elem()
	for i := 0; i < rt.NumIn(); i++ {
		in := rt.In(i)
		if in == hashSuiteIface {
			t.Fatalf("Reshare param %d is hash.HashSuite — reshare must not accept a suite", i)
		}
		if in.Kind() == reflect.Interface && in.Implements(hashSuiteIface) {
			t.Fatalf("Reshare param %d implements hash.HashSuite — reshare must not accept a suite", i)
		}
	}
}

// TestLensReanchorMayChangeSuite — ReanchorWithSuite from a Lens-SHA3
// era to a Lens-BLAKE3 era yields era_2.HashSuiteID == "Lens-BLAKE3";
// era_1 unchanged.
func TestLensReanchorMayChangeSuite(t *testing.T) {
	c := primitives.NewEd25519()
	era1, err := BootstrapWithSuite(
		c,
		hash.NewLensSHA3(),
		3,
		[]string{"a", "b", "c"},
		0, 1,
		deterministicRand("lens-reanchor-era-1"),
	)
	if err != nil {
		t.Fatalf("BootstrapWithSuite: %v", err)
	}
	if era1.HashSuiteID != hash.DefaultID {
		t.Fatalf("era1.HashSuiteID: want %q got %q", hash.DefaultID, era1.HashSuiteID)
	}

	era2, err := ReanchorWithSuite(
		era1,
		c,
		hash.NewLensBLAKE3(),
		3,
		[]string{"d", "e", "f"},
		0,
		deterministicRand("lens-reanchor-era-2"),
	)
	if err != nil {
		t.Fatalf("ReanchorWithSuite: %v", err)
	}
	if era2.HashSuiteID != hash.LegacyBLAKE3ID {
		t.Fatalf("era2.HashSuiteID: want %q got %q", hash.LegacyBLAKE3ID, era2.HashSuiteID)
	}
	if era1.HashSuiteID != hash.DefaultID {
		t.Fatalf("era1.HashSuiteID mutated by Reanchor: want %q got %q",
			hash.DefaultID, era1.HashSuiteID)
	}
	if era1.GroupKey == era2.GroupKey {
		t.Fatal("Reanchor returned the same GroupKey pointer; expected fresh key")
	}
	if era2.State.HashSuiteID != hash.LegacyBLAKE3ID {
		t.Fatalf("era2.State.HashSuiteID: want %q got %q",
			hash.LegacyBLAKE3ID, era2.State.HashSuiteID)
	}
	if era2.EraID != era1.EraID+1 {
		t.Fatalf("era2.EraID: want %d got %d", era1.EraID+1, era2.EraID)
	}
}
