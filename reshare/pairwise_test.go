// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// TestX25519PairAgrees — both ends derive the same secret.
func TestX25519PairAgrees(t *testing.T) {
	var aPriv, bPriv [32]byte
	if _, err := rand.Read(aPriv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := rand.Read(bPriv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	aPub, _ := curve25519.X25519(aPriv[:], curve25519.Basepoint)
	bPub, _ := curve25519.X25519(bPriv[:], curve25519.Basepoint)

	s1, err := X25519Pair(aPriv[:], bPub)
	if err != nil {
		t.Fatalf("X25519Pair a->b: %v", err)
	}
	s2, err := X25519Pair(bPriv[:], aPub)
	if err != nil {
		t.Fatalf("X25519Pair b->a: %v", err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatal("pair shared secrets disagree")
	}
}

// TestAuthenticatedKex round-trips a pairwise KEX with signed
// ephemerals.
func TestAuthenticatedKex(t *testing.T) {
	transcriptHash := [32]byte{0x42}
	jStaticPub, jStaticPriv, _ := ed25519.GenerateKey(rand.Reader)

	var iEph [32]byte
	var jEph [32]byte
	if _, err := rand.Read(iEph[:]); err != nil {
		t.Fatalf("iEph: %v", err)
	}
	if _, err := rand.Read(jEph[:]); err != nil {
		t.Fatalf("jEph: %v", err)
	}
	jEphPub, _ := curve25519.X25519(jEph[:], curve25519.Basepoint)
	sigJ := SignEphemeral(jStaticPriv, jEphPub, transcriptHash)

	auth, err := AuthenticatedKex(iEph[:], jEphPub, sigJ, jStaticPub, transcriptHash, nil)
	if err != nil {
		t.Fatalf("AuthenticatedKex: %v", err)
	}
	if len(auth) != 32 {
		t.Fatalf("auth_kex size %d, want 32", len(auth))
	}

	// Wrong transcript: signature fails.
	bad := [32]byte{0x99}
	if _, err := AuthenticatedKex(iEph[:], jEphPub, sigJ, jStaticPub, bad, nil); err == nil {
		t.Fatal("AuthenticatedKex accepted wrong transcript")
	}
}

// TestDeriveSeedsAndMACKeys — outputs are deterministic and per-pair.
func TestDeriveSeedsAndMACKeys(t *testing.T) {
	const K = 3
	authKex := map[[2]int][]byte{
		{0, 1}: []byte("kex-0-1"),
		{0, 2}: []byte("kex-0-2"),
		{1, 2}: []byte("kex-1-2"),
	}
	selfSeeds := map[int][]byte{
		0: []byte("self-0"),
		1: []byte("self-1"),
		2: []byte("self-2"),
	}
	chainID := []byte("lux")
	groupID := []byte("g")
	seeds, err := DeriveSeeds(K, authKex, selfSeeds, chainID, groupID, 0, 0, nil, 32)
	if err != nil {
		t.Fatalf("DeriveSeeds: %v", err)
	}
	macs, err := DeriveMACKeys(K, authKex, chainID, groupID, 0, 0, nil, 32)
	if err != nil {
		t.Fatalf("DeriveMACKeys: %v", err)
	}
	if got := len(seeds); got != K*(K+1)/2 {
		t.Errorf("seed count %d, want %d", got, K*(K+1)/2)
	}
	if got := len(macs); got != K*(K-1)/2 {
		t.Errorf("mac count %d, want %d", got, K*(K-1)/2)
	}
	// Confirm distinct outputs across pairs.
	a := seeds[[2]int{0, 1}]
	b := seeds[[2]int{1, 2}]
	if bytes.Equal(a, b) {
		t.Error("distinct pairs collided in DeriveSeeds")
	}
}
