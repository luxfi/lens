// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command dkg_oracle emits a deterministic FROST DKG transcript for
// cross-language KAT validation. Drives lens/dkg.Run with a
// BLAKE3-keyed RNG and prints per-party shares + the joint group key.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/luxfi/lens/dkg"
	"github.com/luxfi/lens/primitives"

	"github.com/zeebo/blake3"
)

type vector struct {
	Curve      string         `json:"curve"`
	N          int            `json:"n"`
	T          int            `json:"t"`
	Seed       string         `json:"seed"`
	GroupKey   string         `json:"group_key_hex"`
	Shares     map[int]string `json:"shares_hex"`
	VerShares  map[int]string `json:"verification_shares_hex"`
	PartyOrder []int          `json:"party_order"`
}

func main() {
	curveName := flag.String("curve", "ed25519", "curve: ed25519, secp256k1, ristretto255")
	n := flag.Int("n", 5, "number of parties")
	t := flag.Int("t", 3, "threshold")
	seed := flag.String("seed", "lens.dkg.kat.v1", "deterministic RNG seed")
	flag.Parse()

	c := pickCurve(*curveName)

	rng := blake3.New()
	_, _ = rng.Write([]byte("lens.dkg.oracle.rng:"))
	_, _ = rng.Write([]byte(*seed))
	stream := rng.Digest()

	shares, gk, err := dkg.Run(c, *n, *t, stream)
	if err != nil {
		fail("dkg.Run", err)
	}

	order := make([]int, 0, len(shares))
	for id := range shares {
		order = append(order, id)
	}
	sort.Ints(order)

	out := vector{
		Curve:      c.Name(),
		N:          *n,
		T:          *t,
		Seed:       *seed,
		GroupKey:   hexPoint(gk.X),
		Shares:     map[int]string{},
		VerShares:  map[int]string{},
		PartyOrder: order,
	}
	for _, id := range order {
		ks := shares[id]
		out.Shares[id] = hexScalar(ks.SkShare)
		out.VerShares[id] = hexPoint(ks.VerificationShare)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fail("encode", err)
	}
}

func pickCurve(name string) primitives.Curve {
	switch name {
	case "ed25519":
		return primitives.NewEd25519()
	case "secp256k1":
		return primitives.NewSecp256k1()
	case "ristretto255":
		return primitives.NewRistretto255()
	default:
		fail("curve", fmt.Errorf("unknown curve %q", name))
		return nil
	}
}

func hexScalar(s primitives.Scalar) string {
	b, err := s.MarshalBinary()
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func hexPoint(p primitives.Point) string {
	b, err := p.MarshalBinary()
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func fail(stage string, err error) {
	fmt.Fprintf(os.Stderr, "lens-dkg-oracle: %s: %v\n", stage, err)
	os.Exit(1)
}
