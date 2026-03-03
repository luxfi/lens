// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command reshare_oracle emits Known-Answer-Test (KAT) vectors for the
// Lens reshare kernel. The oracle drives the Reshare and Refresh
// kernels with deterministic randomness derived from a seed and prints
// the resulting share map + master-secret reconstruction as JSON. A
// C++ port at luxcpp/crypto/lens/reshare/ consumes the JSON and
// reproduces the same bytes, providing cross-language byte-equality
// validation.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/reshare"

	"github.com/zeebo/blake3"
)

type vector struct {
	Curve     string            `json:"curve"`
	Variant   string            `json:"variant"`
	Seed      string            `json:"seed"`
	TOld      int               `json:"t_old"`
	TNew      int               `json:"t_new"`
	OldSet    []int             `json:"old_set"`
	NewSet    []int             `json:"new_set"`
	OldShares map[int]string    `json:"old_shares_hex"`
	NewShares map[int]string    `json:"new_shares_hex"`
	Recovered string            `json:"recovered_secret_hex"`
	Notes     map[string]string `json:"notes"`
}

func main() {
	curveName := flag.String("curve", "ed25519", "curve: ed25519, secp256k1, ristretto255")
	variant := flag.String("variant", "reshare", "variant: reshare or refresh")
	tOld := flag.Int("t_old", 3, "old reconstruction threshold")
	tNew := flag.Int("t_new", 3, "new reconstruction threshold")
	seed := flag.String("seed", "lens.reshare.kat.v1", "deterministic RNG seed")
	flag.Parse()

	c := pickCurve(*curveName)

	rng := blake3.New()
	_, _ = rng.Write([]byte("lens.reshare.oracle.rng:"))
	_, _ = rng.Write([]byte(*seed))
	stream := rng.Digest()

	secret, err := c.SampleScalar(stream)
	if err != nil {
		fail("sample secret", err)
	}

	const nOld = 5
	_, oldShares, err := primitives.Shamir(c, secret, *tOld, nOld, stream)
	if err != nil {
		fail("Shamir", err)
	}

	oldSet := []int{}
	for j := 1; j <= nOld; j++ {
		oldSet = append(oldSet, j)
	}

	newSet := []int{6, 7, 8, 9, 10}
	if *tNew > len(newSet) {
		fail("t_new", fmt.Errorf("t_new %d > |newSet| %d", *tNew, len(newSet)))
	}

	var newShares map[int]primitives.Scalar
	if *variant == "refresh" {
		newShares, err = reshare.Refresh(c, oldShares, *tOld, stream)
	} else {
		newShares, err = reshare.Reshare(c, oldShares, *tOld, newSet, *tNew, stream)
	}
	if err != nil {
		fail("kernel", err)
	}

	recovered, err := primitives.LagrangeRecover(c, newShares, *tNew)
	if err != nil {
		fail("recover", err)
	}
	if !recovered.Equal(secret) {
		fail("recover", fmt.Errorf("kernel did not preserve master secret"))
	}

	v := vector{
		Curve:     c.Name(),
		Variant:   *variant,
		Seed:      *seed,
		TOld:      *tOld,
		TNew:      *tNew,
		OldSet:    oldSet,
		NewSet:    newSet,
		OldShares: encodeMap(oldShares),
		NewShares: encodeMap(newShares),
		Recovered: encodeScalar(recovered),
		Notes: map[string]string{
			"format_version":       "1.0",
			"deterministic_rng":    "blake3-keyed",
			"intended_consumer":    "luxcpp/crypto/lens/reshare cross-port byte-equal validation",
			"variant_legal_values": "reshare, refresh",
			"curve_legal_values":   "ed25519, secp256k1, ristretto255",
		},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
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

func encodeMap(m map[int]primitives.Scalar) map[int]string {
	out := make(map[int]string, len(m))
	for k, v := range m {
		out[k] = encodeScalar(v)
	}
	return out
}

func encodeScalar(s primitives.Scalar) string {
	b, err := s.MarshalBinary()
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func fail(stage string, err error) {
	fmt.Fprintf(os.Stderr, "lens-reshare-oracle: %s: %v\n", stage, err)
	os.Exit(1)
}

// streamReader is a thin alias that retains the io.Reader import. The
// blake3.Digest() return type already satisfies io.Reader; this var
// exists so static analysers don't complain about an unused import.
var _ io.Reader = streamReader{}

type streamReader struct{}

func (streamReader) Read(_ []byte) (int, error) { return 0, io.EOF }
