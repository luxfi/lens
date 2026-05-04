// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command cross_runtime_oracle emits a deterministic Lens transcript
// covering DKG -> Sign -> Aggregate end-to-end, for cross-language
// byte-equality validation against the C++ port at
// luxcpp/crypto/lens/.
//
// JSON shape:
//
//	{
//	  "curve": "<>",
//	  "n": int,
//	  "t": int,
//	  "seed": "<>",
//	  "message_hex": "<>",
//	  "salt_hex": "<32-byte hex>",
//	  "signers": [int],            // sorted ascending
//	  "group_key_hex": "<>",
//	  "shares_hex":               { id -> hex },
//	  "verification_shares_hex":  { id -> hex },
//	  "lambda_full_hex":          { id -> hex },  // λ over the full party set
//	  "lambda_signers_hex":       { id -> hex },  // λ over the signing subset
//	  "commits_D_hex":            { id -> hex },
//	  "commits_E_hex":            { id -> hex },
//	  "responses_z_hex":          { id -> hex },
//	  "sig_R_hex": "<>",
//	  "sig_z_hex": "<>"
//	}
//
// All hex outputs are byte-equal to the canonical Go encodings:
//   - Scalars: filippo.io / decred / gtank MarshalBinary
//   - Points:  filippo.io / decred / gtank MarshalBinary (compressed)
//
// The replay harness (luxcpp/crypto/lens/test/cpp/cross_runtime_test.cpp)
// loads this JSON and asserts byte-equal end-to-end.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/luxfi/lens/dkg"
	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/sign"

	"github.com/zeebo/blake3"
)

type Vector struct {
	Curve              string         `json:"curve"`
	N                  int            `json:"n"`
	T                  int            `json:"t"`
	Seed               string         `json:"seed"`
	MessageHex         string         `json:"message_hex"`
	SaltHex            string         `json:"salt_hex"`
	Signers            []int          `json:"signers"`
	GroupKeyHex        string         `json:"group_key_hex"`
	SharesHex          map[int]string `json:"shares_hex"`
	VerSharesHex       map[int]string `json:"verification_shares_hex"`
	LambdaFullHex      map[int]string `json:"lambda_full_hex"`
	LambdaSignersHex   map[int]string `json:"lambda_signers_hex"`
	CommitsDHex        map[int]string `json:"commits_D_hex"`
	CommitsEHex        map[int]string `json:"commits_E_hex"`
	ResponsesZHex      map[int]string `json:"responses_z_hex"`
	SigRHex            string         `json:"sig_R_hex"`
	SigZHex            string         `json:"sig_z_hex"`
}

func main() {
	curveName := flag.String("curve", "ed25519", "curve: ed25519, secp256k1, ristretto255")
	n := flag.Int("n", 5, "number of parties")
	t := flag.Int("t", 3, "threshold")
	seed := flag.String("seed", "lens.cross.kat.v1", "deterministic RNG seed")
	msgStr := flag.String("message", "lens-cross-runtime-test-message", "message to sign")
	flag.Parse()

	c := pickCurve(*curveName)

	// DKG transcript over a deterministic stream (matches dkg_oracle).
	rng := blake3.New()
	_, _ = rng.Write([]byte("lens.dkg.oracle.rng:"))
	_, _ = rng.Write([]byte(*seed))
	dkgStream := rng.Digest()
	keyShares, gk, err := dkg.Run(c, *n, *t, dkgStream)
	if err != nil {
		fail("dkg.Run", err)
	}

	// Signing subset: smallest-id t.
	allIDs := make([]int, 0, len(keyShares))
	for id := range keyShares {
		allIDs = append(allIDs, id)
	}
	sort.Ints(allIDs)
	signers := append([]int(nil), allIDs[:*t]...)

	message := []byte(*msgStr)

	// Deterministic salt for hedged-nonce derivation.  We pin this to a
	// hash of (seed || curve || message) so the same JSON file fully
	// reproduces every byte of the transcript.
	saltHash := sha256.Sum256([]byte(fmt.Sprintf("salt|%s|%s|%s", *seed, c.Name(), *msgStr)))
	salt := saltHash[:]

	// Round 1.
	signersList := make([]*sign.Signer, 0, len(signers))
	commits := make(map[int]*sign.CommitMsg, len(signers))
	for _, id := range signers {
		s := sign.NewSigner(keyShares[id])
		if s == nil {
			fail("sign.NewSigner", fmt.Errorf("nil signer for %d", id))
		}
		signersList = append(signersList, s)
		c1, err := s.Round1(message, signers, fixedRand(salt))
		if err != nil {
			fail("Round1", err)
		}
		commits[id] = c1
	}

	// Round 2.
	responses := make(map[int]*sign.ResponseMsg, len(signers))
	for i, id := range signers {
		r, err := signersList[i].Round2(message, commits)
		if err != nil {
			fail("Round2", err)
		}
		responses[id] = r
	}

	// Aggregate.
	verShares := make(map[int]primitives.Point, len(signers))
	for _, id := range signers {
		verShares[id] = keyShares[id].VerificationShare
	}
	sig, err := sign.Aggregate(gk, message, signers, commits, responses, verShares)
	if err != nil {
		fail("Aggregate", err)
	}

	// λ over full party set + over signing subset.
	lambdaFull, err := primitives.Lagrange(c, allIDs)
	if err != nil {
		fail("Lagrange-full", err)
	}
	lambdaSigners, err := primitives.Lagrange(c, signers)
	if err != nil {
		fail("Lagrange-signers", err)
	}

	out := Vector{
		Curve:           c.Name(),
		N:               *n,
		T:               *t,
		Seed:            *seed,
		MessageHex:      hex.EncodeToString(message),
		SaltHex:         hex.EncodeToString(salt),
		Signers:         signers,
		GroupKeyHex:     hexPoint(gk.X),
		SharesHex:       map[int]string{},
		VerSharesHex:    map[int]string{},
		LambdaFullHex:   map[int]string{},
		LambdaSignersHex: map[int]string{},
		CommitsDHex:     map[int]string{},
		CommitsEHex:     map[int]string{},
		ResponsesZHex:   map[int]string{},
		SigRHex:         hexPoint(sig.R),
		SigZHex:         hexScalar(sig.Z),
	}
	for _, id := range allIDs {
		ks := keyShares[id]
		out.SharesHex[id] = hexScalar(ks.SkShare)
		out.VerSharesHex[id] = hexPoint(ks.VerificationShare)
		out.LambdaFullHex[id] = hexScalar(lambdaFull[id])
	}
	for _, id := range signers {
		out.LambdaSignersHex[id] = hexScalar(lambdaSigners[id])
		out.CommitsDHex[id] = hexPoint(commits[id].D)
		out.CommitsEHex[id] = hexPoint(commits[id].E)
		out.ResponsesZHex[id] = hexScalar(responses[id].Z)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fail("encode", err)
	}
}

// fixedRand returns an io.Reader that emits the supplied bytes once,
// then EOF.  The Lens Round1 hedge transcript reads exactly len(salt)
// bytes; supplying 32 bytes is sufficient and deterministic.
type fixedRandR struct {
	buf []byte
	off int
}

func (r *fixedRandR) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

func fixedRand(salt []byte) io.Reader {
	return &fixedRandR{buf: salt}
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
	fmt.Fprintf(os.Stderr, "lens-cross-runtime-oracle: %s: %v\n", stage, err)
	os.Exit(1)
}
