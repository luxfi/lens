// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command cross_runtime_verify loads a cross-runtime KAT JSON emitted
// by the C++ Lens kernel (luxcpp/crypto/lens/test/cpp/
// cross_runtime_emit), drives the Go canonical with the same seed +
// message + salt, and asserts byte-equal across DKG / Sign / Aggregate.
//
// Usage: cross_runtime_verify <kat_dir>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luxfi/lens/dkg"
	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/sign"

	"github.com/zeebo/blake3"
)

type vector struct {
	Curve            string         `json:"curve"`
	N                int            `json:"n"`
	T                int            `json:"t"`
	Seed             string         `json:"seed"`
	MessageHex       string         `json:"message_hex"`
	SaltHex          string         `json:"salt_hex"`
	Signers          []int          `json:"signers"`
	GroupKeyHex      string         `json:"group_key_hex"`
	SharesHex        map[int]string `json:"shares_hex"`
	VerSharesHex     map[int]string `json:"verification_shares_hex"`
	LambdaFullHex    map[int]string `json:"lambda_full_hex"`
	LambdaSignersHex map[int]string `json:"lambda_signers_hex"`
	CommitsDHex      map[int]string `json:"commits_D_hex"`
	CommitsEHex      map[int]string `json:"commits_E_hex"`
	ResponsesZHex    map[int]string `json:"responses_z_hex"`
	SigRHex          string         `json:"sig_R_hex"`
	SigZHex          string         `json:"sig_z_hex"`
}

type fixedReader struct {
	buf []byte
	off int
}

func (r *fixedReader) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: cross_runtime_verify <kat_dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "glob: %v\n", err)
		os.Exit(1)
	}
	sort.Strings(files)
	pass, total := 0, 0
	for _, path := range files {
		total++
		if replay(path) {
			pass++
		}
	}
	fmt.Printf("\n=== reverse cross-runtime KAT (Go verifies C++ emit): %d/%d byte-equal ===\n",
		pass, total)
	if pass != total || total == 0 {
		os.Exit(1)
	}
}

func replay(path string) bool {
	fmt.Printf("--- %s\n", filepath.Base(path))
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("FAIL: read: %v\n", err)
		return false
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		fmt.Printf("FAIL: parse: %v\n", err)
		return false
	}
	c := pickCurve(v.Curve)
	salt, _ := hex.DecodeString(v.SaltHex)
	msg, _ := hex.DecodeString(v.MessageHex)

	// DKG over the same deterministic stream.
	rng := blake3.New()
	_, _ = rng.Write([]byte("lens.dkg.oracle.rng:"))
	_, _ = rng.Write([]byte(v.Seed))
	stream := rng.Digest()
	keyShares, gk, err := dkg.Run(c, v.N, v.T, stream)
	if err != nil {
		fmt.Printf("FAIL: dkg.Run: %v\n", err)
		return false
	}
	if got := hexPoint(gk.X); got != v.GroupKeyHex {
		fmt.Printf("FAIL: group_key got=%s want=%s\n", got, v.GroupKeyHex)
		return false
	}
	for id, want := range v.SharesHex {
		ks := keyShares[id]
		if ks == nil {
			fmt.Printf("FAIL: missing share %d\n", id)
			return false
		}
		if got := hexScalar(ks.SkShare); got != want {
			fmt.Printf("FAIL: share[%d]\n", id)
			return false
		}
		if got := hexPoint(ks.VerificationShare); got != v.VerSharesHex[id] {
			fmt.Printf("FAIL: ver_share[%d]\n", id)
			return false
		}
	}

	// Sign Round 1.
	signers := make([]*sign.Signer, 0, len(v.Signers))
	commits := make(map[int]*sign.CommitMsg, len(v.Signers))
	for _, id := range v.Signers {
		s := sign.NewSigner(keyShares[id])
		c1, err := s.Round1(msg, v.Signers, &fixedReader{buf: salt})
		if err != nil {
			fmt.Printf("FAIL: Round1[%d]: %v\n", id, err)
			return false
		}
		if got := hexPoint(c1.D); got != v.CommitsDHex[id] {
			fmt.Printf("FAIL: commit_D[%d]\n  got=  %s\n  want= %s\n",
				id, got, v.CommitsDHex[id])
			return false
		}
		if got := hexPoint(c1.E); got != v.CommitsEHex[id] {
			fmt.Printf("FAIL: commit_E[%d]\n", id)
			return false
		}
		signers = append(signers, s)
		commits[id] = c1
	}
	// Round 2.
	responses := make(map[int]*sign.ResponseMsg, len(v.Signers))
	for i, id := range v.Signers {
		r, err := signers[i].Round2(msg, commits)
		if err != nil {
			fmt.Printf("FAIL: Round2[%d]: %v\n", id, err)
			return false
		}
		if got := hexScalar(r.Z); got != v.ResponsesZHex[id] {
			fmt.Printf("FAIL: response_z[%d]\n", id)
			return false
		}
		responses[id] = r
	}
	// Aggregate.
	verShares := make(map[int]primitives.Point, len(v.Signers))
	for _, id := range v.Signers {
		verShares[id] = keyShares[id].VerificationShare
	}
	sig, err := sign.Aggregate(gk, msg, v.Signers, commits, responses, verShares)
	if err != nil {
		fmt.Printf("FAIL: Aggregate: %v\n", err)
		return false
	}
	if got := hexPoint(sig.R); got != v.SigRHex {
		fmt.Printf("FAIL: sig_R got=%s want=%s\n", got, v.SigRHex)
		return false
	}
	if got := hexScalar(sig.Z); got != v.SigZHex {
		fmt.Printf("FAIL: sig_z\n")
		return false
	}
	if err := sign.Verify(gk, msg, sig); err != nil {
		fmt.Printf("FAIL: Verify: %v\n", err)
		return false
	}
	fmt.Printf("PASS %s n=%d t=%d  byte-equal end-to-end\n",
		strings.TrimSpace(v.Curve), v.N, v.T)
	return true
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
		panic("unknown curve " + name)
	}
}

func hexScalar(s primitives.Scalar) string {
	b, _ := s.MarshalBinary()
	return hex.EncodeToString(b)
}

func hexPoint(p primitives.Point) string {
	b, _ := p.MarshalBinary()
	return hex.EncodeToString(b)
}
