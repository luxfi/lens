// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/sign"
	"github.com/luxfi/lens/threshold"
)

// TestFullReshareFlow is the end-to-end integration test:
//
//  1. Trusted-dealer setup of (s, X, shares).
//  2. Reshare onto a different validator set with a different t.
//  3. New committee threshold-signs an activation message.
//  4. Activation signature verifies under the unchanged GroupKey.
//
// This is the test suite the chain-level circuit-breaker depends on.
func TestFullReshareFlow(t *testing.T) {
	curves := []primitives.Curve{
		primitives.NewEd25519(),
		primitives.NewSecp256k1(),
		primitives.NewRistretto255(),
	}
	for _, c := range curves {
		t.Run(c.Name(), func(t *testing.T) {
			// Step 1: trusted-dealer setup.
			secret, err := c.SampleScalar(rand.Reader)
			if err != nil {
				t.Fatalf("sample: %v", err)
			}
			X := secret.ActOnBase()
			gk := threshold.NewGroupKey(c, X)
			const tOld, nOld = 3, 5
			_, oldShares, err := primitives.Shamir(c, secret, tOld, nOld, rand.Reader)
			if err != nil {
				t.Fatalf("Shamir: %v", err)
			}

			// Step 2: reshare to a new committee with new threshold.
			newSet := []int{6, 7, 8, 9, 10, 11, 12}
			tNew := 5
			newShareScalars, err := Reshare(c, oldShares, tOld, newSet, tNew, rand.Reader)
			if err != nil {
				t.Fatalf("Reshare: %v", err)
			}

			// Build new KeyShares (reshare exit-point: turn scalar shares
			// into full KeyShare instances).
			lambda, err := primitives.Lagrange(c, newSet)
			if err != nil {
				t.Fatalf("Lagrange: %v", err)
			}
			newShares := make(map[int]*threshold.KeyShare, len(newSet))
			for _, id := range newSet {
				ks := &threshold.KeyShare{
					Index:             indexOf(newSet, id),
					PartyID:           id,
					SkShare:           newShareScalars[id],
					VerificationShare: newShareScalars[id].ActOnBase(),
					Lambda:            lambda[id],
					GroupKey:          gk,
				}
				newShares[id] = ks
			}

			// Step 3: build the activation message and threshold-sign it.
			activation := &ActivationMessage{
				Transcript: TranscriptInputs{
					ChainID:               []byte("lux-mainnet"),
					NetworkID:             []byte("network-1"),
					GroupID:               []byte("lens-shadow"),
					KeyEraID:              1,
					OldGeneration:         0,
					NewGeneration:         1,
					ThresholdOld:          tOld,
					ThresholdNew:          uint32(tNew),
					Variant:               "reshare",
					CurveName:             c.Name(),
					HashSuiteID:           "Lens-SHA3",
					ImplementationVersion: "lens-test-1.0",
				},
				ReshareTranscript: ReshareTranscript{
					QualifiedQuorum: []int{1, 2, 3, 4, 5},
				},
			}
			activationBytes := activation.SignableBytes(nil)

			// Pick t_new of the new committee to sign.
			signers := newSet[:tNew]
			signersByID := make(map[int]*sign.Signer, tNew)
			commits := make(map[int]*sign.CommitMsg, tNew)
			for _, id := range signers {
				signersByID[id] = sign.NewSigner(newShares[id])
				cm, err := signersByID[id].Round1(activationBytes, signers, rand.Reader)
				if err != nil {
					t.Fatalf("Round1 for %d: %v", id, err)
				}
				commits[id] = cm
			}
			// Recompute lambdas for the SUBSET that signs.
			subsetLambda, err := primitives.Lagrange(c, signers)
			if err != nil {
				t.Fatalf("Lagrange subset: %v", err)
			}
			for _, id := range signers {
				newShares[id].Lambda = subsetLambda[id]
			}
			responses := make(map[int]*sign.ResponseMsg, tNew)
			for _, id := range signers {
				rm, err := signersByID[id].Round2(activationBytes, commits)
				if err != nil {
					t.Fatalf("Round2 for %d: %v", id, err)
				}
				responses[id] = rm
			}
			verShares := threshold.VerificationShares(newShares)
			activationSig, err := sign.Aggregate(gk, activationBytes, signers, commits, responses, verShares)
			if err != nil {
				t.Fatalf("Aggregate activation sig: %v", err)
			}

			// Step 4: verify under the unchanged GroupKey.
			if err := sign.Verify(gk, activationBytes, activationSig); err != nil {
				t.Fatalf("activation cert failed under unchanged GroupKey: %v", err)
			}

			// Verify the chain-side circuit-breaker accepts it.
			cert := &ActivationCert{
				Message:   *activation,
				Signature: nil, // raw bytes don't matter for Verify routing
			}
			tHash := activation.Transcript.Hash(nil)
			xHash := activation.ReshareTranscript.Hash(nil)
			err = VerifyActivation(cert, tHash, xHash, nil, func(message, _ []byte) bool {
				// Sub-routine: re-verify the FROST signature on `message`.
				if string(message) != string(activationBytes) {
					return false
				}
				return sign.Verify(gk, message, activationSig) == nil
			})
			if err != nil {
				t.Fatalf("VerifyActivation: %v", err)
			}
		})
	}
}

func indexOf(set []int, id int) int {
	for i, v := range set {
		if v == id {
			return i
		}
	}
	return -1
}
