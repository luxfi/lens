// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import "testing"

// TestActivationMessageSignableBytesStable — same inputs → same bytes.
func TestActivationMessageSignableBytesStable(t *testing.T) {
	msg := &ActivationMessage{
		Transcript: TranscriptInputs{
			ChainID: []byte("test"), GroupID: []byte("g"), Variant: "reshare",
			ThresholdOld: 3, ThresholdNew: 3,
		},
		ReshareTranscript: ReshareTranscript{
			CommitDigests:   map[int][32]byte{1: {0x01}, 2: {0x02}},
			QualifiedQuorum: []int{1, 2, 3},
		},
	}
	a := msg.SignableBytes(nil)
	b := msg.SignableBytes(nil)
	if string(a) != string(b) {
		t.Fatal("SignableBytes not deterministic")
	}
}

// TestVerifyActivationGood/Bad covers the chain-side circuit-breaker.
func TestVerifyActivationCircuitBreaker(t *testing.T) {
	transcriptInputs := TranscriptInputs{
		ChainID: []byte("test"), GroupID: []byte("g"), Variant: "reshare",
		ThresholdOld: 3, ThresholdNew: 3,
	}
	exchange := ReshareTranscript{
		QualifiedQuorum: []int{1, 2, 3},
	}
	cert := &ActivationCert{
		Message: ActivationMessage{
			Transcript:        transcriptInputs,
			ReshareTranscript: exchange,
		},
		Signature: []byte("sigblob"),
	}
	good := func(_, _ []byte) bool { return true }
	bad := func(_, _ []byte) bool { return false }

	tHash := transcriptInputs.Hash(nil)
	xHash := exchange.Hash(nil)

	if err := VerifyActivation(cert, tHash, xHash, nil, good); err != nil {
		t.Errorf("good verify failed: %v", err)
	}
	if err := VerifyActivation(cert, tHash, xHash, nil, bad); err == nil {
		t.Error("bad verify should have failed")
	}

	// Mismatched transcript hash → ErrTranscriptMismatch.
	wrong := [32]byte{0xFF}
	if err := VerifyActivation(cert, wrong, xHash, nil, good); err == nil {
		t.Error("transcript mismatch should fail")
	}
}

// TestReshareTranscriptHashStable — deterministic exchange digest.
func TestReshareTranscriptHashStable(t *testing.T) {
	rt := ReshareTranscript{
		CommitDigests:       map[int][32]byte{1: {0x01}, 2: {0x02}, 3: {0x03}},
		ComplaintHashes:     [][32]byte{{0xAA}, {0xBB}},
		DisqualifiedSenders: []int{2},
		QualifiedQuorum:     []int{1, 3},
	}
	a := rt.Hash(nil)
	b := rt.Hash(nil)
	if a != b {
		t.Fatal("ReshareTranscript.Hash not deterministic")
	}
}
