// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package wire is lens's wire-format hardening boundary.
//
// LP-107 Phase 4: lens consumes luxfi/math/codec for bounded
// decoding of curve-point and scalar slices on untrusted input
// (DKG broadcast frames, threshold-share blobs, partial-signature
// aggregation buffers).
//
// Lens deals in curve points (Ed25519 / secp256k1 / Ristretto255 —
// 32-byte each) and scalars (32-byte each), so the wire-format risk
// surface is smaller than pulsar's lattice Vector[Poly] frames. We
// still route the byte streams through luxfi/math/codec.Reader so
// the substrate's bounded-decode contract applies uniformly across
// the Lux protocol stack.
package wire

import (
	"bytes"
	"fmt"

	"github.com/luxfi/math/codec"
)

// MaxLensSliceLen — Lens caps participant + share counts well below
// any lattice cap. With production t-of-n at most ~256, 4096 is a
// generous but conservative bound.
const MaxLensSliceLen = 4096

// LensWireLimits is the codec.Limits configuration lens uses for
// every untrusted-input frame.
var LensWireLimits = codec.Limits{
	MaxFrameBytes:     1 * 1024 * 1024, // 1 MiB — much smaller than pulsar
	MaxUint16SliceLen: MaxLensSliceLen,
	MaxUint32SliceLen: MaxLensSliceLen,
	MaxUint64SliceLen: MaxLensSliceLen,
	MaxDepth:          3,
}

// ValidateLengthPrefixedFrame walks a length-prefixed slice frame
// (one varint length + payload bytes) and asserts the length is
// within MaxLensSliceLen. Returns an error wrapping codec.ErrLimitExceeded
// when the cap is exceeded.
//
// Use this for any wire format whose first field is a variable-length
// vector of curve points or scalars where the count is attacker-
// controlled.
func ValidateLengthPrefixedFrame(frame []byte) error {
	r, err := codec.NewReader(bytes.NewReader(frame), LensWireLimits)
	if err != nil {
		return fmt.Errorf("lens/wire: NewReader: %w", err)
	}
	if _, err := r.ReadUint64Slice(); err != nil {
		return fmt.Errorf("lens/wire: outer length: %w", err)
	}
	return nil
}
