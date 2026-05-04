// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"bytes"
	"errors"
	"testing"

	"github.com/luxfi/math/codec"
)

func encodeUvarint(out *bytes.Buffer, v uint64) {
	for v >= 0x80 {
		out.WriteByte(byte(v) | 0x80)
		v >>= 7
	}
	out.WriteByte(byte(v))
}

// TestValidateLengthPrefixedFrame_RejectsHugeLength — same regression
// that protects pulsar/wire. Lens consumes the same math/codec
// substrate, so the same attack input class is rejected uniformly.
func TestValidateLengthPrefixedFrame_RejectsHugeLength(t *testing.T) {
	const huge = uint64(70_368_955_777_453)
	var buf bytes.Buffer
	encodeUvarint(&buf, huge)
	err := ValidateLengthPrefixedFrame(buf.Bytes())
	if err == nil {
		t.Fatal("ValidateLengthPrefixedFrame returned nil for huge length")
	}
	if !errors.Is(err, codec.ErrLimitExceeded) {
		t.Errorf("err is not ErrLimitExceeded: %v", err)
	}
}

func TestValidateLengthPrefixedFrame_HappyPath(t *testing.T) {
	var buf bytes.Buffer
	encodeUvarint(&buf, 3)
	buf.Write([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	if err := ValidateLengthPrefixedFrame(buf.Bytes()); err != nil {
		t.Errorf("happy-path: %v", err)
	}
}

func TestValidateLengthPrefixedFrame_OverCap(t *testing.T) {
	var buf bytes.Buffer
	encodeUvarint(&buf, uint64(MaxLensSliceLen+1))
	err := ValidateLengthPrefixedFrame(buf.Bytes())
	if !errors.Is(err, codec.ErrLimitExceeded) {
		t.Errorf("err is not ErrLimitExceeded: %v", err)
	}
}
