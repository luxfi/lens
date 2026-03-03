// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"encoding/binary"

	"github.com/zeebo/blake3"
)

// HashPoint returns BLAKE3-32 over a domain-separated tag and the
// canonical encoding of `p`. Used as a stable identifier for a
// curve-point in transcript hashing.
func HashPoint(tag string, p Point) [32]byte {
	h := blake3.New()
	_, _ = h.Write([]byte(tag))
	bytes, _ := p.MarshalBinary()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(bytes)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(bytes)
	var out [32]byte
	copy(out[:], h.Sum(nil)[:32])
	return out
}

// HashPoints returns BLAKE3-32 over a domain-separated tag and the
// canonical encoding of every point in `ps`, length-prefixed for
// unambiguous parsing.
func HashPoints(tag string, ps ...Point) [32]byte {
	h := blake3.New()
	_, _ = h.Write([]byte(tag))
	for _, p := range ps {
		bytes, _ := p.MarshalBinary()
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(bytes)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write(bytes)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil)[:32])
	return out
}
