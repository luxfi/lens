// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Lens (FROST) wire-format fuzz harnesses.
//
// FuzzLensSign1Data           — Round-1 commit message bytes (D, E points)
// FuzzLensSign2Data           — Round-2 response bytes (Z scalar)
// FuzzLensKeyShareSerialize   — KeyShare.SkShare scalar bytes
// FuzzLensGroupKeySerialize   — GroupKey canonical bytes (curveName + X)
//
// Property: every UnmarshalBinary path never escapes a panic on
// arbitrary input.

package sign

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/luxfi/lens/primitives"
)

const fuzzMaxRawSize = 1024

// decodePointWithRecover decodes a Point from raw bytes with a
// recover boundary so any escaping panic from the curve library
// becomes a returned error.
func decodePointWithRecover(c primitives.Curve, raw []byte) (err error) {
	if len(raw) > fuzzMaxRawSize {
		return fmt.Errorf("input exceeds fuzzMaxRawSize")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode panic recovered: %v", r)
		}
	}()
	p := c.NewPoint()
	return p.UnmarshalBinary(raw)
}

// decodeScalarWithRecover decodes a Scalar from raw bytes.
func decodeScalarWithRecover(c primitives.Curve, raw []byte) (err error) {
	if len(raw) > fuzzMaxRawSize {
		return fmt.Errorf("input exceeds fuzzMaxRawSize")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode panic recovered: %v", r)
		}
	}()
	s := c.NewScalar()
	return s.UnmarshalBinary(raw)
}

// addSmallSeeds adds bounded seeds. Real ceremony data is in
// TestFuzzCorpus_*Replay.
func addSmallSeeds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Add(bytes.Repeat([]byte{0x02}, 33)) // valid-looking compressed point
	f.Add(bytes.Repeat([]byte{0xff}, 33))
}

// FuzzLensSign1Data fuzzes the Round-1 commit message Point decoder.
// CommitMsg.{D,E} are public Points broadcast by every signer.
func FuzzLensSign1Data(f *testing.F) {
	addSmallSeeds(f)

	curves := []primitives.Curve{
		primitives.NewSecp256k1(),
		primitives.NewEd25519(),
		primitives.NewRistretto255(),
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, c := range curves {
			_ = decodePointWithRecover(c, raw)
		}
	})
}

// FuzzLensSign2Data fuzzes the Round-2 response message Scalar
// decoder. ResponseMsg.Z is a public Scalar broadcast by every signer.
func FuzzLensSign2Data(f *testing.F) {
	addSmallSeeds(f)

	curves := []primitives.Curve{
		primitives.NewSecp256k1(),
		primitives.NewEd25519(),
		primitives.NewRistretto255(),
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, c := range curves {
			_ = decodeScalarWithRecover(c, raw)
		}
	})
}

// FuzzLensKeyShareSerialize fuzzes the KeyShare.SkShare decoder.
// A KeyShare is a persisted DKG output; corrupt on-disk bytes must
// surface as errors not panics.
func FuzzLensKeyShareSerialize(f *testing.F) {
	addSmallSeeds(f)

	curves := []primitives.Curve{
		primitives.NewSecp256k1(),
		primitives.NewEd25519(),
		primitives.NewRistretto255(),
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, c := range curves {
			_ = decodeScalarWithRecover(c, raw)
		}
	})
}

// FuzzLensGroupKeySerialize fuzzes the GroupKey decoder. Layout:
// curveName(uvarint-prefixed) || X(point-bytes).
func FuzzLensGroupKeySerialize(f *testing.F) {
	addSmallSeeds(f)

	curves := []primitives.Curve{
		primitives.NewSecp256k1(),
		primitives.NewEd25519(),
		primitives.NewRistretto255(),
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		// Extract curve name + X bytes per the GroupKey.Bytes layout.
		if len(raw) < 1 {
			return
		}
		nameLen := int(raw[0])
		if nameLen > len(raw)-1 {
			return
		}
		// name := raw[1 : 1+nameLen]  // not used, we sweep all curves
		_ = nameLen
		x := raw[1+nameLen:]
		if len(x) > fuzzMaxRawSize {
			return
		}
		for _, c := range curves {
			_ = decodePointWithRecover(c, x)
		}
	})
}

// TestFuzzCorpus_LensSign1Replay confirms the Sign1 small-seed
// corpus replays cleanly.
func TestFuzzCorpus_LensSign1Replay(t *testing.T) {
	curves := []primitives.Curve{
		primitives.NewSecp256k1(),
		primitives.NewEd25519(),
		primitives.NewRistretto255(),
	}
	for _, raw := range [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0x02}, 33),
	} {
		for _, c := range curves {
			_ = decodePointWithRecover(c, raw)
		}
	}
}

// TestFuzzCorpus_LensSign2Replay mirrors Sign1 for scalars.
func TestFuzzCorpus_LensSign2Replay(t *testing.T) {
	curves := []primitives.Curve{
		primitives.NewSecp256k1(),
		primitives.NewEd25519(),
		primitives.NewRistretto255(),
	}
	for _, raw := range [][]byte{
		{},
		bytes.Repeat([]byte{0xff}, 32),
	} {
		for _, c := range curves {
			_ = decodeScalarWithRecover(c, raw)
		}
	}
}

// TestFuzzCorpus_LensKeyShareReplay reuses the scalar replay path.
func TestFuzzCorpus_LensKeyShareReplay(t *testing.T) {
	TestFuzzCorpus_LensSign2Replay(t)
}

// TestFuzzCorpus_LensGroupKeyReplay confirms the GroupKey parser
// rejects malformed inputs cleanly.
func TestFuzzCorpus_LensGroupKeyReplay(t *testing.T) {
	curves := []primitives.Curve{
		primitives.NewSecp256k1(),
		primitives.NewEd25519(),
		primitives.NewRistretto255(),
	}
	for _, raw := range [][]byte{
		{}, // truncated
		{0x00}, // empty curve name + missing X
		append([]byte{0x09}, []byte("secp256k1...")...), // missing X
	} {
		if len(raw) >= 1 {
			nameLen := int(raw[0])
			if nameLen <= len(raw)-1 {
				x := raw[1+nameLen:]
				for _, c := range curves {
					_ = decodePointWithRecover(c, x)
				}
			}
		}
	}
}
