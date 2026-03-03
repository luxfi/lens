// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package keyera is the lifecycle wrapper for a Lens group lineage.
//
// One KeyEra is opened by Bootstrap (a one-time foundation MPC ceremony
// at chain genesis or governance-gated Reanchor). The trust is confined
// to genesis of that key era. Subsequent validator-set rotations call
// Reshare, which preserves the GroupKey (G, H, X) and rotates only the
// share distribution; no trusted dealer is needed for resharing.
// Reanchor opens a new era with a fresh GroupKey for security-event
// response (rare, governance-gated).
//
// The single source of truth for the lifecycle is `lens/DESIGN.md` (in
// concept; see also pulsar/DESIGN.md and lps/LP-103-lens.md).
//
// Invariants (enforced loudly):
//
//	BLS lane:    each validator has its OWN keypair.
//	ML-DSA lane: each validator has its OWN keypair.
//	Lens lane:   each validator has a SHARE of one group key.
//	Pulsar lane: each validator has a SHARE of one group key.
//
// Within a key era:
//
//   - The same hidden signing secret s is preserved across epochs.
//   - The same group public key X = s·G is preserved.
//   - G and H are curve constants; they never change within or across
//     eras of the same curve.
//   - Only the share distribution of s rotates per epoch.
//
// Across key eras (Reanchor): X is fresh, s is fresh.
package keyera

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/luxfi/lens/hash"
	"github.com/luxfi/lens/primitives"
	"github.com/luxfi/lens/reshare"
	"github.com/luxfi/lens/threshold"
)

// Errors returned by the package.
var (
	ErrUninitialized    = errors.New("keyera: era is uninitialized")
	ErrInvalidThreshold = errors.New("keyera: threshold must satisfy 1 <= t <= n")
	ErrEmptyValidators  = errors.New("keyera: validator set is empty")
	ErrMissingShare     = errors.New("keyera: share missing for validator")
)

// LensKeyEraID is a monotonically increasing identifier for a key era.
// Bumped only on Reanchor (rare governance event). All resharings
// within an era keep the same era ID.
type LensKeyEraID uint64

// LensGroupID identifies one Lens group for grouped Quasar setups
// where validator sets are partitioned into smaller groups, each with
// its own GroupKey lineage. For the single-group case it is zero.
type LensGroupID uint64

// KeyEra is one Lens group lineage. The GroupKey (G, H, X) is set at
// Bootstrap and persists across every Reshare within the era. State
// is the current epoch's share distribution; it rotates each Reshare.
//
// HashSuiteID pins the hash profile this era was opened under. It is
// recorded at Bootstrap and remains immutable through every Reshare in
// the era (per pulsar/proofs/hash-suite-separation.tex Remark on
// era-pinning, mirrored on the curve-side sister kernel). Reanchor MAY
// change the suite for the new era. The field is read-only after
// Bootstrap returns; Reshare propagates it without parameterisation.
type KeyEra struct {
	EraID        LensKeyEraID
	GroupID      LensGroupID
	GroupKey     *threshold.GroupKey
	GenesisEpoch uint64
	HashSuiteID  string
	State        *EpochShareState
}

// EpochShareState is the per-epoch share distribution for a key era.
//
// Three lineage fields, kept distinct (do not collapse — they mean
// different things):
//
//   - KeyEraID: Lens group-key lineage. Bumps only at Reanchor (fresh
//     GroupKey).
//   - Generation: LSS resharing version within this key era. Bumps
//     every Refresh / Reshare under the same GroupKey.
//   - RollbackFrom: nonzero only when this state descends from a
//     Rollback (= the prior Generation that was reverted from). Zero
//     on ordinary forward transitions.
type EpochShareState struct {
	// Lineage (changes only at Reanchor).
	KeyEraID uint64

	// HashSuiteID is the pinned hash profile for this share state.
	// Mirrored from the parent KeyEra at Bootstrap and propagated
	// without modification through every Reshare. Reanchor opens a
	// NEW era which MAY pin a different value.
	HashSuiteID string

	// LSS lifecycle.
	Generation   uint64
	RollbackFrom uint64

	// Per-epoch state (rotates every Refresh / Reshare).
	Epoch      uint64
	Validators []string
	Threshold  int
	Shares     map[string]*threshold.KeyShare
}

// Bootstrap runs the one-time trusted-dealer ceremony at chain
// genesis or governance-gated Reanchor.
//
// The trust is confined to genesis of the key era: the dealer
// momentarily knows the master secret s while constructing the shares.
// If s is retained, copied, or exfiltrated, the long-lived Lens group
// key is compromised. Foundation MUST coordinate Bootstrap as a
// publicly observable MPC ceremony at chain launch.
//
// After Bootstrap returns, the master secret no longer exists in the
// dealer's memory. The chain only has the public GroupKey and the
// distributed shares.
//
// Use crypto/rand.Reader for the kernel's randomness when no specific
// ceremony source is provided. Tests pass a deterministic source.
//
// Bootstrap pins the production HashSuite (Lens-SHA3). Use
// BootstrapWithSuite to open an era under the legacy Lens-BLAKE3
// profile (for cross-suite KAT replay only — NOT for production).
func Bootstrap(
	c primitives.Curve,
	t int,
	validators []string,
	groupID LensGroupID,
	eraID LensKeyEraID,
	entropy io.Reader,
) (*KeyEra, error) {
	return BootstrapWithSuite(c, hash.Default(), t, validators, groupID, eraID, entropy)
}

// BootstrapWithSuite is the canonical entrypoint that explicitly pins
// the hash profile this era will run under. The supplied suite is
// recorded on the returned KeyEra and propagates unchanged through
// every Reshare; Reanchor opens a fresh era and MAY pin a different
// suite. Pass nil to use the production default (Lens-SHA3).
func BootstrapWithSuite(
	c primitives.Curve,
	suite hash.HashSuite,
	t int,
	validators []string,
	groupID LensGroupID,
	eraID LensKeyEraID,
	entropy io.Reader,
) (*KeyEra, error) {
	if len(validators) == 0 {
		return nil, ErrEmptyValidators
	}
	n := len(validators)
	if t < 1 || t > n {
		return nil, fmt.Errorf("%w: t=%d n=%d", ErrInvalidThreshold, t, n)
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	suite = hash.Resolve(suite)
	suiteID := suite.ID()

	// Sample master secret s and compute X = s·G.
	secret, err := c.SampleScalar(entropy)
	if err != nil {
		return nil, fmt.Errorf("keyera: sample secret: %w", err)
	}
	X := secret.ActOnBase()
	gk := threshold.NewGroupKey(c, X)

	// (t, n) Shamir share of secret.
	_, shareScalars, err := primitives.Shamir(c, secret, t, n, entropy)
	if err != nil {
		return nil, fmt.Errorf("keyera: Shamir: %w", err)
	}

	signerIDs := make([]int, n)
	for i := range signerIDs {
		signerIDs[i] = i + 1
	}
	lambda, err := primitives.Lagrange(c, signerIDs)
	if err != nil {
		return nil, fmt.Errorf("keyera: Lagrange: %w", err)
	}

	seeds, macKeys := derivePairwiseMaterial(n, entropy)

	state := &EpochShareState{
		KeyEraID:     uint64(eraID),
		HashSuiteID:  suiteID,
		Generation:   0,
		RollbackFrom: 0,
		Epoch:        0,
		Validators:   append([]string(nil), validators...),
		Threshold:    t,
		Shares:       make(map[string]*threshold.KeyShare, n),
	}
	for i, v := range validators {
		pid := i + 1
		ks := &threshold.KeyShare{
			Index:             i,
			PartyID:           pid,
			SkShare:           shareScalars[pid],
			VerificationShare: shareScalars[pid].ActOnBase(),
			Lambda:            lambda[pid],
			Seeds:             seeds,
			MACKeys:           macKeys[i],
			GroupKey:          gk,
		}
		state.Shares[v] = ks
	}

	// Erase dealer's master secret.
	reshare.EraseScalar(secret)

	return &KeyEra{
		EraID:        eraID,
		GroupID:      groupID,
		GroupKey:     gk,
		GenesisEpoch: 0,
		HashSuiteID:  suiteID,
		State:        state,
	}, nil
}

// Reshare evolves the era to a new committee while preserving GroupKey.
//
// The bare Shamir kernel runs in-process; for distributed deployments
// the consensus layer wraps this in the full Verifiable Secret
// Resharing exchange (commits, complaints, activation cert) defined
// in lens/reshare. This kernel exists to (a) drive the cryptographic
// core, (b) be reused as the trusted-collaborator path for
// single-process integration tests, and (c) provide a reference
// against which the distributed protocol can be byte-equality checked.
//
// rand defaults to crypto/rand.Reader.
func (era *KeyEra) Reshare(
	newValidators []string,
	newThreshold int,
	randSource io.Reader,
) (*EpochShareState, error) {
	if era == nil || era.GroupKey == nil || era.State == nil {
		return nil, ErrUninitialized
	}
	if len(newValidators) == 0 {
		return nil, ErrEmptyValidators
	}
	K := len(newValidators)
	if newThreshold < 1 || newThreshold > K {
		return nil, fmt.Errorf("%w: t=%d n=%d", ErrInvalidThreshold, newThreshold, K)
	}
	if randSource == nil {
		randSource = rand.Reader
	}
	c := era.GroupKey.Curve

	// Build oldShares map from current state.
	oldShares := make(map[int]primitives.Scalar, len(era.State.Shares))
	for _, v := range era.State.Validators {
		ks, ok := era.State.Shares[v]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingShare, v)
		}
		oldShares[ks.PartyID] = c.NewScalar().Set(ks.SkShare)
	}

	newCommitteeIDs := make([]int, K)
	for i := range newValidators {
		newCommitteeIDs[i] = i + 1
	}

	newShareScalars, err := reshare.Reshare(
		c,
		oldShares,
		era.State.Threshold,
		newCommitteeIDs,
		newThreshold,
		randSource,
	)
	if err != nil {
		return nil, fmt.Errorf("keyera: reshare kernel: %w", err)
	}

	lambda, err := primitives.Lagrange(c, newCommitteeIDs)
	if err != nil {
		return nil, fmt.Errorf("keyera: Lagrange: %w", err)
	}
	seeds, macKeys := derivePairwiseMaterial(K, randSource)

	nextState := &EpochShareState{
		KeyEraID: era.State.KeyEraID,
		// HashSuiteID is era-pinned; propagated, NOT a parameter.
		// Reshare cannot change the suite — see hash-suite-separation
		// theorem (proofs/pulsar/hash-suite-separation.tex; the same
		// reasoning applies on the curve-side sister kernel).
		HashSuiteID:  era.HashSuiteID,
		Generation:   era.State.Generation + 1,
		RollbackFrom: 0,
		Epoch:        era.State.Epoch + 1,
		Validators:   append([]string(nil), newValidators...),
		Threshold:    newThreshold,
		Shares:       make(map[string]*threshold.KeyShare, K),
	}
	for i, v := range newValidators {
		pid := i + 1
		ks := &threshold.KeyShare{
			Index:             i,
			PartyID:           pid,
			SkShare:           newShareScalars[pid],
			VerificationShare: newShareScalars[pid].ActOnBase(),
			Lambda:            lambda[pid],
			Seeds:             seeds,
			MACKeys:           macKeys[i],
			GroupKey:          era.GroupKey,
		}
		nextState.Shares[v] = ks
	}

	era.State = nextState
	return nextState, nil
}

// Reanchor opens a new key era with a fresh GroupKey. Use ONLY for
// security-event response — long-tail share leakage, suspected
// master-secret compromise, etc. The chain governance MUST authorize
// this; it is not a routine operation.
//
// Reanchor inherits the prior era's HashSuiteID. To migrate to a
// different suite (e.g. moving from legacy Lens-BLAKE3 to production
// Lens-SHA3) call ReanchorWithSuite.
func Reanchor(
	prev *KeyEra,
	c primitives.Curve,
	t int,
	validators []string,
	groupID LensGroupID,
	entropy io.Reader,
) (*KeyEra, error) {
	var suite hash.HashSuite
	if prev != nil && prev.HashSuiteID == hash.LegacyBLAKE3ID {
		suite = hash.NewLensBLAKE3()
	} else {
		suite = hash.Default()
	}
	return ReanchorWithSuite(prev, c, suite, t, validators, groupID, entropy)
}

// ReanchorWithSuite opens a new key era with a fresh GroupKey under
// the supplied HashSuite. Reanchor is the ONLY lifecycle entrypoint
// that may pin a hash profile different from the prior era's
// (Reshare cannot — that is enforced by Reshare not accepting a suite
// parameter). nil suite resolves to the production default.
func ReanchorWithSuite(
	prev *KeyEra,
	c primitives.Curve,
	suite hash.HashSuite,
	t int,
	validators []string,
	groupID LensGroupID,
	entropy io.Reader,
) (*KeyEra, error) {
	var nextEraID LensKeyEraID
	var nextEpoch uint64
	if prev != nil {
		nextEraID = prev.EraID + 1
		if prev.State != nil {
			nextEpoch = prev.State.Epoch + 1
		}
	}
	next, err := BootstrapWithSuite(c, suite, t, validators, groupID, nextEraID, entropy)
	if err != nil {
		return nil, err
	}
	next.GenesisEpoch = nextEpoch
	next.State.Epoch = nextEpoch
	return next, nil
}

// derivePairwiseMaterial generates per-pair PRF seeds and MAC keys for
// a committee of size K.
//
//	seeds[i][j] : 32 bytes, present for every (i, j).
//	macKeys[i][j] : 32 bytes, present for i != j; symmetric.
//
// In a single-process simulation the material is freshly drawn from
// randSource. In a distributed deployment the consensus layer
// overrides this with authenticated pairwise KEX from
// lens/reshare/pairwise.go.
func derivePairwiseMaterial(K int, randSource io.Reader) (map[int][][]byte, []map[int][]byte) {
	const kSize = 32
	seeds := make(map[int][][]byte, K)
	macKeys := make([]map[int][]byte, K)
	for i := 0; i < K; i++ {
		seeds[i] = make([][]byte, K)
		macKeys[i] = make(map[int][]byte, K-1)
	}
	for i := 0; i < K; i++ {
		for j := 0; j < K; j++ {
			buf := make([]byte, kSize)
			_, _ = io.ReadFull(randSource, buf)
			seeds[i][j] = buf
		}
	}
	for i := 0; i < K; i++ {
		for j := i + 1; j < K; j++ {
			buf := make([]byte, kSize)
			_, _ = io.ReadFull(randSource, buf)
			macKeys[i][j] = buf
			macKeys[j][i] = buf
		}
	}
	return seeds, macKeys
}
