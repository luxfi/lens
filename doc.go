// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package lens is the curve-based threshold signing kernel for Lux.
//
// Lens is the classical sister to Pulsar (the lattice kernel at
// github.com/luxfi/pulsar). Both kernels share the same lifecycle
// shape — Bootstrap → Reshare* → Reanchor — and the same activation
// circuit-breaker contract; they differ only in the math field they
// operate over:
//
//	Pulsar (PQ)        Lens (classical)
//	  Module-LWE         Discrete log over a prime-order group
//	  R_q                Curve scalar field
//	  Ringtail Sign      FROST 2-round Sign (RFC 9591)
//	  Lattice Pedersen   Curve Pedersen (g·s + h·r)
//
// # Layer separation
//
//	github.com/luxfi/lens (this module)
//	  ├── primitives/    curve abstraction, polynomial, Lagrange,
//	  │                  Pedersen commit, Shamir
//	  ├── sign/          FROST 2-round signing math (RFC 9591)
//	  ├── threshold/     GroupKey, KeyShare, Signer types
//	  ├── reshare/       Refresh (HJKY97) + Reshare (Desmedt-Jajodia),
//	  │                  Pedersen commits, complaints, transcript,
//	  │                  pairwise KEX, activation cert
//	  ├── hash/          HashSuite (Lens-SHA3 production /
//	  │                  Lens-BLAKE3 legacy)
//	  ├── dkg/           Distributed FROST key generation
//	  ├── keyera/        Bootstrap / Reshare / Reanchor lifecycle
//	  └── cmd/*_oracle/  KAT vector generators for cross-port
//	                     byte-equal validation
//
//	github.com/luxfi/threshold/protocols/lss/lss_lens.go
//	  └── LSS adapter — wires Generation tracking, Rollback, and
//	      Bootstrap-Dealer / Signature-Coordinator role separation
//	      onto the Lens kernel.
//
// # Lifecycle invariants
//
//	BLS lane:    each validator has its OWN keypair.
//	ML-DSA lane: each validator has its OWN keypair.
//	Lens lane:   each validator has a SHARE of one group key.
//	Pulsar lane: each validator has a SHARE of one group key.
//
// Within a key era:
//
//   - The hidden master secret s is preserved across every Reshare.
//   - The group public key X = s·G is byte-identical across resharing.
//   - Only the share distribution rotates per epoch.
//   - The error term and dealer state from Bootstrap are erased.
//
// Across key eras (Reanchor): X is fresh, s is fresh.
//
// # Three layers, one shipping path
//
//  1. Bootstrap — trusted-dealer ceremony at chain genesis OR FROST
//     DKG (proper distributed). Confined to one key era. Foundation
//     MPC ceremony, observable, single one-time trust event.
//  2. Reshare — preserves s and X; rotates share distribution. No
//     trusted dealer. Triggered by every validator-set change.
//  3. Reanchor — fresh GroupKey, new key era. Rare governance event;
//     same trust shape as Bootstrap.
//
// # Domain separation
//
// Every Lens-emitted message carries a distinct version-tagged prefix.
// No shared prefix between any two:
//
//	QUASAR-LENS-BUNDLE-v1     — Lens threshold cert over a bundle
//	QUASAR-LENS-SIGN1-v1      — FROST Round 1
//	QUASAR-LENS-SIGN2-v1      — FROST Round 2
//	QUASAR-LENS-AGGREGATE-v1  — FROST aggregate
//	QUASAR-LENS-REFRESH-v1    — Refresh activation cert
//	QUASAR-LENS-RESHARE-v1    — Reshare activation cert
//	QUASAR-LENS-ACTIVATE-v1   — generic activation alias
//	QUASAR-LENS-REANCHOR-v1   — Reanchor authorization
//
// # Activation cert
//
// After resharing finishes the math, the chain does NOT accept the
// new epoch on faith. The new committee threshold-signs an activation
// message under the UNCHANGED GroupKey using their freshly-derived
// shares; only when this signature verifies does the chain mark the
// new epoch live. See reshare/activation.go.
//
// # Cited works
//
//   - Komlo, Goldberg 2020. "FROST: Flexible Round-Optimized Schnorr
//     Threshold Signatures." SAC 2020.
//   - RFC 9591. "The Flexible Round-Optimized Schnorr Threshold
//     (FROST) Protocol for Two-Round Schnorr Signatures." 2024.
//   - HJKY97. Herzberg-Jakobsson-Jarecki-Krawczyk-Yung. "Proactive
//     Secret Sharing or: How to Cope With Perpetual Leakage."
//   - Desmedt-Jajodia 1997. "Redistributing Secret Shares to New
//     Access Structures."
//   - Wong-Wang-Wing 2002. "Verifiable Secret Redistribution for
//     Archive Systems."
//   - Seesahai 2025. "LSS MPC ECDSA: A Pragmatic Framework for
//     Dynamic and Resilient Threshold Signatures." (LSS framework)
//
// # Status
//
// Production-grade. All packages have unit + integration test coverage.
// LSS adapter at threshold/protocols/lss/lss_lens.go.
package lens
