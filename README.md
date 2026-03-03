# Lens — Curve threshold kernel

> Lux is not merely adding post-quantum signatures to a chain; it defines a hybrid finality architecture for DAG-native consensus, with protocol-agnostic threshold lifecycle, post-quantum threshold sealing, and cross-chain propagation of Horizon finality.

See [LP-105 §Claims and evidence](https://github.com/luxfi/lps/blob/main/LP-105-lux-stack-lexicon.md#claims-and-evidence) for the canonical claims/evidence table and the ten architectural commitments — single source of truth.

Lens is the curve-based threshold signing kernel for Lux. It is the
classical sister to Pulsar (the lattice kernel at
[`github.com/luxfi/pulsar`](https://github.com/luxfi/pulsar)).

## Quick reference

| Component | Pulsar | Lens |
|---|---|---|
| Math field | Module-LWE / R_q | Discrete log over a prime-order group |
| Sign math | Corona Sign1/Sign2/Combine | FROST 2-round (RFC 9591) |
| Pedersen commits | A·NTT(s) + B·NTT(r) over R_q | s·G + r·H over the curve |
| Genesis | Trusted-dealer Bootstrap | Trusted-dealer Bootstrap **or** FROST DKG |
| Per-epoch DKG | Never — VSR via `pulsar/reshare` | Never — VSR via `lens/reshare` |
| Lifecycle | LSS-managed | LSS-managed |
| LSS adapter | `threshold/protocols/lss/lss_pulsar.go` | `threshold/protocols/lss/lss_lens.go` |

## Curves shipped

- **Ed25519** — RFC 8032 / FIPS 186-5 EdDSA curve.
- **secp256k1** — SEC 2 / Bitcoin curve.
- **Ristretto255** — RFC 9496 prime-order group over Curve25519.

All three implement `primitives.Curve`. Per-curve secondary generators
(`H`) are derived deterministically from a Lens-specific
nothing-up-my-sleeve tag (`lens.<curve>.h-base.v1`); discrete log of
`H` with respect to `G` is unknown to anyone, which is the only
property Pedersen binding requires.

## Package layout

```
primitives/  — curve abstraction, polynomial, Lagrange, Pedersen, Shamir, hash helpers
sign/        — FROST 2-round Schnorr threshold signing (RFC 9591)
threshold/   — GroupKey, KeyShare, Signer, Signature types
reshare/     — Refresh (HJKY97) + Reshare (Desmedt-Jajodia),
               Pedersen commits, complaints, transcript, pairwise KEX,
               activation cert
hash/        — HashSuite (Lens-SHA3 production / Lens-BLAKE3 legacy)
dkg/         — Distributed FROST key generation (proper distributed,
               no trusted dealer needed)
keyera/      — Bootstrap / Reshare / Reanchor lifecycle wrapper
cmd/         — KAT oracle binaries for cross-port byte-equal validation
```

## Running

```bash
GOWORK=off go test ./...
GOWORK=off go run ./cmd/reshare_oracle -curve ed25519 -variant reshare -t_old 3 -t_new 3
GOWORK=off go run ./cmd/dkg_oracle -curve secp256k1 -n 5 -t 3
```

## Lifecycle invariants

```
BLS lane:    each validator has its OWN keypair.
ML-DSA lane: each validator has its OWN keypair.
Lens lane:   each validator has a SHARE of one group key.
Pulsar lane: each validator has a SHARE of one group key.
```

Within a key era:

- Master secret `s` is preserved across every Reshare.
- Group public key `X = s·G` is byte-identical across resharing.
- Only the share distribution rotates per epoch.

Across key eras (Reanchor): `X` and `s` are fresh.

## References

- Komlo, Goldberg 2020. *FROST: Flexible Round-Optimized Schnorr
  Threshold Signatures.* SAC 2020.
- RFC 9591. *The Flexible Round-Optimized Schnorr Threshold (FROST)
  Protocol for Two-Round Schnorr Signatures.*
- HJKY97. *Proactive Secret Sharing or: How to Cope With Perpetual
  Leakage.* CRYPTO.
- Desmedt-Jajodia 1997. *Redistributing Secret Shares to New Access
  Structures.*
- Wong-Wang-Wing 2002. *Verifiable Secret Redistribution for Archive
  Systems.*
- Seesahai 2025. *LSS MPC ECDSA: A Pragmatic Framework for Dynamic and
  Resilient Threshold Signatures.* (LSS framework, paper-backed)
- LP-103. *Lens — Curve-Based Threshold Signatures with Dynamic
  Resharing.* https://github.com/luxfi/lps/blob/main/LP-103-lens.md
- LP-073. *Pulsar — lattice threshold sister kernel.*

## License

Apache-2.0. See [LICENSE](LICENSE).
