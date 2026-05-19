# Lens (LP-103) Curve-Side Threshold — Patent Claim Drafts (Attorney Review)

> **Internal working document.** Bundle #12 of the Lux PATENT-INVENTORY.
> Not a filed application; not a legal opinion.

## §0 Bundle summary

- **Title**: A discrete-logarithm-side threshold-signing kernel
  sharing the Bootstrap → Reshare → Reanchor lifecycle, activation
  circuit-breaker, identifiable abort, and HashSuite injection
  patterns of its post-quantum lattice sibling kernel (Pulsar),
  providing a uniform threshold-signing API across discrete-log
  AND lattice fields.
- **Inventors**: Lux Industries cryptography team.
- **Priority date**: file as US provisional within 12 months OR
  defensive publication.
- **Estimated claim count**: 13 (1 independent + 12 dependent).
- **Defensive-vs-offensive**: **Defensive (with offensive option).**

## §1 Background and prior art

1. **FROST RFC 9591** (Komlo-Goldberg, 2025): threshold Schnorr
   over discrete-log groups.
2. **GG18/GG20** (Gennaro-Goldfeder 2018/2020): threshold ECDSA.
3. **CGGMP21** (Canetti-Gennaro-Goldfeder-Makriyannis-Peled 2021):
   threshold ECDSA with proactive resharing.
4. **HJKY97** (Herzberg et al. 1997): proactive secret sharing.
5. **Pulsar** (luxfi/pulsar): the lattice sibling that
   Lens mirrors structurally.

Lens implements:
- DKG (FROST-style for the classical field; mirroring Pulsar's
  DKG2 structurally).
- Reshare with HJKY97 (curve Pedersen commits).
- Reanchor (rare governance event).
- Activation circuit-breaker (verify the new committee can
  threshold-sign before accepting it).
- HashSuite (`Lens-SHA3` production / `Lens-BLAKE3` legacy).
- Cross-port byte-equal KAT validation.

Lux's claim is NOT to threshold Schnorr or FROST itself
(prior art); the claim is to the **uniform lifecycle API**
across PQ and classical kernels.

## §2 Inventive concept

```
github.com/luxfi/lens     # classical (DL)
github.com/luxfi/pulsar   # lattice (M-LWE)
github.com/luxfi/corona   # lattice (R-LWE)
github.com/luxfi/magnetar # hash (SLH-DSA seed)
```

All four kernels share the same lifecycle methods and call signatures:

```
Bootstrap(committee, threshold, hashSuite) -> (GroupKey, Shares)
Reshare(oldCommittee, newCommittee, shares) -> Shares'
Reanchor(committee, threshold, hashSuite) -> (GroupKey', Shares')
Sign(message, partialShares) -> Signature
Verify(GroupKey, message, signature) -> bool
VerifyActivation(σ_test, transcript, GroupKey) -> bool
```

A single LSS (Lux Secret Sharing) adapter wires Generation
tracking, Rollback, and role separation (Bootstrap-Dealer vs
Signature-Coordinator) onto whichever kernel is in use.

## §3 Independent claim (draft)

> **Claim 1.** A computer-implemented method for providing a
> uniform threshold-signing application programming interface
> across cryptographic kernels operating in distinct
> mathematical fields, the method comprising:
>
> (a) defining a kernel interface comprising the operations:
>     `Bootstrap`, `Reshare`, `Reanchor`, `Sign`, `Verify`, and
>     `VerifyActivation`, each operation specified by signature
>     and semantic contract;
>
> (b) implementing the kernel interface for a first kernel
>     operating over a prime-order discrete-logarithm group,
>     producing signatures verifiable under a discrete-logarithm
>     verifier;
>
> (c) implementing the kernel interface for a second kernel
>     operating over a Module-Lattice ring `R_q`, producing
>     signatures verifiable under an FIPS 204 ML-DSA-65 verifier;
>
> (d) implementing the kernel interface for a third kernel
>     operating over a Ring-Lattice ring `R_q`, producing
>     signatures verifiable under a Ring-LWE-threshold verifier
>     (Corona);
>
> (e) providing a single Lux Secret Sharing adapter that:
>
>     (e1) wraps any kernel implementing the interface;
>
>     (e2) tracks Generation counters and supports Rollback;
>
>     (e3) separates the Bootstrap-Dealer role (used only at
>          chain genesis and rare governance-gated reanchor)
>          from the Signature-Coordinator role (rotated per
>          consensus round); and
>
> (f) configuring a blockchain consensus protocol to select the
>     kernel at runtime via a security-profile selector,
>     allowing the protocol to operate over the discrete-log
>     kernel for legacy compatibility, the M-LWE kernel for
>     production post-quantum finality, the R-LWE kernel for
>     defense-in-depth, or a multi-kernel combination producing
>     parallel certificates over disjoint hardness assumptions.

## §4 Dependent claims (drafts)

**Claim 2.** The method of claim 1, wherein the discrete-log
kernel is built on the Edwards curve Ed25519 / Curve25519, the
Module-Lattice kernel is built on the FIPS 204 ML-DSA-65
parameter set, and the Ring-Lattice kernel is built on the
Corona / Boschini ePrint 2024/1113 parameter set.

**Claim 3.** The method of claim 1, wherein the `Bootstrap`
operation requires a one-time multi-party computation ceremony
with at least one honest participant, and the `Reshare` operation
is dealerless and does NOT require any participant to be honest
beyond the threshold count.

**Claim 4.** The method of claim 1, wherein the `Reanchor`
operation is a rare governance event opening a new key era with
fresh group public key and fresh share distribution, and the
previous era's group public key is archived for historical
verification.

**Claim 5.** The method of claim 1, wherein `VerifyActivation`
returns success only if the new committee successfully
threshold-signs a canonical activation transcript under the
unchanged group public key from the previous epoch.

**Claim 6.** The method of claim 1, wherein each kernel
incorporates a HashSuite injection point such that the SP 800-
185 hash function (KMAC, cSHAKE, or TupleHash) used for
challenge derivation is configurable per chain, with the
HashSuite identifier era-pinned at Bootstrap and immutable
through every Reshare in the era.

**Claim 7.** The method of claim 1, wherein every kernel produces
identifiable-abort evidence via a typed
`AbortEvidence{Kind, Accuser, Accused, Evidence, Signature}`
envelope, the envelope format identical across all kernels and
suitable for protocol-level slashing.

**Claim 8.** The method of claim 1, wherein every kernel
maintains cross-port byte-equality with a C++ implementation via
a Known-Answer-Test (KAT) manifest enforced in continuous
integration.

**Claim 9.** The method of claim 1, wherein the security
profile of step (f) selects one of: discrete-log only (legacy
classical), M-LWE only (Pulsar production), R-LWE only (Corona),
discrete-log + M-LWE (BLS + Pulsar dual hardness), and
discrete-log + M-LWE + R-LWE (Quasar triple hardness).

**Claim 10.** The method of claim 1, wherein the `Sign` operation
is two-round for the lattice kernels (commit + response) and
single-round for the discrete-log kernel (Schnorr-style),
abstracted behind the same kernel interface such that the LSS
adapter does not require kernel-specific round-handling logic.

**Claim 11.** The method of claim 1, wherein the `Sign`
operation for the M-LWE kernel produces output byte-equal to a
single-party FIPS 204 ML-DSA-65 signature, allowing FIPS 140-3-
validated verifiers to accept the threshold signature
unmodified.

**Claim 12.** The method of claim 1, wherein the kernel-
selection is recorded in the chain's block headers via a
`FinalitySchemeID` field, allowing on-chain proof of the kernel
under which each block was finalized.

**Claim 13.** A non-transitory computer-readable medium storing
the Go source code of the `lens`, `pulsar`, and `corona`
kernels' implementations of the kernel interface, together with
the `threshold/protocols/lss/lss_lens.go`,
`threshold/protocols/lss/lss_pulsar.go`, and
`threshold/protocols/lss/lss_corona.go` adapter files.

## §5 Reference to implementation

- `~/work/lux/lens/doc.go` (kernel interface description).
- `~/work/lux/lens/{primitives,sign,threshold,reshare,hash,dkg,keyera}/`.
- `~/work/lux/pulsar/`,
- `~/work/lux/corona/`,
- `~/work/lux/magnetar/`,
- `~/work/lux/threshold/protocols/lss/`.

## §6 Defensive vs offensive

**DEFENSIVE.** The interface-level uniformity is more of an API-
design pattern than a hard technical invention. Defensive
publication recommended unless attorney elevates the prospect.

---

**Document metadata**
- Path: `lens/docs/patent-claims-lens-lifecycle.md`
- Bundle: #12 of `lps/PATENT-INVENTORY.md`
- Created: 2026-05-19
