# Lens — constant-time review (Gate 7)

**Scope:** every Lens code path that touches a secret share, a private
commit opening, or a verifier digest compared against an attacker-
supplied value. Mirror surface to `~/work/lux/pulsar/CONSTANT-TIME-REVIEW.md`.

**Status legend:**

- **(a)** Constant-time by construction; cite the underlying primitive.
- **(b)** Constant-time gap; documented; not exploitable because the
  value is public OR no remote timing oracle exists on this path.
- **(c)** MUST FIX before production.

**Headline:** zero (c) entries. All curve scalar/point primitives that
hold a secret share route through a constant-time backend (filippo.io
ed25519, gtank ristretto255). The two (b) entries are
(i) `reshare/commit.go` early-return on Pedersen mismatch (public-output
side-channel only, identical to the pulsar mirror), and (ii) the
`secp256k1`-backed scalar-mul operations from `decred/dcrd` which are
non-CT but only ever reached with public scalar inputs in Lens FROST
threshold mode.

---

## 1. Verifier paths

| Location | Status | Notes |
|---|---|---|
| `lens.sign.Verify` (`lens/sign/sign.go:314`) | **(a)** | Pure public-input path. The `lhs.Equal(rhs)` call routes to each curve's `Point.Equal`: ed25519 → `filippo.io/edwards25519.Point.Equal` returns int (CT) [3]; ristretto255 → `gtank/ristretto255.Element.Equal` returns int (CT) [4]; secp256k1 → see §5 (RHS public; CT-fold over `FieldVal.Equals`). |
| `lens.reshare.VerifyShareAgainstCommits` (`lens/reshare/commit.go:56`) | **(b)** | Delegates to `primitives.VerifyPedersenShare`. The internal `Equal` call short-circuits on the first slot mismatch — same posture as the pulsar mirror; the leaked information is bounded by the wire-broadcast complaint. **Documented; not exploitable beyond the position-of-first-mismatch which is anyway in the complaint message.** |
| `lens.reshare.VerifyActivation` (`lens/reshare/activation.go`) | **(a)** | `[32]byte` array equality is constant-time on the supported architectures (Go compiler emits SIMD for fixed-size array equality). The threshold-signature `verify` callback is delegated to the caller. |
| `lens.dkg` Round 2 verifier | **(a)** | Same pattern as the pulsar dkg2 path: byte-blob `Equal` over uniform-length point encodings. The lens DKG operates on Pedersen point commitments rather than ring polynomials; `Point.Equal` is constant-time on every supported curve (see §3 below). |

---

## 2. DKG complaint / verification

| Location | Status | Notes |
|---|---|---|
| Round 1 commit-share dimension check | **(a)** | Structural integer compares on public metadata. |
| Round 2 share verification (Pedersen identity over the curve) | **(a)** | `share·G + blind·H ?= Σ x^k · C_k` checked via `Point.Equal` — constant-time on ed25519 and ristretto255 (see §3); on secp256k1, `FieldVal.Equals` is XOR-fold CT, the only short-circuit is the `IsIdentity` branch which operates on public RHS. |
| Complaint identification (`lens/reshare/complaint.go`) | **(a)** | Operates on public complaint metadata (sender ID, complainer ID). |
| Disqualification quorum (`lens/reshare/complaint.go`) | **(a)** | Pure deterministic set filter on public IDs. |

---

## 3. Share handling

| Location | Status | Notes |
|---|---|---|
| `lens.keyera.Bootstrap` (`lens/keyera/keyera.go:117`) | **(a)** | One-time foundation MPC ceremony. The trusted dealer holds the master secret in memory only on its own host; no remote timing channel. The dealer erases the master secret via `reshare.EraseScalar` (`keyera.go:186`) before returning. |
| `lens.keyera.Reshare` (`lens/keyera/keyera.go:208`) | **(a)** | Lagrange recombination of secret share scalars with public Lagrange coefficients. Backed by the curve's constant-time Scalar Mul. The `c.NewScalar().Set(ks.SkShare)` per-validator copy uses the curve's CT `Set`. |
| `lens.reshare.EraseScalar` (`lens/reshare/keyshare.go:72`) | **(a)** | Implementation `s.Set(s.Curve().NewScalar())` — overwrites the receiver via the curve's CT scalar Set. The ed25519 and ristretto255 Set are CT; secp256k1 Set zeros the underlying `ModNScalar` array (CT word-fill). |
| Lens key-share derivation | **(a)** | Same trust boundary as keyera Bootstrap/Reshare. |

---

## 4. Scalar / ring operations

Lens does not have a polynomial-ring path; the relevant scalar/point
operations are entirely on the curve (covered by §5).

---

## 5. Lens curve operations (per-curve)

### Ed25519 (`lens/primitives/ed25519.go`)

| Operation | Status | Notes |
|---|---|---|
| Scalar Act / ActOnBase (`Scalar.Act`, `ActOnBase`) | **(a)** | `filippo.io/edwards25519.Point.ScalarMult` and `ScalarBaseMult` — constant-time per the package documentation [3]. This is the implementation backing `crypto/ed25519` since Go 1.17 and is the canonical CT Ed25519 implementation in Go. |
| Scalar Add / Sub / Mul / Negate / Invert | **(a)** | `edwards25519.Scalar` operations are all constant-time, including `Invert` (Fermat-based) [3]. |
| Point Add / Sub / Negate | **(a)** | All routed through `edwards25519.Point` which is CT [3]. |
| Equality (`Scalar.Equal`, `Point.Equal`) | **(a)** | Both return `int` deliberately to enforce CT use [3]. |
| Marshal / Unmarshal (`MarshalBinary` / `UnmarshalBinary`) | **(a)** | Canonical encoding via `Bytes` / `SetCanonicalBytes`. Rejection on malformed input is on public input (received from the wire). |

### secp256k1 (`lens/primitives/secp256k1.go`)

| Operation | Status | Notes |
|---|---|---|
| Scalar Act / ActOnBase | **(b)** | `decred/dcrd/dcrec/secp256k1/v4.ScalarMultNonConst` / `ScalarBaseMultNonConst` are explicitly non-constant-time. **In Lens, every secp256k1 scalar-on-point operation in production paths uses a public scalar:** `binding factor ρ`, `challenge c`, `Lagrange coefficient λ`. The only secret scalar in FROST is the share `s_i`, and it is multiplied by other scalars (CT, see next row) before being multiplied by a point. **Documented gap; not exploitable in current call sites.** Action: if a future single-party secp256k1 path lands (e.g. validator-local Bitcoin-key signing), swap to a CT scalar-mul (e.g. `crypto/ecdsa`'s internal). |
| Scalar Add / Sub / Mul / Negate (`ModNScalar`) | **(a)** | `secp256k1.ModNScalar.{Add,Mul,etc.}` are constant-time per the dcrd source (10×26-bit limb representation, branch-free reduction). |
| Scalar Invert (`InverseNonConst`) | **(b)** | Explicitly non-CT. **Only invoked from `primitives.Lagrange`** over public committee IDs (the secret share is never inverted). |
| Point Equal (`secp256k1Point.Equal`) | **(b)** | Short-circuits on `IsIdentity` (public branch); after normalization, `FieldVal.Equals` is XOR-fold CT. The receiver and `other` are typically both public (verifier-aggregated commitments). |
| Encoding (`MarshalBinary`, `UnmarshalBinary`) | **(a)** | Compressed-point encoding (33 bytes). The `IsIdentity` branch produces a `0x00`-prefixed all-zero blob in CT (no leakage about whether the point is identity, beyond what the byte already says publicly). |

### Ristretto255 (`lens/primitives/ristretto255.go`)

| Operation | Status | Notes |
|---|---|---|
| Scalar Act / ActOnBase | **(a)** | `gtank/ristretto255.Element.ScalarMult` / `ScalarBaseMult` — constant-time per package documentation [4]. The package is explicitly designed for PAKE/OPAQUE/Schnorr deployments where CT is required. |
| Scalar Add / Sub / Mul / Negate / Invert | **(a)** | All `ristretto255.Scalar` ops are CT [4]. |
| Equal (`Scalar.Equal`, `Element.Equal`) | **(a)** | Returns `int` (0/1), deliberately CT [4]. |
| FromUniformBytes (hash-to-scalar / hash-to-curve) | **(a)** | Implements RFC 9496 §4.3.4 Elligator2; CT by construction. |
| Encoding | **(a)** | RFC 9496 canonical encoding; `SetCanonicalBytes` rejects malformed input via a CT-friendly square-root branch (per RFC 9496 §4.3.5). |

---

## (c) entries

**None.**

The (b) entries are:

1. **`lens/reshare/commit.go:VerifyShareAgainstCommits`** — short-circuit
   on Pedersen mismatch coordinate. Same pattern as the pulsar mirror;
   addressed at the next reshare protocol revision when both modules
   migrate to a uniform CT helper.

2. **`lens/primitives/secp256k1.go`** — `dcrd` non-CT scalar mul / scalar
   invert. Only reached with public scalar inputs in current FROST
   threshold deployments. Reroute when a single-party secp256k1 path
   is added.

Neither blocks the Mar-3 Architecture Freeze.

---

## Citations

- [1] `~/work/lux/luxcpp/crypto/ringtail/RED-DKG-REVIEW.md` Findings 5/6.
- [2] https://pkg.go.dev/crypto/subtle#ConstantTimeCompare
- [3] https://pkg.go.dev/filippo.io/edwards25519
- [4] https://pkg.go.dev/github.com/gtank/ristretto255

## Cross-references

- Pulsar surfaces: `~/work/lux/pulsar/CONSTANT-TIME-REVIEW.md`
- Proof anchor: `proofs/definitions/transcript-binding.tex`
- Threshold framework: `~/work/lux/threshold` (orchestration, not in
  scope for this audit; threshold-layer CT properties inherit from
  pulsar/lens kernels).
