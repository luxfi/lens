#!/usr/bin/env bash
# regen-kats.sh — deterministic regeneration + verification of every
# Lens KAT consumed by cross-language ports.
#
# Lens oracles emit JSON to stdout (no canonical fixed path), so we
# capture into a per-script-run scripts/kat/ directory and write a
# manifest. The directory is checked into .gitignore so successive
# runs only validate determinism, not contents on disk.
#
# Coverage:
#   - dkg_oracle: { ed25519, secp256k1, ristretto255 } × { (n=5,t=3),
#     (n=7,t=5) }     → 6 vectors
#   - reshare_oracle: same curves × (n=5,t=3)             → 3 vectors
#   - hash determinism + tag-distinct tests                → in-process

set -euo pipefail

LENS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KAT_DIR="${LENS_DIR}/scripts/kat"
MANIFEST="${LENS_DIR}/scripts/regen-kats.manifest.sha256"

VERIFY=0
if [[ "${1:-}" == "--verify" ]]; then
  VERIFY=1
fi

cd "${LENS_DIR}"
mkdir -p "${KAT_DIR}"

emit_dkg() {
  local curve="$1" n="$2" t="$3" out="$4"
  go run ./cmd/dkg_oracle -curve "${curve}" -n "${n}" -t "${t}" \
    -seed "lens.dkg.kat.v1" > "${out}"
}

emit_reshare() {
  local curve="$1" t_old="$2" t_new="$3" variant="$4" out="$5"
  go run ./cmd/reshare_oracle -curve "${curve}" \
    -t_old "${t_old}" -t_new "${t_new}" -variant "${variant}" \
    -seed "lens.reshare.kat.v1" > "${out}"
}

echo "[1/3] dkg_oracle KAT vectors"
for curve in ed25519 secp256k1 ristretto255; do
  emit_dkg "${curve}" 5 3 "${KAT_DIR}/dkg_${curve}_n5_t3.json"
  emit_dkg "${curve}" 7 5 "${KAT_DIR}/dkg_${curve}_n7_t5.json"
done

echo "[2/3] reshare_oracle KAT vectors"
for curve in ed25519 secp256k1 ristretto255; do
  emit_reshare "${curve}" 3 3 reshare \
    "${KAT_DIR}/reshare_${curve}_told3_tnew3.json"
  emit_reshare "${curve}" 3 5 reshare \
    "${KAT_DIR}/reshare_${curve}_told3_tnew5.json"
  emit_reshare "${curve}" 3 3 refresh \
    "${KAT_DIR}/refresh_${curve}_t3.json"
done

echo "[3/3] in-tree hash suite tests"
go test -count=1 -run "TestSuiteIDsAreDistinct|TestSuiteOperationsAreDeterministic|TestTagsAreDistinct|TestPairwiseCanonicalizesPair|TestDerivePairwiseDistinguishesFields" ./hash >/dev/null

# Build sha256 manifest.
TMP_MANIFEST="$(mktemp)"
trap 'rm -f "${TMP_MANIFEST}"' EXIT

# Stable order regardless of glob expansion. Paths in the manifest
# are relative to LENS_DIR so the manifest is portable across hosts.
find "${KAT_DIR}" -maxdepth 1 -name "*.json" -type f | sort | while read -r f; do
  rel="${f#${LENS_DIR}/}"
  shasum -a 256 "$f" | awk -v p="${rel}" '{print $1"  "p}'
done > "${TMP_MANIFEST}"

if [[ "${VERIFY}" == "1" ]]; then
  if [[ ! -f "${MANIFEST}" ]]; then
    echo "ERROR: --verify requested but no prior manifest at ${MANIFEST}"
    exit 2
  fi
  if ! diff -u "${MANIFEST}" "${TMP_MANIFEST}"; then
    echo "FAIL: manifest mismatch — Lens KAT regeneration is non-deterministic" >&2
    exit 3
  fi
  echo "OK: Lens KAT regeneration is byte-equal across runs ($(wc -l < "${MANIFEST}") files)"
else
  cp "${TMP_MANIFEST}" "${MANIFEST}"
  echo "wrote manifest: ${MANIFEST}"
  cat "${MANIFEST}"
fi
