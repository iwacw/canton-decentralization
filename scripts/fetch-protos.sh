#!/usr/bin/env bash
# Fetch the Canton/Daml protos this toolkit uses (plus transitive imports) from a pinned
# digital-asset/canton tag into proto/. Small download (~40 files, <1 MB).
set -euo pipefail

CANTON_REF="${CANTON_REF:-v3.5.19}"
SCALAPB_REF="${SCALAPB_REF:-v0.11.17}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/proto"
BASE="https://raw.githubusercontent.com/digital-asset/canton/$CANTON_REF/community"
ROOTS=(
  "$BASE/base/src/main/protobuf"
  "$BASE/admin-api/src/main/protobuf"
  "$BASE/ledger-api-proto/src/main/protobuf"
  "$BASE/daml-lf/ledger-api-value-proto/src/main/protobuf"
)
SEEDS=(
  com/digitalasset/canton/protocol/v30/topology.proto
  com/digitalasset/canton/crypto/v30/crypto.proto
  com/digitalasset/canton/version/v1/untyped_versioned_message.proto
  com/digitalasset/canton/topology/admin/v30/topology_manager_read_service.proto
  com/digitalasset/canton/topology/admin/v30/topology_manager_write_service.proto
  com/daml/ledger/api/v2/interactive/interactive_submission_service.proto
  com/daml/ledger/api/v2/interactive/transaction/v1/interactive_submission_data.proto
  com/daml/ledger/api/v2/admin/party_management_service.proto
  com/daml/ledger/api/v2/state_service.proto
)

rm -rf "$OUT"; mkdir -p "$OUT"
declare -A seen=()
queue=("${SEEDS[@]}")
while ((${#queue[@]})); do
  p="${queue[0]}"; queue=("${queue[@]:1}")
  [[ -n "${seen[$p]:-}" ]] && continue
  seen[$p]=1
  case "$p" in
    google/protobuf/*) continue ;;              # shipped with grpcio-tools
    google/rpc/*) continue ;;                   # googleapis-common-protos
    scalapb/scalapb.proto)
      mkdir -p "$OUT/scalapb"
      curl -sfL "https://raw.githubusercontent.com/scalapb/ScalaPB/$SCALAPB_REF/protobuf/scalapb/scalapb.proto" \
        -o "$OUT/$p"
      continue ;;
  esac
  ok=""
  for r in "${ROOTS[@]}"; do
    mkdir -p "$OUT/$(dirname "$p")"
    if curl -sfL "$r/$p" -o "$OUT/$p"; then ok=1; break; fi
  done
  [[ -n "$ok" ]] || { echo "not found: $p" >&2; exit 1; }
  while read -r dep; do queue+=("$dep"); done < <(sed -n 's/^import "\(.*\)";/\1/p' "$OUT/$p")
done
echo "canton=$CANTON_REF scalapb=$SCALAPB_REF" > "$OUT/VERSION"
find "$OUT" -name '*.proto' | sed "s|$OUT/||" | sort
