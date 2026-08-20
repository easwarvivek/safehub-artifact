#!/usr/bin/env bash
# Run one lane of the sweep-2 (operations) sweep.
#
#   e13_ops_lane.sh <lane-number> <server-ip> "<operations>" "<depth points>"
#
# Lane N uses safehub port 18190+2N and control port 18191+2N, matching
# e13_serverfarm.sh, and namespace lN so lanes cannot collide on repository
# names or read each other's storage.
set -uo pipefail
LANE="${1:?lane}"; SRV="${2:?server ip}"; OPS="${3:?operations}"; PTS="${4:?depth points}"
HERE="$(cd "$(dirname "$0")" && pwd)"
export SAFEHUB_E13_SERVER="$SRV"
export SAFEHUB_E13_GIT_PORT=18191
export SAFEHUB_E13_SH_PORT=$((18190 + 2*LANE))
export SAFEHUB_E13_SVC_PORT=$((18191 + 2*LANE))
export SAFEHUB_E13_NS="l$LANE"
export SAFEHUB_E13_OPS="$OPS"
export SAFEHUB_E13_POINTS="$PTS"
export SAFEHUB_E13_REPS="${SAFEHUB_E13_REPS:-5}"
export SAFEHUB_E13_GCRYPT_REPS="${SAFEHUB_E13_GCRYPT_REPS:-3}"
export SAFEHUB_E13_DELTA_KIB="${SAFEHUB_E13_DELTA_KIB:-50}"
export SAFEHUB_E13_OPS_BASE_MB="${SAFEHUB_E13_OPS_BASE_MB:-4}"
export SAFEHUB_E13_ROOT="$HOME/e13-ops-run-l$LANE"
ART="${SAFEHUB_E13_ART:-$HOME/e13-ops-artifacts/lane$LANE}"
mkdir -p "$ART"
export SAFEHUB_E13_OUT="$ART/e13-ops-l$LANE.json"
export SAFEHUB_E13_ROWS="$ART/ops-l$LANE.jsonl"

case "$(df -P "$SAFEHUB_E13_ROOT" 2>/dev/null | awk 'NR==2{print $1}')" in
  tmpfs|*tmpfs*) echo "FATAL: state root is on tmpfs"; exit 1 ;;
esac
echo "lane $LANE  ops=[$OPS]  depths=[$PTS]  ns=l$LANE  art=$ART"
exec bash "$HERE/e2e_e13_ops.sh"
