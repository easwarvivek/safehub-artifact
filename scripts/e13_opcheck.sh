#!/usr/bin/env bash
# Local operating-point check: one point per experiment, run TWICE.
#
# Purpose is agreement and shape, not publication numbers. Two runs of the same
# point on the same host should agree; a cell that moves between them is not a
# measurement. Every arm is then checked against its cost model, because a curve
# that contradicts the model is a broken arm rather than a finding.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${SAFEHUB_OPCHECK_OUT:-$HOME/e13-opcheck}"
RUNS="${SAFEHUB_OPCHECK_RUNS:-2}"
mkdir -p "$OUT"

# Small points: this establishes agreement and ordering, not final numbers.
run_one() {  # label script mode point run extra...
  local label="$1" script="$2" mode="$3" point="$4" run="$5"; shift 5
  local root="$HOME/e13-oc-$label-$run"
  rm -rf "$root"
  echo "--- $label run $run ($(date -u +%H:%M:%S))"
  env "$@" \
    SAFEHUB_E13_MODE="$mode" SAFEHUB_E13_POINTS="$point" \
    SAFEHUB_E13_REPS=3 SAFEHUB_E13_GCRYPT_REPS=2 \
    SAFEHUB_E13_ROOT="$root" \
    SAFEHUB_E13_OUT="$OUT/$label-r$run.json" \
    SAFEHUB_E13_ROWS="$OUT/$label-r$run.jsonl" \
    bash "$ROOT/scripts/$script" >"$OUT/$label-r$run.out" 2>&1
  local rc=$?
  grep -E "^    " "$OUT/$label-r$run.out" || echo "    (no rows) rc=$rc"
  rm -rf "$root"
  return $rc
}

for r in $(seq 1 "$RUNS"); do
  run_one A1 e2e_e13_edit.sh delta     50   "$r" SAFEHUB_E13_BASE_MB=2
  run_one A2 e2e_e13_edit.sh filesz    1024 "$r" SAFEHUB_E13_BASE_MB=2 SAFEHUB_E13_EDIT_KIB=1
  run_one A3 e2e_e13_edit.sh nfiles    20   "$r" SAFEHUB_E13_BASE_MB=2 SAFEHUB_E13_EDIT_KIB=1 SAFEHUB_E13_NFILE_KIB=100
  run_one B  e2e_e13_repo.sh size      5    "$r"
  run_one C  e2e_e13_repo.sh depth     32   "$r" SAFEHUB_E13_DEPTH_BASE_MB=1
  run_one D  e2e_e13_repo.sh updates   20   "$r" SAFEHUB_E13_UPD_BASE_MB=1
  run_one E  e2e_e13_repo.sh revisions 25   "$r" SAFEHUB_E13_UPD_BASE_MB=1 SAFEHUB_E13_REV_FILE_KIB=256
done
echo "=== rows in $OUT ==="
ls "$OUT"/*.jsonl 2>/dev/null | while read -r f; do printf "  %-28s %s rows\n" "$(basename "$f")" "$(wc -l <"$f" | tr -d ' ')"; done
