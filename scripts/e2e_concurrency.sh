#!/usr/bin/env bash
# Concurrent push sweep: N pushers on distinct branches against one server.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODE="$ROOT/code"
cd "$CODE"

OUT="${SAFEHUB_CONCURRENCY_OUT:-$ROOT/code/eval/published/concurrency-latest.json}"
PUSHERS_LIST="${SAFEHUB_PUSHERS:-1 2 4 8}"
STARVE="${SAFEHUB_STARVE:-0}"
RAW="$(mktemp /tmp/safehub-conc-raw.XXXXXX)"
mv "$RAW" "$RAW.json" 2>/dev/null || true
RAW="${RAW}.json"
echo '{"cells":[]}' >"$RAW"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CODE/target}"
cargo build -p safehub-server -p safehub-cli -p sit-remote-safehub -q --release
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
SERVER_BIN="$TARGET_DIR/release/safehub-server"
SH="$TARGET_DIR/release/shub"
SIT="$TARGET_DIR/release/sit"
export PATH="$TARGET_DIR/release:$PATH"

DATA="$(mktemp -d /tmp/safehub-conc.XXXXXX)"
CFG="$(mktemp -d /tmp/safehub-conc-cfg.XXXXXX)"
WORK="$(mktemp -d /tmp/safehub-conc-work.XXXXXX)"
LISTEN="127.0.0.1:18090"
export SAFEHUB_HOST="http://$LISTEN"
export SAFEHUB_DATA="$DATA"
export HOME="$CFG"
export XDG_CONFIG_HOME="$CFG/.config"
mkdir -p "$XDG_CONFIG_HOME"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA" "$CFG" "$WORK" "$RAW"
}
trap cleanup EXIT

"$SERVER_BIN" --listen "$LISTEN" --data "$DATA" &
SERVER_PID=$!
for _ in $(seq 1 50); do
  if curl -sf "$SAFEHUB_HOST/v1/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl -sf "$SAFEHUB_HOST/v1/health" >/dev/null

"$SH" auth register --user alice --password alice-pw --hostname "$SAFEHUB_HOST"
"$SH" auth login --user alice --secret alice-pw --hostname "$SAFEHUB_HOST"
(
  cd "$WORK"
  "$SH" repo create conc --clone
)
SEED="$WORK/conc"
[[ -d "$SEED/.git" ]] || { echo "missing checkout $SEED"; exit 1; }
(
  cd "$SEED"
  git config user.email "conc@safehub"
  git config user.name "conc"
  echo "base $(date)" >> README.md || echo base > README.md
  git add -A
  git commit -qm "seed" || true
  # Warm tip so concurrent branch pushes have a parent head.
  "$SIT" push sit HEAD:refs/heads/main || "$SIT" push
)

append_cell() {
  CELL="$1" RAW="$RAW" python3 - <<'PY'
import json, os
path = os.environ["RAW"]
doc = json.load(open(path))
doc["cells"].append(json.loads(os.environ["CELL"]))
json.dump(doc, open(path, "w"), indent=2)
PY
}

for n in $PUSHERS_LIST; do
  echo "=== concurrent pushers n=$n ==="
  for i in $(seq 1 "$n"); do
    d="$WORK/p$i"
    rm -rf "$d"
    cp -R "$SEED" "$d"
    (
      cd "$d"
      # Unique branch names per cell so prior cells' refs do not collide.
      git checkout -q -B "branch-n${n}-$i"
      echo "payload-$i-$(date +%s%N)" > "f-$i.txt"
      git add "f-$i.txt"
      git commit -qm "conc $i"
    )
  done

  start=$(python3 -c 'import time; print(time.time())')
  pids=()
  for i in $(seq 1 "$n"); do
    (
      cd "$WORK/p$i"
      "$SIT" push sit "HEAD:refs/heads/branch-n${n}-$i" >"$WORK/out-$i.txt" 2>"$WORK/err-$i.txt"
    ) &
    pids+=($!)
  done
  ok=0
  fail=0
  for pid in "${pids[@]}"; do
    if wait "$pid"; then ok=$((ok+1)); else fail=$((fail+1)); fi
  done
  end=$(python3 -c 'import time; print(time.time())')
  wall=$(python3 -c "print(round($end - $start, 3))")
  retries=0
  if ls "$WORK"/err-*.txt >/dev/null 2>&1; then
    retries=$(grep -h "CAS conflict" "$WORK"/err-*.txt 2>/dev/null | wc -l | tr -d '[:space:]' || true)
  fi
  retries=${retries:-0}

  cell=$(RETRY="$retries" OK="$ok" FAIL="$fail" WALL="$wall" N="$n" python3 - <<'PY'
import json, os
ok=int(os.environ["OK"]); fail=int(os.environ["FAIL"]); wall=float(os.environ["WALL"]); n=int(os.environ["N"]); retries=int(os.environ["RETRY"] or 0)
print(json.dumps({
  "pushers": n,
  "wall_s": wall,
  "ok": ok,
  "fail": fail,
  "cas_retry_hints": retries,
  "throughput_pushes_per_s": round((ok / max(wall, 1e-6)), 3),
  "upload_window": 8,
  "note": "real concurrent sit push to distinct branches; CAS serializes tip append",
  "measured": True,
}))
PY
)
  append_cell "$cell"
  echo "  n=$n wall=${wall}s ok=$ok fail=$fail retries=$retries"
done

starve_json='{"note":"set SAFEHUB_STARVE=1 to run large-vs-small experiment"}'
if [[ "$STARVE" == "1" ]]; then
  echo "=== starvation: 1 large vs 4 small ==="
  cp -R "$SEED" "$WORK/large"
  (
    cd "$WORK/large"
    git checkout -q -B large
    dd if=/dev/zero of=big.bin bs=1048576 count=8 status=none
    git add big.bin
    git commit -qm "large"
  )
  for i in 1 2 3 4; do
    cp -R "$SEED" "$WORK/small$i"
    (
      cd "$WORK/small$i"
      git checkout -q -B "small-$i"
      echo "s$i" > s.txt
      git add s.txt
      git commit -qm "small $i"
    )
  done
  start=$(python3 -c 'import time; print(time.time())')
  ( cd "$WORK/large" && "$SIT" push sit HEAD:refs/heads/large >"$WORK/large.out" 2>"$WORK/large.err" ) & LPID=$!
  SMALL_PIDS=()
  for i in 1 2 3 4; do
    ( cd "$WORK/small$i" && "$SIT" push sit "HEAD:refs/heads/small-$i" >/dev/null 2>&1 ) &
    SMALL_PIDS+=($!)
  done
  # Bound wait so starvation non-completion is a measured outcome, not a hang.
  STARVE_BUDGET_S="${SAFEHUB_STARVE_BUDGET_S:-30}"
  elapsed=0
  while kill -0 "$LPID" 2>/dev/null && [[ $elapsed -lt $STARVE_BUDGET_S ]]; do
    sleep 1
    elapsed=$((elapsed + 1))
  done
  if kill -0 "$LPID" 2>/dev/null; then
    kill "$LPID" 2>/dev/null || true
    large_ok=false
  else
    if wait "$LPID"; then large_ok=true; else large_ok=false; fi
  fi
  # Wait on the small pushers only. A bare `wait` also waits on the
  # safehub-server this script backgrounded, which never exits, so the arm
  # would hang instead of reporting an outcome.
  for pid in "${SMALL_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  end=$(python3 -c 'import time; print(time.time())')
  # Shell booleans are the strings "true"/"false"; pass them through the
  # environment and parse, rather than interpolating bare words into Python.
  starve_json=$(LARGE_OK="$large_ok" START="$start" END="$end" \
    BUDGET="$STARVE_BUDGET_S" python3 -c '
import json, os
print(json.dumps({
  "large_completed": os.environ["LARGE_OK"] == "true",
  "wall_s": round(float(os.environ["END"]) - float(os.environ["START"]), 3),
  "budget_s": int(os.environ["BUDGET"]),
  "small_pushers": 4,
  "large_push_mib": 8,
  "measured": True,
  "note": ("one 8 MiB push against 4 concurrent small pushes under the CAS "
           "retry budget; large_completed=false means the large push was "
           "still retrying when the budget expired"),
}))
')
  echo "  starvation large_completed=$large_ok"
fi

python3 - <<PY
import json
from datetime import datetime, timezone
raw = json.load(open("$RAW"))
doc = {
  "note": "concurrency harness: real N concurrent pushers on distinct branches",
  "measured_at": datetime.now(timezone.utc).isoformat(),
  "cells": raw["cells"],
  "starvation": json.loads(r'''$starve_json'''),
}
open("$OUT", "w").write(json.dumps(doc, indent=2) + "\n")
print("wrote $OUT")
PY
trap - EXIT
kill "$SERVER_PID" 2>/dev/null || true
rm -rf "$DATA" "$CFG" "$WORK" "$RAW"
