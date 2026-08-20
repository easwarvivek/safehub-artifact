#!/usr/bin/env bash
# Eval E02 — decouple repository size from per-push delta.
#
# The published size sweep grew the working tree and the history depth at the
# same time, so no row can attribute its cost to either axis. This harness runs
# the two one-dimensional sweeps that separate the axes:
#
#   Arm A  fixed delta, varying history depth
#   Arm B  fixed history depth, varying per-push delta
#
# Every push in an arm is a sample, so per-push cells carry median + IQR rather
# than a single shot, and clone/fetch are repeated SAFEHUB_EVAL_REPS times.
#
# Env:
#   SAFEHUB_DD_DEPTHS="5 10 15 20 25 30 40 50 75 100"   arm A depths
#   SAFEHUB_DD_FIXED_DELTA_KIB=64                       arm A per-push delta
#   SAFEHUB_DD_DELTAS_KIB="8 16 32 48 64 96 128 192 256 512 1024"  arm B deltas
#   SAFEHUB_DD_FIXED_DEPTH=20                           arm B depth
#   SAFEHUB_DD_BASE_MIB=4                               seeded tree present before either arm
#
# Publishes: code/eval/published/depth-delta-latest.json
#
# Modes:
#   SAFEHUB_DD_MODE=fast  (default) — analytical cells + measured AEAD micro
#   SAFEHUB_DD_MODE=e2e             — full sit:// server sweep (expensive)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/eval_common.sh"

MODE="${SAFEHUB_DD_MODE:-fast}"
if [[ "$MODE" == "fast" ]]; then
  echo "==> E02 fast path (SAFEHUB_DD_MODE=fast)"
  exec python3 "$SCRIPT_DIR/gen_depth_delta_latest.py"
fi
echo "==> E02 full E2E path (SAFEHUB_DD_MODE=$MODE)"

OUT="${SAFEHUB_DD_OUT:-$EVAL_PUB/depth-delta-latest.json}"
DEPTHS="${SAFEHUB_DD_DEPTHS:-5 10 15 20 25 30 40 50 75 100}"
FIXED_DELTA_KIB="${SAFEHUB_DD_FIXED_DELTA_KIB:-64}"
DELTAS_KIB="${SAFEHUB_DD_DELTAS_KIB:-8 16 32 48 64 96 128 192 256 512 1024}"
FIXED_DEPTH="${SAFEHUB_DD_FIXED_DEPTH:-20}"
BASE_MIB="${SAFEHUB_DD_BASE_MIB:-4}"
LISTEN="127.0.0.1:18111"
GIT_LISTEN="127.0.0.1"
GIT_PORT="18112"
export SAFEHUB_HOST="http://$LISTEN"

DATA="$(mktemp -d /tmp/safehub-dd-data.XXXXXX)"
CFG="$(mktemp -d /tmp/safehub-dd-cfg.XXXXXX)"
WORK="$(mktemp -d /tmp/safehub-dd-work.XXXXXX)"
GIT_BASE="$WORK/git-base"
ROWS="$WORK/rows.jsonl"
: >"$ROWS"
export HOME="$CFG"
export XDG_CONFIG_HOME="$CFG/.config"
export SAFEHUB_DATA="$DATA"
mkdir -p "$XDG_CONFIG_HOME"

SERVER_PID=""
GIT_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "$GIT_PID" ]] && kill "$GIT_PID" 2>/dev/null || true
  rm -rf "$DATA" "$CFG" "$WORK"
}
trap cleanup EXIT

eval_build safehub-server safehub-cli sit-remote-safehub
eval_start_server "$LISTEN" "$DATA"
mkdir -p "$GIT_BASE"
git daemon --base-path="$GIT_BASE" --export-all --enable=receive-pack \
  --listen="$GIT_LISTEN" --port="$GIT_PORT" --reuseaddr \
  >"$WORK/git-daemon.log" 2>&1 &
GIT_PID=$!
for _ in $(seq 1 80); do
  (exec 3<>"/dev/tcp/$GIT_LISTEN/$GIT_PORT") 2>/dev/null && {
    exec 3<&- 3>&-
    break
  }
  sleep 0.1
done
kill -0 "$GIT_PID" 2>/dev/null || {
  echo "git daemon failed to start" >&2
  exit 1
}
"$SH" auth register --user alice --password alice-dd-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default || true

# Source-shaped, compressible payload: a random-byte delta would make every
# packfile incompressible and turn the delta axis into a pure I/O measurement.
write_delta() {
  python3 - "$1" "$2" "$3" <<'PY'
import random, sys
from pathlib import Path
path, kib, seed = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
rng = random.Random(seed)
idents = ["resolve", "encode", "verify", "merge", "index", "flush", "render"]
types = ["u64", "usize", "String", "Vec<u8>"]
lines = ["// Copyright (c) 2026 The SafeHub Evaluation Authors.",
         "use std::collections::BTreeMap;", "use anyhow::Result;", ""]
target = kib * 1024
size = sum(len(x) + 1 for x in lines)
i = 0
while size < target:
    name = rng.choice(idents)
    ty = rng.choice(types)
    block = [
        f"/// Revision {seed} unit {i}.",
        f"pub fn {name}_{seed}_{i}(input: &{ty}) -> Result<{ty}> {{",
        "    let mut out = input.clone();",
        f"    for _ in 0..{rng.randint(1, 9)} {{",
        "        out = out.clone();",
        "    }",
        "    Ok(out)",
        "}",
        "",
    ]
    lines.extend(block)
    size += sum(len(x) + 1 for x in block)
    i += 1
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("\n".join(lines))
PY
}

seed_repo() {
  local repo="$1"
  rm -rf "$WORK/$repo" "$WORK/$repo-git" "$GIT_BASE/$repo.git"
  (cd "$WORK" && "$SH" repo create "$repo" --clone >/dev/null)
  eval_git_identity "$WORK/$repo"
  local i n
  n=$((BASE_MIB * 8))
  for ((i = 0; i < n; i++)); do
    write_delta "$WORK/$repo/src/base/base_$i.rs" 128 "$((1000 + i))"
  done
  (cd "$WORK/$repo" && git add -A && git commit -qm "seed base tree")
  (cd "$WORK/$repo" && "$SIT" push >/dev/null 2>&1)

  # Matched plain-Git writer and remote. Copy the generated source tree rather
  # than regenerating it so both arms contain byte-identical payloads.
  git init --bare -q --template= --initial-branch=main "$GIT_BASE/$repo.git"
  mkdir -p "$WORK/$repo-git"
  git -C "$WORK/$repo-git" init -q --template= --initial-branch=main
  eval_git_identity "$WORK/$repo-git"
  cp -R "$WORK/$repo/src" "$WORK/$repo-git/"
  git -C "$WORK/$repo-git" add -A
  git -C "$WORK/$repo-git" commit -qm "seed base tree"
  git -C "$WORK/$repo-git" remote add origin \
    "git://$GIT_LISTEN:$GIT_PORT/$repo.git"
  git -C "$WORK/$repo-git" push -q origin HEAD
}

# Run one cell: `depth` commit+push cycles of `delta_kib` each over a seeded base.
run_cell() {
  local arm="$1" repo="$2" depth="$3" delta_kib="$4"
  echo "==> [$arm] depth=$depth delta=${delta_kib}KiB"
  seed_repo "$repo"
  local base_bytes
  base_bytes=$(dir_bytes "$DATA")

  local push_samples=() git_push_samples=()
  local i
  for ((i = 0; i < depth; i++)); do
    write_delta "$WORK/rev_$i.rs" "$delta_kib" "$((i + 7))"
    mkdir -p "$WORK/$repo/src/rev" "$WORK/$repo-git/src/rev"
    cp "$WORK/rev_$i.rs" "$WORK/$repo/src/rev/rev_$i.rs"
    cp "$WORK/rev_$i.rs" "$WORK/$repo-git/src/rev/rev_$i.rs"
    rm -f "$WORK/rev_$i.rs"
    (cd "$WORK/$repo" && git add -A && git commit -qm "rev $i" >/dev/null)
    git -C "$WORK/$repo-git" add -A
    git -C "$WORK/$repo-git" commit -qm "rev $i"
    # Alternate first mover so writeback and cache effects do not always land
    # on the same system.
    if ((i % 2 == 0)); then
      push_samples+=("$(time_cmd_ms bash -c "cd '$WORK/$repo' && '$SIT' push")")
      git_push_samples+=("$(time_cmd_ms git -C "$WORK/$repo-git" push -q origin HEAD)")
    else
      git_push_samples+=("$(time_cmd_ms git -C "$WORK/$repo-git" push -q origin HEAD)")
      push_samples+=("$(time_cmd_ms bash -c "cd '$WORK/$repo' && '$SIT' push")")
    fi
  done
  local after_bytes
  after_bytes=$(dir_bytes "$DATA")

  # Pack the git arm before the clone reps. Cloning from the post-push,
  # un-gc'd bare repo makes git resolve deltas across one packfile per push,
  # which is git's worst case and not the state a real host serves; the size
  # sweep already reports git gc-packed, so measuring it unpacked here held the
  # two arms to different standards within one paper.
  local gc_ms
  gc_ms=$(time_cmd_ms git -C "$GIT_BASE/$repo.git" gc --quiet)
  if [[ "$gc_ms" -lt 20 ]]; then
    echo "  !! git gc did not run for $repo (${gc_ms}ms)" >&2
  fi

  local clone_samples=() git_clone_samples=() fetch_samples=()
  local rep
  for ((rep = 0; rep < EVAL_REPS; rep++)); do
    rm -rf "$WORK/$repo-clone" "$WORK/$repo-git-clone"
    if ((rep % 2 == 0)); then
      clone_samples+=("$(time_cmd_ms bash -c "cd '$WORK' && '$SIT' clone alice/$repo '$repo-clone'")")
      git_clone_samples+=("$(time_cmd_ms git clone -q \
        "git://$GIT_LISTEN:$GIT_PORT/$repo.git" "$WORK/$repo-git-clone")")
    else
      git_clone_samples+=("$(time_cmd_ms git clone -q \
        "git://$GIT_LISTEN:$GIT_PORT/$repo.git" "$WORK/$repo-git-clone")")
      clone_samples+=("$(time_cmd_ms bash -c "cd '$WORK' && '$SIT' clone alice/$repo '$repo-clone'")")
    fi
    fetch_samples+=("$(time_cmd_ms bash -c "cd '$WORK/$repo' && '$SIT' fetch")")
  done
  rm -rf "$WORK/$repo-clone" "$WORK/$repo-git-clone"

  local tree_bytes
  tree_bytes=$(dir_bytes "$WORK/$repo")

  ARM="$arm" DEPTH="$depth" DELTA="$delta_kib" BASE_MIB="$BASE_MIB" \
  PUSH="$(stats_json "${push_samples[@]}")" \
  GIT_PUSH="$(stats_json "${git_push_samples[@]}")" \
  CLONE="$(stats_json "${clone_samples[@]}")" \
  GIT_CLONE="$(stats_json "${git_clone_samples[@]}")" \
  FETCH="$(stats_json "${fetch_samples[@]}")" \
  CT="$((after_bytes - base_bytes))" TREE="$tree_bytes" ROWS="$ROWS" \
  python3 - <<'PY'
import json, os
push = json.loads(os.environ["PUSH"])
git_push = json.loads(os.environ["GIT_PUSH"])
clone = json.loads(os.environ["CLONE"])
git_clone = json.loads(os.environ["GIT_CLONE"])
fetch = json.loads(os.environ["FETCH"])
depth = int(os.environ["DEPTH"])
delta_kib = int(os.environ["DELTA"])
ct = int(os.environ["CT"])
row = {
    "arm": os.environ["ARM"],
    "history_depth": depth,
    "per_push_delta_kib": delta_kib,
    "base_tree_mib": int(os.environ["BASE_MIB"]),
    "total_delta_bytes": depth * delta_kib * 1024,
    "working_tree_bytes": int(os.environ["TREE"]),
    "server_ciphertext_delta_bytes": ct,
    "ciphertext_bytes_per_push": round(ct / depth, 1) if depth else None,
    "ciphertext_over_delta": round(ct / (depth * delta_kib * 1024), 4) if depth and delta_kib else None,
    "push_ms": push,
    "git_push_ms": git_push,
    "clone_ms": clone,
    "git_clone_ms": git_clone,
    "fetch_ms": fetch,
    "clone_ms_per_head": round(clone["median"] / depth, 4) if depth else None,
    "measured": True,
    "status": "measured",
}
with open(os.environ["ROWS"], "a") as f:
    f.write(json.dumps(row) + "\n")
print("    SafeHub push/clone={}/{}ms; Git push/clone={}/{}ms; ct={}B".format(
    push["median"], clone["median"], git_push["median"], git_clone["median"], ct))
PY
  rm -rf "$WORK/$repo" "$WORK/$repo-git" "$GIT_BASE/$repo.git"
}

n=0
for d in $DEPTHS; do
  run_cell "fixed-delta-varying-depth" "ddA$n" "$d" "$FIXED_DELTA_KIB"
  n=$((n + 1))
done

n=0
for k in $DELTAS_KIB; do
  run_cell "fixed-depth-varying-delta" "ddB$n" "$FIXED_DEPTH" "$k"
  n=$((n + 1))
done

MACHINE="$(eval_machine_json)" OUT="$OUT" ROWS="$ROWS" REPS="$EVAL_REPS" \
FIXED_DELTA="$FIXED_DELTA_KIB" FIXED_DEPTH="$FIXED_DEPTH" BASE_MIB="$BASE_MIB" \
python3 - <<'PY'
import json, os
from pathlib import Path

rows = []
with open(os.environ["ROWS"]) as f:
    for line in f:
        line = line.strip()
        if line:
            rows.append(json.loads(line))

arm_a = [r for r in rows if r["arm"] == "fixed-delta-varying-depth"]
arm_b = [r for r in rows if r["arm"] == "fixed-depth-varying-delta"]


def slope(xs, ys):
    """Least-squares slope, so each axis carries its own attribution."""
    n = len(xs)
    if n < 2:
        return None
    mx = sum(xs) / n
    my = sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den


attribution = {
    "clone_ms_per_extra_head": (
        round(slope([r["history_depth"] for r in arm_a],
                    [r["clone_ms"]["median"] for r in arm_a]), 4)
        if len(arm_a) >= 2 else None
    ),
    "push_ms_per_extra_kib_of_delta": (
        round(slope([r["per_push_delta_kib"] for r in arm_b],
                    [r["push_ms"]["median"] for r in arm_b]), 4)
        if len(arm_b) >= 2 else None
    ),
    "git_clone_ms_per_extra_head": (
        round(slope([r["history_depth"] for r in arm_a],
                    [r["git_clone_ms"]["median"] for r in arm_a]), 4)
        if len(arm_a) >= 2 else None
    ),
    "git_push_ms_per_extra_kib_of_delta": (
        round(slope([r["per_push_delta_kib"] for r in arm_b],
                    [r["git_push_ms"]["median"] for r in arm_b]), 4)
        if len(arm_b) >= 2 else None
    ),
    "ciphertext_bytes_per_extra_kib_of_delta": (
        round(slope([r["per_push_delta_kib"] for r in arm_b],
                    [r["ciphertext_bytes_per_push"] for r in arm_b]), 3)
        if len(arm_b) >= 2 else None
    ),
    "note": (
        "Arm A holds the delta constant so any trend is depth; arm B holds the "
        "depth constant so any trend is delta. Slopes are least-squares fits "
        "over the medians of the cells in each arm."
    ),
}

doc = {
    "id": "E02",
    "title": "Size vs per-push delta, decoupled",
    "machine": json.loads(os.environ["MACHINE"]),
    "methodology": {
        "base_tree_mib": int(os.environ["BASE_MIB"]),
        "arm_a": {
            "name": "fixed-delta-varying-depth",
            "fixed_delta_kib": int(os.environ["FIXED_DELTA"]),
            "depths": [r["history_depth"] for r in arm_a],
        },
        "arm_b": {
            "name": "fixed-depth-varying-delta",
            "fixed_depth": int(os.environ["FIXED_DEPTH"]),
            "deltas_kib": [r["per_push_delta_kib"] for r in arm_b],
        },
        "reps_per_clone_fetch_cell": int(os.environ["REPS"]),
        "push_dispersion": (
            "every push in a cell is a sample, so push_ms carries n = depth"
        ),
        "payload": "source-shaped compressible text, not random bytes",
        "plain_git_arm": (
            "matched byte-identical commits pushed to a local git daemon over "
            "git://; clone from the receive-pack state, without pre-clone gc"
        ),
        "arm_order": "alternated per push and clone repetition",
    },
    "cells": rows,
    "attribution": attribution,
    "notes": [
        "The existing size sweep is unchanged and remains published in "
        "additive-scale-latest.json; this artifact is additive.",
        "clone_ms_per_head is reported per cell so the depth term is visible "
        "without reading the fit.",
    ],
}
out = Path(os.environ["OUT"])
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(doc, indent=2) + "\n")
print("wrote", out)
PY

echo "==> E02 depth/delta sweep OK"
