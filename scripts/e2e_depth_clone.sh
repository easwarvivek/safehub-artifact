#!/usr/bin/env bash
# Eval E03 — measured clone vs history depth, to depth 10^4.
#
# The published depth-clone cells were analytical: an AEAD-rate model with
# synthesized dispersion, labelled model/extrapolated beyond depth 10^2. This
# harness replaces them with wall-clock measurements and publishes nothing that
# was not timed on this machine.
#
# One repository lineage grows monotonically to the deepest checkpoint. At every
# checkpoint both arms are cloned EVAL_REPS times, so every depth compares the
# same history rather than a freshly generated one. Push samples accumulate
# across the whole build, so per-depth push cells carry the pushes that landed
# inside that interval.
#
# Env:
#   SAFEHUB_DC_CHECKPOINTS="10 32 100 316 1000 3162 10000"
#   SAFEHUB_DC_DELTA_KIB=64      per-push delta, held fixed so depth is the axis
#   SAFEHUB_DC_BASE_MIB=4        seeded tree present before the first push
#   SAFEHUB_DC_CONSOLIDATE=1     time an admin consolidation at the last cell
#
# Publishes: code/eval/published/depth-clone-latest.json
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/eval_common.sh"

OUT="${SAFEHUB_DC_OUT:-$EVAL_PUB/depth-clone-latest.json}"
CHECKPOINTS="${SAFEHUB_DC_CHECKPOINTS:-10 32 100 316 1000 3162 10000}"
DELTA_KIB="${SAFEHUB_DC_DELTA_KIB:-64}"
BASE_MIB="${SAFEHUB_DC_BASE_MIB:-4}"
DO_CONSOLIDATE="${SAFEHUB_DC_CONSOLIDATE:-1}"
LISTEN="127.0.0.1:18121"
GIT_LISTEN="127.0.0.1"
GIT_PORT="18122"
export SAFEHUB_HOST="http://$LISTEN"

DATA="$(mktemp -d /tmp/safehub-dc-data.XXXXXX)"
CFG="$(mktemp -d /tmp/safehub-dc-cfg.XXXXXX)"
WORK="$(mktemp -d /tmp/safehub-dc-work.XXXXXX)"
GIT_BASE="$WORK/git-base"
# Results live outside $WORK: the cleanup trap wipes $WORK, and a trailing
# optional step must not be able to destroy a multi-hour measurement.
ROWS="${SAFEHUB_DC_ROWS:-$(mktemp /tmp/safehub-dc-rows.XXXXXX).jsonl}"
: >"$ROWS"
echo "==> rows: $ROWS (kept outside the work dir)"
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

"$SH" auth register --user alice --password alice-dc-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default || true

REPO="dc"
MAXDEPTH=0
for d in $CHECKPOINTS; do ((d > MAXDEPTH)) && MAXDEPTH=$d; done

# Source-shaped compressible revisions. Random bytes would make every packfile
# incompressible and turn a depth measurement into a pure I/O measurement.
# One long-lived generator process instead of one python spawn per revision:
# at depth 10^4 the spawn cost would dominate the build.
GEN_FIFO="$WORK/gen.fifo"
mkfifo "$GEN_FIFO"
python3 - "$GEN_FIFO" "$DELTA_KIB" <<'PY' &
import random, sys
from pathlib import Path

fifo, kib = sys.argv[1], int(sys.argv[2])
idents = ["resolve", "encode", "verify", "merge", "index", "flush", "render"]
types = ["u64", "usize", "String", "Vec<u8>"]


def revision(seed: int) -> str:
    rng = random.Random(seed)
    lines = [
        "// Copyright (c) 2026 The SafeHub Evaluation Authors.",
        "use std::collections::BTreeMap;",
        "use anyhow::Result;",
        "",
    ]
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
    return "\n".join(lines)


# Protocol: read "<seed> <path-a> <path-b>" per line, write both, reply "ok".
with open(fifo, "r") as req:
    for line in req:
        line = line.strip()
        if not line or line == "quit":
            break
        seed_s, pa, pb = line.split("\t")
        body = revision(int(seed_s))
        for p in (pa, pb):
            path = Path(p)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        Path(pa + ".done").write_text("ok")
PY
GEN_PID=$!
exec 9>"$GEN_FIFO"

write_rev() {
  local seed="$1" pa="$2" pb="$3"
  printf '%s\t%s\t%s\n' "$seed" "$pa" "$pb" >&9
  local waited=0
  while [[ ! -f "$pa.done" ]]; do
    sleep 0.002
    waited=$((waited + 1))
    ((waited > 5000)) && {
      echo "revision generator stalled" >&2
      exit 1
    }
  done
  rm -f "$pa.done"
}

echo "==> seeding base tree (${BASE_MIB} MiB) and matched plain-git remote"
rm -rf "$WORK/$REPO" "$WORK/$REPO-git" "$GIT_BASE/$REPO.git"
(cd "$WORK" && "$SH" repo create "$REPO" --clone >/dev/null)
eval_git_identity "$WORK/$REPO"
git init --bare -q --template= --initial-branch=main "$GIT_BASE/$REPO.git"
mkdir -p "$WORK/$REPO-git"
git -C "$WORK/$REPO-git" init -q --template= --initial-branch=main
eval_git_identity "$WORK/$REPO-git"
for ((i = 0; i < BASE_MIB * 8; i++)); do
  write_rev "$((1000 + i))" \
    "$WORK/$REPO/src/base/base_$i.rs" "$WORK/$REPO-git/src/base/base_$i.rs"
done
(cd "$WORK/$REPO" && git add -A && git commit -qm "seed base tree")
(cd "$WORK/$REPO" && "$SIT" push >/dev/null 2>&1)
git -C "$WORK/$REPO-git" add -A
git -C "$WORK/$REPO-git" commit -qm "seed base tree"
git -C "$WORK/$REPO-git" remote add origin "git://$GIT_LISTEN:$GIT_PORT/$REPO.git"
git -C "$WORK/$REPO-git" push -q origin HEAD

BASE_CT=$(dir_bytes "$DATA")

measure_checkpoint() {
  local depth="$1" push_stats="$2" git_push_stats="$3" interval_from="$4"
  echo "==> checkpoint depth=$depth: cloning both arms x$EVAL_REPS"
  # With receive.autogc left at its default, git repacks the bare repository at
  # points of its own choosing during the replay, so a checkpoint's git clone
  # depends on whether a gc happened to fire before it. That is git's ordinary
  # maintenance and the conservative default, but it is not reproducible across
  # runs. SAFEHUB_DC_PIN_GC=1 packs the bare repository immediately before each
  # checkpoint instead, so every git clone is timed against a freshly packed
  # remote -- the same defined state the size sweep's clone_packed_ms uses.
  local gc_ms=null
  if [[ "${SAFEHUB_DC_PIN_GC:-0}" == "1" ]]; then
    gc_ms="$(time_cmd_ms git -C "$GIT_BASE/$REPO.git" gc --quiet)" || {
      echo "git gc failed at depth=$depth" >&2; return 1; }
    echo "    pinned gc: ${gc_ms}ms"
  fi
  local clone_samples=() git_clone_samples=() fetch_samples=()
  local rep
  for ((rep = 0; rep < EVAL_REPS; rep++)); do
    rm -rf "$WORK/$REPO-clone" "$WORK/$REPO-git-clone"
    if ((rep % 2 == 0)); then
      clone_samples+=("$(time_cmd_ms bash -c "cd '$WORK' && '$SIT' clone alice/$REPO '$REPO-clone'")")
      git_clone_samples+=("$(time_cmd_ms git clone -q \
        "git://$GIT_LISTEN:$GIT_PORT/$REPO.git" "$WORK/$REPO-git-clone")")
    else
      git_clone_samples+=("$(time_cmd_ms git clone -q \
        "git://$GIT_LISTEN:$GIT_PORT/$REPO.git" "$WORK/$REPO-git-clone")")
      clone_samples+=("$(time_cmd_ms bash -c "cd '$WORK' && '$SIT' clone alice/$REPO '$REPO-clone'")")
    fi
    fetch_samples+=("$(time_cmd_ms bash -c "cd '$WORK/$REPO' && '$SIT' fetch")")
  done
  # Equal-content assertion: an exit status of zero is not evidence of work.
  local sh_tree git_tree
  sh_tree="$(git -C "$WORK/$REPO-clone" rev-parse HEAD^{tree} 2>/dev/null || echo none)"
  git_tree="$(git -C "$WORK/$REPO-git-clone" rev-parse HEAD^{tree} 2>/dev/null || echo none)"
  rm -rf "$WORK/$REPO-clone" "$WORK/$REPO-git-clone"

  local ct_now
  ct_now=$(dir_bytes "$DATA")

  DEPTH="$depth" FROM="$interval_from" DELTA="$DELTA_KIB" BASE_MIB="$BASE_MIB" \
  PUSH="$push_stats" GIT_PUSH="$git_push_stats" \
  CLONE="$(stats_json "${clone_samples[@]}")" \
  GIT_CLONE="$(stats_json "${git_clone_samples[@]}")" \
  FETCH="$(stats_json "${fetch_samples[@]}")" \
  CT="$((ct_now - BASE_CT))" SH_TREE="$sh_tree" GIT_TREE="$git_tree" \
  GC_MS="$gc_ms" PIN_GC="${SAFEHUB_DC_PIN_GC:-0}" \
  ROWS="$ROWS" python3 - <<'PY'
import json, os
depth = int(os.environ["DEPTH"])
clone = json.loads(os.environ["CLONE"])
git_clone = json.loads(os.environ["GIT_CLONE"])
row = {
    "history_depth": depth,
    "push_interval_from": int(os.environ["FROM"]),
    "per_push_delta_kib": int(os.environ["DELTA"]),
    "base_tree_mib": int(os.environ["BASE_MIB"]),
    "push_ms": json.loads(os.environ["PUSH"]),
    "git_push_ms": json.loads(os.environ["GIT_PUSH"]),
    "clone_ms": clone,
    "git_clone_ms": git_clone,
    "fetch_ms": json.loads(os.environ["FETCH"]),
    "clone_ratio_over_git": (
        round(clone["median"] / git_clone["median"], 3)
        if git_clone.get("median") else None
    ),
    "git_pinned_gc": os.environ.get("PIN_GC") == "1",
    "git_gc_ms": (
        int(os.environ["GC_MS"]) if os.environ.get("GC_MS", "null") != "null" else None
    ),
    "clone_ms_per_head": round(clone["median"] / depth, 4) if depth else None,
    "git_clone_ms_per_head": (
        round(git_clone["median"] / depth, 4) if depth else None
    ),
    "server_ciphertext_bytes": int(os.environ["CT"]),
    "clone_tree_matches": os.environ["SH_TREE"] == os.environ["GIT_TREE"]
    and os.environ["SH_TREE"] != "none",
    "measured": True,
    "status": "measured",
}
with open(os.environ["ROWS"], "a") as f:
    f.write(json.dumps(row) + "\n")
print("    depth={} sit clone={}ms git clone={}ms ratio={} ms/head={}".format(
    depth, clone["median"], git_clone["median"],
    row["clone_ratio_over_git"], row["clone_ms_per_head"]))
PY
}

echo "==> building one lineage to depth $MAXDEPTH (delta=${DELTA_KIB}KiB fixed)"
declare -a PUSH_ACC=() GIT_PUSH_ACC=()
interval_from=1
i=0
for ((rev = 1; rev <= MAXDEPTH; rev++)); do
  write_rev "$((rev + 7))" \
    "$WORK/$REPO/src/rev/rev_$rev.rs" "$WORK/$REPO-git/src/rev/rev_$rev.rs"
  (cd "$WORK/$REPO" && git add -A && git commit -qm "rev $rev" >/dev/null)
  git -C "$WORK/$REPO-git" add -A
  git -C "$WORK/$REPO-git" commit -qm "rev $rev"
  if ((rev % 2 == 0)); then
    PUSH_ACC+=("$(time_cmd_ms bash -c "cd '$WORK/$REPO' && '$SIT' push")")
    GIT_PUSH_ACC+=("$(time_cmd_ms git -C "$WORK/$REPO-git" push -q origin HEAD)")
  else
    GIT_PUSH_ACC+=("$(time_cmd_ms git -C "$WORK/$REPO-git" push -q origin HEAD)")
    PUSH_ACC+=("$(time_cmd_ms bash -c "cd '$WORK/$REPO' && '$SIT' push")")
  fi

  for cp in $CHECKPOINTS; do
    if ((rev == cp)); then
      measure_checkpoint "$cp" \
        "$(stats_json "${PUSH_ACC[@]}")" \
        "$(stats_json "${GIT_PUSH_ACC[@]}")" \
        "$interval_from"
      PUSH_ACC=()
      GIT_PUSH_ACC=()
      interval_from=$((rev + 1))
    fi
  done
  if ((rev % 500 == 0)); then
    echo "    ... $rev/$MAXDEPTH revisions"
  fi
done

publish() {
  ROWS="$ROWS" OUT="$OUT" CONSOL="$1" DELTA="$DELTA_KIB" \
  BASE_MIB="$BASE_MIB" REPS="$EVAL_REPS" MAXDEPTH="$MAXDEPTH" \
  python3 "$SCRIPT_DIR/lib/publish_depth_clone.py"
}

# Publish the depth cells now. Consolidation is a separate, optional claim; if
# it fails the depth measurement must still land.
echo "==> publishing depth cells before optional extras"
publish '{"status":"not-run-yet"}'

CONSOL_JSON='{"status":"not-run"}'
if [[ "$DO_CONSOLIDATE" == "1" ]]; then
  # Never fatal: this is an extra claim on top of an already-published result.
  set +e
  echo "==> consolidation at depth $MAXDEPTH, then re-clone"
  # time_cmd_ms prints elapsed ms and returns the command's status. Under
  # set +e an unchecked status turns a failed consolidation into a plausible
  # small number, so each status is captured and a failure is published as a
  # failure rather than as a measurement.
  bytes_before="$(dir_bytes "$DATA")"
  rotate_ms="$(time_cmd_ms "$SH" repo rotate "alice/$REPO")"; rotate_rc=$?
  consol_ms="$(time_cmd_ms "$SH" repo consolidate "alice/$REPO")"; consol_rc=$?
  bytes_after="$(dir_bytes "$DATA")"
  if [[ "$rotate_rc" -ne 0 || "$consol_rc" -ne 0 ]]; then
    echo "==> consolidation FAILED (rotate rc=$rotate_rc, consolidate rc=$consol_rc); \
re-running once with output for the record" >&2
    "$SH" repo rotate "alice/$REPO" 2>&1 | tail -5 >&2
    "$SH" repo consolidate "alice/$REPO" 2>&1 | tail -5 >&2
    CONSOL_JSON="$(ROTATE_RC="$rotate_rc" CONSOL_RC="$consol_rc" DEPTH="$MAXDEPTH" python3 - <<'PY'
import json, os
print(json.dumps({
    "at_history_depth": int(os.environ["DEPTH"]),
    "measured": False,
    "status": "failed",
    "rotate_rc": int(os.environ["ROTATE_RC"]),
    "consolidate_rc": int(os.environ["CONSOL_RC"]),
    "note": (
        "Admin rotate or consolidate exited non-zero; no timing is published "
        "for this cell because the operation did not complete."
    ),
}))
PY
    )"
  else
    post_samples=()
    for ((rep = 0; rep < EVAL_REPS; rep++)); do
      rm -rf "$WORK/$REPO-clone"
      post_samples+=("$(time_cmd_ms bash -c "cd '$WORK' && '$SIT' clone alice/$REPO '$REPO-clone'")")
    done
    rm -rf "$WORK/$REPO-clone"
    CONSOL_JSON="$(ROTATE="$rotate_ms" CONSOL="$consol_ms" \
      BEFORE="$bytes_before" AFTER="$bytes_after" \
      POST="$(stats_json "${post_samples[@]}")" DEPTH="$MAXDEPTH" python3 - <<'PY'
import json, os
before, after = int(os.environ["BEFORE"]), int(os.environ["AFTER"])
print(json.dumps({
    "at_history_depth": int(os.environ["DEPTH"]),
    "rotate_ms": int(os.environ["ROTATE"]),
    "consolidate_ms": int(os.environ["CONSOL"]),
    "clone_after_consolidation_ms": json.loads(os.environ["POST"]),
    "server_bytes_before": before,
    "server_bytes_after": after,
    "server_bytes_reclaimed": before - after,
    "compacted": after < before,
    "measured": True,
    "status": "measured",
    "note": (
        "Admin rotate + shub repo consolidate at the deepest checkpoint, then "
        "re-clone. Both commands are checked for a zero exit status and the "
        "server directory is sized before and after, so a silent no-op is "
        "visible as zero reclaimed bytes. Honest-storage compaction only: "
        "ciphertext a malicious host retained is not erased."
    ),
}))
PY
    )"
  fi
  set -e
fi

printf 'quit\n' >&9 || true
exec 9>&-
wait "$GEN_PID" 2>/dev/null || true

echo "==> re-publishing $OUT with consolidation"
publish "$CONSOL_JSON"
echo "==> done; rows retained at $ROWS"
