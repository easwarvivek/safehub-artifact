#!/usr/bin/env bash
# Eval E12 — merge, rebase, and force-push against history depth, to 10^3.
#
# Design and adversarial review: review-notes/e12-history-ops-design.md.
# Guards: scripts/lib/history_ops_lib.sh, tested by scripts/tests/test_history_ops.sh.
#
# Ordinary push moves a delta and costs what the delta costs. These three are
# statements about history: merge joins two lineages, rebase rewrites a range,
# force-push replaces a tip with a non-descendant. The last two are
# non-fast-forward, so on the SafeHub side they hit the §IV-D gate, where the
# verifier recomputes ancestry against its local DAG and an admin ML-DSA-87
# co-signature is required. Recomputing ancestry is the step with a reason to
# scale with depth; that is what this measures.
#
# `main` is grown once, monotonically, and never touched afterwards. Every
# operation runs on a scratch branch created at the checkpoint and deleted
# after, so each checkpoint measures the same linear history it claims to. The
# scratch pushes still lengthen SafeHub's per-repository head log, which is
# append-only; that footprint is reported per row rather than hidden.
#
# Env:
#   SAFEHUB_HO_CHECKPOINTS="10 32 100 316 1000"
#   SAFEHUB_HO_DELTA_KIB=64      per-revision delta, fixed so depth is the axis
#   SAFEHUB_HO_BASE_MIB=4        seeded tree present before the first push
#   SAFEHUB_HO_REBASE_N=3        commits the rebase arm rewrites
#   SAFEHUB_HO_PIN_GC=1          pack the bare git repo before each checkpoint
#
# Publishes: code/eval/published/history-ops-latest.json
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/eval_common.sh"
source "$SCRIPT_DIR/lib/history_ops_lib.sh"

OUT="${SAFEHUB_HO_OUT:-$EVAL_PUB/history-ops-latest.json}"
CHECKPOINTS="${SAFEHUB_HO_CHECKPOINTS:-10 32 100 316 1000}"
DELTA_KIB="${SAFEHUB_HO_DELTA_KIB:-64}"
BASE_MIB="${SAFEHUB_HO_BASE_MIB:-4}"
REBASE_N="${SAFEHUB_HO_REBASE_N:-3}"
PIN_GC="${SAFEHUB_HO_PIN_GC:-1}"
LISTEN="127.0.0.1:18131"
GIT_LISTEN="127.0.0.1"
GIT_PORT="18132"
export SAFEHUB_HOST="http://$LISTEN"

DATA="$(mktemp -d /tmp/safehub-ho-data.XXXXXX)"
CFG="$(mktemp -d /tmp/safehub-ho-cfg.XXXXXX)"
WORK="$(mktemp -d /tmp/safehub-ho-work.XXXXXX)"
GIT_BASE="$WORK/git-base"
# Results live outside $WORK so the cleanup trap cannot destroy the run.
ROWS="${SAFEHUB_HO_ROWS:-$(mktemp /tmp/safehub-ho-rows.XXXXXX).jsonl}"
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
  (exec 3<>"/dev/tcp/$GIT_LISTEN/$GIT_PORT") 2>/dev/null && { exec 3<&- 3>&-; break; }
  sleep 0.1
done
kill -0 "$GIT_PID" 2>/dev/null || { echo "git daemon failed to start" >&2; exit 1; }

"$SH" auth register --user alice --password alice-ho-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default || true

REPO="ho"
MAXDEPTH=0
for d in $CHECKPOINTS; do ((d > MAXDEPTH)) && MAXDEPTH=$d; done

# Source-shaped compressible revisions, same generator contract as E03: random
# bytes would make every packfile incompressible and turn this into an I/O
# measurement. One long-lived process, not one spawn per revision.
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
    lines = ["// Copyright (c) 2026 The SafeHub Evaluation Authors.",
             "use std::collections::BTreeMap;", "use anyhow::Result;", ""]
    target = kib * 1024
    size = sum(len(x) + 1 for x in lines)
    i = 0
    while size < target:
        name = rng.choice(idents); ty = rng.choice(types)
        block = [f"/// Revision {seed} unit {i}.",
                 f"pub fn {name}_{seed}_{i}(input: &{ty}) -> Result<{ty}> {{",
                 "    let mut out = input.clone();",
                 f"    for _ in 0..{rng.randint(1, 9)} {{", "        out = out.clone();",
                 "    }", "    Ok(out)", "}", ""]
        lines.extend(block); size += sum(len(x) + 1 for x in block); i += 1
    return "\n".join(lines)

with open(fifo, "r") as req:
    for line in req:
        line = line.strip()
        if not line or line == "quit":
            break
        seed_s, pa, pb = line.split("\t")
        body = revision(int(seed_s))
        for p in (pa, pb):
            path = Path(p); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        Path(pa + ".done").write_text("ok")
PY
GEN_PID=$!
exec 9>"$GEN_FIFO"

write_rev() {
  local seed="$1" pa="$2" pb="$3" waited=0
  printf '%s\t%s\t%s\n' "$seed" "$pa" "$pb" >&9
  while [[ ! -f "$pa.done" ]]; do
    sleep 0.002
    waited=$((waited + 1))
    ((waited > 5000)) && { echo "revision generator stalled" >&2; exit 1; }
  done
  rm -f "$pa.done"
}

SHREPO="$WORK/$REPO"
GITREPO="$WORK/$REPO-git"
BARE="$GIT_BASE/$REPO.git"

echo "==> seeding base tree (${BASE_MIB} MiB) and matched plain-git remote"
rm -rf "$SHREPO" "$GITREPO" "$BARE"
(cd "$WORK" && "$SH" repo create "$REPO" --clone >/dev/null)
eval_git_identity "$SHREPO"
git init --bare -q --template= --initial-branch=main "$BARE"
mkdir -p "$GITREPO"
git -C "$GITREPO" init -q --template= --initial-branch=main
eval_git_identity "$GITREPO"
for ((i = 0; i < BASE_MIB * 8; i++)); do
  write_rev "$((1000 + i))" "$SHREPO/src/base/base_$i.rs" "$GITREPO/src/base/base_$i.rs"
done
(cd "$SHREPO" && git add -A && git commit -qm "seed base tree")
(cd "$SHREPO" && "$SIT" push >/dev/null 2>&1)
git -C "$GITREPO" add -A
git -C "$GITREPO" commit -qm "seed base tree"
git -C "$GITREPO" remote add origin "git://$GIT_LISTEN:$GIT_PORT/$REPO.git"
git -C "$GITREPO" push -q origin HEAD

# The two arms need not share a default branch name: the SafeHub repo takes
# whatever git's local default is, while the matched remote is created with an
# explicit --initial-branch. Reading one and using it for both silently breaks
# every checkout in the other arm, so each arm carries its own.
SH_MAIN="$(git -C "$SHREPO" symbolic-ref --short HEAD)"
GIT_MAIN="$(git -C "$GITREPO" symbolic-ref --short HEAD)"
echo "==> branches: safehub=$SH_MAIN git=$GIT_MAIN"

# Current SafeHub head-log length, read from the server's own store: heads land
# at $DATA/heads/<repo_id>/log/<seq>.bin, contiguous from 1. There is no CLI
# command for this, and inventing one would put an unmeasured code path in the
# measurement loop. This is the harness's footprint on the depth axis.
head_seq() {
  local rid
  rid="$(ls "$DATA/heads" 2>/dev/null | head -1)" || return 0
  [[ -n "$rid" ]] || { echo 0; return 0; }
  ls "$DATA/heads/$rid/log" 2>/dev/null | grep -c '\.bin$' || echo 0
}

# ---------------------------------------------------------------- operations
#
# Each returns 0 only if the operation was performed AND proved to be the
# operation it is named. HO_MS carries the timing of the push under test; the
# local git work is timed separately into HO_LOCAL_MS so an encrypted-push cost
# is never confused with git's tree work.

# merge: topic off the tip plus one revision, merged --no-ff into a scratch
# integration branch, then pushed. Clean merge, no conflicts (see design §4 A10).
op_merge_sh() {
  local tag="$1" rc
  git -C "$SHREPO" checkout -q -b "topic-$tag" "$SH_MAIN"
  write_rev "$((900000 + RANDOM))" "$SHREPO/src/op/t_$tag.rs" "$WORK/.sink_$tag"
  git -C "$SHREPO" add -A && git -C "$SHREPO" commit -qm "topic $tag" >/dev/null
  git -C "$SHREPO" checkout -q -b "integ-$tag" "$SH_MAIN"
  ho_timed git -C "$SHREPO" merge --no-ff -q "topic-$tag" -m "merge $tag"; rc=$?
  HO_LOCAL_MS=$HO_MS
  [[ $rc -eq 0 ]] || return 1
  ho_is_merge_commit "$SHREPO" HEAD || { echo "    merge produced no merge commit" >&2; return 1; }
  ho_timed bash -c "cd '$SHREPO' && '$SIT' push sit integ-$tag"; rc=$?
  git -C "$SHREPO" checkout -q "$SH_MAIN"
  return $rc
}

op_merge_git() {
  local tag="$1" rc
  git -C "$GITREPO" checkout -q -b "topic-$tag" "$GIT_MAIN"
  write_rev "$((900000 + RANDOM))" "$GITREPO/src/op/t_$tag.rs" "$WORK/.sink_g_$tag"
  git -C "$GITREPO" add -A && git -C "$GITREPO" commit -qm "topic $tag" >/dev/null
  git -C "$GITREPO" checkout -q -b "integ-$tag" "$GIT_MAIN"
  ho_timed git -C "$GITREPO" merge --no-ff -q "topic-$tag" -m "merge $tag"; rc=$?
  HO_LOCAL_MS=$HO_MS
  [[ $rc -eq 0 ]] || return 1
  ho_is_merge_commit "$GITREPO" HEAD || { echo "    git merge produced no merge commit" >&2; return 1; }
  ho_timed git -C "$GITREPO" push -q origin "integ-$tag"; rc=$?
  git -C "$GITREPO" checkout -q "$GIT_MAIN"
  return $rc
}

# rebase: a branch of REBASE_N revisions is pushed as-is, then rebased onto the
# tip and pushed again. The second push is the non-fast-forward one.
op_rebase_sh() {
  local tag="$1" rc old new
  git -C "$SHREPO" checkout -q -b "rb-$tag" "$SH_MAIN~1"
  for ((k = 0; k < REBASE_N; k++)); do
    write_rev "$((910000 + RANDOM))" "$SHREPO/src/op/r_${tag}_$k.rs" "$WORK/.sink_r_${tag}_$k"
    git -C "$SHREPO" add -A && git -C "$SHREPO" commit -qm "rb $tag $k" >/dev/null
  done
  (cd "$SHREPO" && "$SIT" push sit "rb-$tag" >/dev/null 2>&1) || return 1
  old="$(git -C "$SHREPO" rev-parse "rb-$tag")"
  ho_timed git -C "$SHREPO" rebase -q "$SH_MAIN"; rc=$?
  HO_LOCAL_MS=$HO_MS
  [[ $rc -eq 0 ]] || { git -C "$SHREPO" rebase --abort 2>/dev/null || true; return 1; }
  new="$(git -C "$SHREPO" rev-parse "rb-$tag")"
  ho_is_rebase "$SHREPO" "$old" "$new" "$(git -C "$SHREPO" rev-parse "$SH_MAIN")" \
    || { echo "    rebase did not rewrite onto the new base" >&2; return 1; }
  ho_timed bash -c "cd '$SHREPO' && '$SIT' push --force sit rb-$tag"; rc=$?
  [[ $rc -eq 0 ]] && { ho_push_was_forced "$SHREPO" \
    || { echo "    rebase push was not recorded as forced" >&2; rc=1; }; }
  git -C "$SHREPO" checkout -q "$SH_MAIN"
  return $rc
}

op_rebase_git() {
  local tag="$1" rc old new
  git -C "$GITREPO" checkout -q -b "rb-$tag" "$GIT_MAIN~1"
  for ((k = 0; k < REBASE_N; k++)); do
    write_rev "$((910000 + RANDOM))" "$GITREPO/src/op/r_${tag}_$k.rs" "$WORK/.sink_rg_${tag}_$k"
    git -C "$GITREPO" add -A && git -C "$GITREPO" commit -qm "rb $tag $k" >/dev/null
  done
  git -C "$GITREPO" push -q origin "rb-$tag" || return 1
  old="$(git -C "$GITREPO" rev-parse "rb-$tag")"
  ho_timed git -C "$GITREPO" rebase -q "$GIT_MAIN"; rc=$?
  HO_LOCAL_MS=$HO_MS
  [[ $rc -eq 0 ]] || { git -C "$GITREPO" rebase --abort 2>/dev/null || true; return 1; }
  new="$(git -C "$GITREPO" rev-parse "rb-$tag")"
  ho_is_rebase "$GITREPO" "$old" "$new" "$(git -C "$GITREPO" rev-parse "$GIT_MAIN")" \
    || { echo "    git rebase did not rewrite onto the new base" >&2; return 1; }
  ho_timed git -C "$GITREPO" push -q --force origin "rb-$tag"; rc=$?
  git -C "$GITREPO" checkout -q "$GIT_MAIN"
  return $rc
}

# force-push: scratch branch pushed, tip amended, pushed again. Minimal object
# change so the timing is the gate and the ref update, not the payload.
op_force_sh() {
  local tag="$1" rc old new
  git -C "$SHREPO" checkout -q -b "fp-$tag" "$SH_MAIN"
  write_rev "$((920000 + RANDOM))" "$SHREPO/src/op/f_$tag.rs" "$WORK/.sink_f_$tag"
  git -C "$SHREPO" add -A && git -C "$SHREPO" commit -qm "fp $tag" >/dev/null
  (cd "$SHREPO" && "$SIT" push sit "fp-$tag" >/dev/null 2>&1) || return 1
  old="$(git -C "$SHREPO" rev-parse "fp-$tag")"
  git -C "$SHREPO" commit -q --amend -m "fp $tag rewritten" >/dev/null
  new="$(git -C "$SHREPO" rev-parse "fp-$tag")"
  ho_is_non_ff "$SHREPO" "$old" "$new" \
    || { echo "    amend produced a descendant, not a rewrite" >&2; return 1; }
  HO_LOCAL_MS=0
  ho_timed bash -c "cd '$SHREPO' && '$SIT' push --force sit fp-$tag"; rc=$?
  [[ $rc -eq 0 ]] && { ho_push_was_forced "$SHREPO" \
    || { echo "    force push was not recorded as forced" >&2; rc=1; }; }
  git -C "$SHREPO" checkout -q "$SH_MAIN"
  return $rc
}

op_force_git() {
  local tag="$1" rc old new
  git -C "$GITREPO" checkout -q -b "fp-$tag" "$GIT_MAIN"
  write_rev "$((920000 + RANDOM))" "$GITREPO/src/op/f_$tag.rs" "$WORK/.sink_fg_$tag"
  git -C "$GITREPO" add -A && git -C "$GITREPO" commit -qm "fp $tag" >/dev/null
  git -C "$GITREPO" push -q origin "fp-$tag" || return 1
  old="$(git -C "$GITREPO" rev-parse "fp-$tag")"
  git -C "$GITREPO" commit -q --amend -m "fp $tag rewritten" >/dev/null
  new="$(git -C "$GITREPO" rev-parse "fp-$tag")"
  ho_is_non_ff "$GITREPO" "$old" "$new" \
    || { echo "    git amend produced a descendant, not a rewrite" >&2; return 1; }
  HO_LOCAL_MS=0
  ho_timed git -C "$GITREPO" push -q --force origin "fp-$tag"; rc=$?
  git -C "$GITREPO" checkout -q "$GIT_MAIN"
  return $rc
}

# Scratch refs are dropped from both remotes and both work trees. A leaked
# branch would make later checkpoints measure a different repository (design A8).
drop_scratch() {
  local tag="$1" b
  for b in "topic-$tag" "integ-$tag" "rb-$tag" "fp-$tag"; do
    git -C "$SHREPO" branch -q -D "$b" 2>/dev/null || true
    git -C "$GITREPO" branch -q -D "$b" 2>/dev/null || true
    git -C "$GITREPO" push -q origin --delete "$b" 2>/dev/null || true
    git -C "$BARE" update-ref -d "refs/heads/$b" 2>/dev/null || true
    ho_ref_absent_git "$BARE" "$b" || {
      echo "scratch ref $b survived cleanup in the bare repo" >&2
      return 1
    }
  done
  git -C "$SHREPO" checkout -q "$SH_MAIN" || {
    echo "safehub arm could not return to $SH_MAIN" >&2; return 1; }
  git -C "$GITREPO" checkout -q "$GIT_MAIN" || {
    echo "git arm could not return to $GIT_MAIN" >&2; return 1; }
  rm -rf "$SHREPO/src/op" "$GITREPO/src/op"
  git -C "$SHREPO" checkout -q -- . 2>/dev/null || true
  git -C "$GITREPO" checkout -q -- . 2>/dev/null || true
}

# Control: an ordinary fast-forward push of one revision, on both arms, taken
# in the same environment and at the same moment as the operations under test.
# Without it a ratio has nothing to be read against -- if the history-op numbers
# and the control disagree with a standalone measurement of the same push, the
# harness environment is doing something and the ratio is not about the
# operation at all.
op_ff_ref_sh() {
  local tag="$1" rc
  write_rev "$((930000 + RANDOM))" "$SHREPO/src/ref/x_$tag.rs" "$WORK/.sink_x_$tag"
  git -C "$SHREPO" add -A && git -C "$SHREPO" commit -qm "ref $tag" >/dev/null
  ho_timed bash -c "cd '$SHREPO' && '$SIT' push"; rc=$?
  return $rc
}

op_ff_ref_git() {
  local tag="$1" rc
  write_rev "$((930000 + RANDOM))" "$GITREPO/src/ref/x_$tag.rs" "$WORK/.sink_xg_$tag"
  git -C "$GITREPO" add -A && git -C "$GITREPO" commit -qm "ref $tag" >/dev/null
  ho_timed git -C "$GITREPO" push -q origin HEAD; rc=$?
  return $rc
}

measure_checkpoint() {
  local depth="$1"
  echo "==> checkpoint depth=$depth: merge / rebase / force-push x$EVAL_REPS"
  local gc_ms=null
  if [[ "$PIN_GC" == "1" ]]; then
    gc_ms="$(time_cmd_ms git -C "$BARE" gc --quiet)" || {
      echo "git gc failed at depth=$depth" >&2; return 1; }
  fi
  local seq_before seq_after
  seq_before="$(head_seq)"

  local -a M_SH=() M_GIT=() M_LOC=() R_SH=() R_GIT=() R_LOC=() F_SH=() F_GIT=()
  local -a X_SH=() X_GIT=()
  local failed="" rep rc tag
  for ((rep = 0; rep < EVAL_REPS; rep++)); do
    tag="d${depth}r${rep}"
    # Alternate arm order so neither side always pays the cold-cache cost.
    if ((rep % 2 == 0)); then
      op_merge_sh  "m$tag"; rc=$?; ho_sample M_SH  "$rc" || failed="merge/sit"
      [[ $rc -eq 0 ]] && M_LOC+=("$HO_LOCAL_MS")
      op_merge_git "m$tag"; rc=$?; ho_sample M_GIT "$rc" || failed="merge/git"
    else
      op_merge_git "m$tag"; rc=$?; ho_sample M_GIT "$rc" || failed="merge/git"
      op_merge_sh  "m$tag"; rc=$?; ho_sample M_SH  "$rc" || failed="merge/sit"
      [[ $rc -eq 0 ]] && M_LOC+=("$HO_LOCAL_MS")
    fi
    drop_scratch "m$tag" || return 1

    if ((rep % 2 == 0)); then
      op_rebase_sh  "b$tag"; rc=$?; ho_sample R_SH  "$rc" || failed="rebase/sit"
      [[ $rc -eq 0 ]] && R_LOC+=("$HO_LOCAL_MS")
      op_rebase_git "b$tag"; rc=$?; ho_sample R_GIT "$rc" || failed="rebase/git"
    else
      op_rebase_git "b$tag"; rc=$?; ho_sample R_GIT "$rc" || failed="rebase/git"
      op_rebase_sh  "b$tag"; rc=$?; ho_sample R_SH  "$rc" || failed="rebase/sit"
      [[ $rc -eq 0 ]] && R_LOC+=("$HO_LOCAL_MS")
    fi
    drop_scratch "b$tag" || return 1

    if ((rep % 2 == 0)); then
      op_force_sh  "f$tag"; rc=$?; ho_sample F_SH  "$rc" || failed="force/sit"
      op_force_git "f$tag"; rc=$?; ho_sample F_GIT "$rc" || failed="force/git"
    else
      op_force_git "f$tag"; rc=$?; ho_sample F_GIT "$rc" || failed="force/git"
      op_force_sh  "f$tag"; rc=$?; ho_sample F_SH  "$rc" || failed="force/sit"
    fi
    drop_scratch "f$tag" || return 1

    if ((rep % 2 == 0)); then
      op_ff_ref_sh  "$tag"; rc=$?; ho_sample X_SH  "$rc" || failed="ffref/sit"
      op_ff_ref_git "$tag"; rc=$?; ho_sample X_GIT "$rc" || failed="ffref/git"
    else
      op_ff_ref_git "$tag"; rc=$?; ho_sample X_GIT "$rc" || failed="ffref/git"
      op_ff_ref_sh  "$tag"; rc=$?; ho_sample X_SH  "$rc" || failed="ffref/sit"
    fi
  done
  seq_after="$(head_seq)"

  DEPTH="$depth" DELTA="$DELTA_KIB" BASE_MIB="$BASE_MIB" REBASE_N="$REBASE_N" \
  MERGE_SH="$(stats_json "${M_SH[@]:-}")" MERGE_GIT="$(stats_json "${M_GIT[@]:-}")" \
  MERGE_LOCAL="$(stats_json "${M_LOC[@]:-}")" \
  REBASE_SH="$(stats_json "${R_SH[@]:-}")" REBASE_GIT="$(stats_json "${R_GIT[@]:-}")" \
  REBASE_LOCAL="$(stats_json "${R_LOC[@]:-}")" \
  FORCE_SH="$(stats_json "${F_SH[@]:-}")" FORCE_GIT="$(stats_json "${F_GIT[@]:-}")" \
  FFREF_SH="$(stats_json "${X_SH[@]:-}")" FFREF_GIT="$(stats_json "${X_GIT[@]:-}")" \
  GC_MS="$gc_ms" PIN="$PIN_GC" FAILED="$failed" \
  SEQ_BEFORE="${seq_before:-0}" SEQ_AFTER="${seq_after:-0}" \
  ROWS="$ROWS" python3 - <<'PY'
import json, os

def st(name):
    return json.loads(os.environ[name])

def ratio(a, b):
    am, bm = a.get("median"), b.get("median")
    return round(am / bm, 3) if am is not None and bm else None

failed = os.environ["FAILED"]
merge_sh, merge_git = st("MERGE_SH"), st("MERGE_GIT")
reb_sh, reb_git = st("REBASE_SH"), st("REBASE_GIT")
frc_sh, frc_git = st("FORCE_SH"), st("FORCE_GIT")
sb, sa = int(os.environ["SEQ_BEFORE"] or 0), int(os.environ["SEQ_AFTER"] or 0)
row = {
    "history_depth": int(os.environ["DEPTH"]),
    "per_push_delta_kib": int(os.environ["DELTA"]),
    "base_tree_mib": int(os.environ["BASE_MIB"]),
    "rebase_commits": int(os.environ["REBASE_N"]),
    # merge: push of a two-parent commit; local is the git merge itself.
    "merge_push_ms": merge_sh,
    "git_merge_push_ms": merge_git,
    "merge_local_ms": st("MERGE_LOCAL"),
    "merge_ratio_over_git": ratio(merge_sh, merge_git),
    # rebase: the SECOND push, which is non-fast-forward and co-signed.
    "rebase_push_ms": reb_sh,
    "git_rebase_push_ms": reb_git,
    "rebase_local_ms": st("REBASE_LOCAL"),
    "rebase_ratio_over_git": ratio(reb_sh, reb_git),
    # force-push: tip replacement, minimal object change.
    "force_push_ms": frc_sh,
    "git_force_push_ms": frc_git,
    "force_ratio_over_git": ratio(frc_sh, frc_git),
    # Control: an ordinary fast-forward push of one revision, same environment,
    # same moment. The history-op cells are only interpretable against it.
    "ff_ref_push_ms": st("FFREF_SH"),
    "git_ff_ref_push_ms": st("FFREF_GIT"),
    "ff_ref_ratio_over_git": ratio(st("FFREF_SH"), st("FFREF_GIT")),
    "git_pinned_gc": os.environ["PIN"] == "1",
    "git_gc_ms": (int(os.environ["GC_MS"])
                  if os.environ.get("GC_MS", "null") != "null" else None),
    # The harness's own footprint on the axis: scratch pushes lengthen the
    # append-only head log even though `main` is untouched.
    "head_log_seq_before": sb,
    "head_log_seq_after": sa,
    "head_log_seq_added_by_ops": (sa - sb) if (sa and sb) else None,
    "non_ff_cosig_on_sit_only": True,
    "measured": not failed,
    "status": "failed" if failed else "measured",
}
if failed:
    row["failed_at"] = failed
    # A failed arm publishes no numbers: a status is not a measurement.
    for k in ("merge_push_ms", "git_merge_push_ms", "rebase_push_ms",
              "git_rebase_push_ms", "force_push_ms", "git_force_push_ms",
              "merge_ratio_over_git", "rebase_ratio_over_git",
              "force_ratio_over_git"):
        row[k] = None
with open(os.environ["ROWS"], "a") as f:
    f.write(json.dumps(row) + "\n")
if failed:
    print("    depth={} FAILED at {}".format(row["history_depth"], failed))
else:
    print("    depth={} merge {}/{} | rebase {}/{} | force {}/{} | "
          "ff-control {}/{}".format(
              row["history_depth"], merge_sh.get("median"), merge_git.get("median"),
              reb_sh.get("median"), reb_git.get("median"),
              frc_sh.get("median"), frc_git.get("median"),
              st("FFREF_SH").get("median"), st("FFREF_GIT").get("median")))
PY
  [[ -z "$failed" ]]
}

echo "==> building one lineage to depth $MAXDEPTH (delta=${DELTA_KIB}KiB fixed)"
for ((rev = 1; rev <= MAXDEPTH; rev++)); do
  write_rev "$((rev + 7))" "$SHREPO/src/rev/rev_$rev.rs" "$GITREPO/src/rev/rev_$rev.rs"
  (cd "$SHREPO" && git add -A && git commit -qm "rev $rev" >/dev/null)
  git -C "$GITREPO" add -A
  git -C "$GITREPO" commit -qm "rev $rev"
  (cd "$SHREPO" && "$SIT" push >/dev/null 2>&1)
  git -C "$GITREPO" push -q origin HEAD
  ((rev % 100 == 0)) && echo "    ... $rev/$MAXDEPTH revisions"
  for cp in $CHECKPOINTS; do
    if ((rev == cp)); then
      measure_checkpoint "$cp" || echo "    (checkpoint $cp recorded as failed)"
    fi
  done
done

printf 'quit\n' >&9 || true
exec 9>&-
wait "$GEN_PID" 2>/dev/null || true

echo "==> publishing $OUT"
ROWS="$ROWS" OUT="$OUT" DELTA="$DELTA_KIB" REBASE_N="$REBASE_N" PIN="$PIN_GC" \
  python3 "$SCRIPT_DIR/publish_history_ops.py"
echo "==> done"
