#!/usr/bin/env bash
# Eval E13-A — every operation but clone, swept against DELTA size.
#
# Design and adversarial review: code/eval/design-e13-full-matrix.md.
# Guards: scripts/lib/e13_lib.sh, tested by scripts/tests/test_e13.sh.
#
# Push, pull, fetch, merge, rebase and force-push all move an edit, and whether
# their cost tracks that edit is what separates the four tools: git and SafeHub
# are delta-proportional, git-crypt costs whole changed files, gcrypt costs the
# whole repository. Sweeping delta at a fixed base repository shows that
# directly -- delta-proportional rises with the axis, file-proportional steps,
# repository-proportional is flat and high. The slopes are the result.
#
# Every timed command's status is checked, every operation asserts a
# postcondition, and each operation's corrected basis is its OWN no-payload
# floor on the SAME tool (see e13_lib.sh).
#
# Env:
#   SAFEHUB_E13_DELTAS="5 10 50 100 500 1024 1536 2048 2560 3072"  KiB (5KB..3MB)
#   SAFEHUB_E13_REPS=5            repetitions per operation
#   SAFEHUB_E13_GCRYPT_REPS=3     gcrypt only; topped up to 5 later
#   SAFEHUB_E13_BASE_MB=16        fixed base repository
#   SAFEHUB_E13_ROOT=$HOME/e13    state root; must NOT be tmpfs
#
# Publishes: code/eval/published/e13-delta-latest.json
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/eval_common.sh"
source "$SCRIPT_DIR/lib/e13_lib.sh"

OUT="${SAFEHUB_E13_OUT:-$EVAL_PUB/e13-delta-latest.json}"
DELTAS="${SAFEHUB_E13_DELTAS:-5 10 50 100 500 1024 1536 2048 2560 3072}"
REPS="${SAFEHUB_E13_REPS:-5}"
GREPS="${SAFEHUB_E13_GCRYPT_REPS:-3}"
BASE_MB="${SAFEHUB_E13_BASE_MB:-16}"
ROOT="${SAFEHUB_E13_ROOT:-$HOME/e13}"
LISTEN="127.0.0.1:18181"
export SAFEHUB_HOST="http://$LISTEN"

rm -rf "$ROOT"; mkdir -p "$ROOT"
DATA="$ROOT/data"; CFG="$ROOT/cfg"; WORK="$ROOT/work"
mkdir -p "$DATA" "$CFG" "$WORK"
ROWS="${SAFEHUB_E13_ROWS:-$ROOT/delta-rows.jsonl}"
: >"$ROWS"
echo "==> rows: $ROWS   state root: $ROOT (root disk, not tmpfs)"
export HOME="$CFG" XDG_CONFIG_HOME="$CFG/.config" SAFEHUB_DATA="$DATA"
export GNUPGHOME="$CFG/gnupg"
mkdir -p "$XDG_CONFIG_HOME" "$GNUPGHOME"; chmod 700 "$GNUPGHOME"

SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

eval_build safehub-server safehub-cli sit-remote-safehub
eval_start_server "$LISTEN" "$DATA"
"$SH" auth register --user alice --password alice-e13-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default || true

ARMS=()
for a in git gitcrypt gcrypt safehub; do
  if e13_arm_available "$a"; then ARMS+=("$a"); else echo "==> arm $a UNAVAILABLE (reported absent, not zero)"; fi
done
GCRYPT_KEY=""
if printf '%s\n' "${ARMS[@]}" | grep -qx gcrypt; then
  GCRYPT_KEY="$(e13_gcrypt_key "$CFG")" || GCRYPT_KEY=""
  if [[ -z "$GCRYPT_KEY" ]]; then
    echo "==> gcrypt key generation failed; arm dropped"
    ARMS=($(printf '%s\n' "${ARMS[@]}" | grep -vx gcrypt))
  fi
fi
echo "==> arms: ${ARMS[*]}"

# Compressible source-shaped content: random bytes make every packfile
# incompressible and turn a delta measurement into an I/O measurement.
gen_blob() {
  python3 - "$1" "$2" "$3" <<'PY'
import random, sys
from pathlib import Path
path, kib, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rng = random.Random(seed)
idents = ["resolve","encode","verify","merge","index","flush","render"]
types = ["u64","usize","String","Vec<u8>"]
out, size, i = [], 0, 0
while size < kib*1024:
    b = (f"/// unit {seed}_{i}\n"
         f"pub fn {rng.choice(idents)}_{seed}_{i}(x: &{rng.choice(types)}) -> u64 {{\n"
         f"    let mut o = 0u64; for _ in 0..{rng.randint(1,9)} {{ o += 1; }} o\n}}\n")
    out.append(b); size += len(b); i += 1
Path(path).parent.mkdir(parents=True, exist_ok=True)
Path(path).write_text("".join(out))
PY
}

reps_for() { [[ "$1" == "gcrypt" ]] && echo "$GREPS" || echo "$REPS"; }

# ------------------------------------------------------------- arm setup ----
arm_setup() {
  local arm="$1" tag="$2" wt bare
  wt="$WORK/${arm}_$tag"; bare="$WORK/${arm}_$tag.bare"
  rm -rf "$wt" "$bare"
  if [[ "$arm" == "safehub" ]]; then
    ( cd "$WORK" && "$SH" repo create "${arm}_$tag" --clone >/dev/null 2>&1 ) || return 1
    eval_git_identity "$wt"
  else
    git init --bare -q --template= --initial-branch=main "$bare"
    mkdir -p "$wt"; git init -q --template= --initial-branch=main "$wt"
    eval_git_identity "$wt"
    case "$arm" in
      gcrypt)
        git -C "$wt" remote add origin "gcrypt::file://$bare"
        git -C "$wt" config gcrypt.participants "$GCRYPT_KEY"
        git -C "$wt" config gcrypt.publish-participants true ;;
      gitcrypt)
        git -C "$wt" remote add origin "file://$bare"
        printf '*.rs filter=git-crypt diff=git-crypt\n' > "$wt/.gitattributes"
        ( cd "$wt" && git-crypt init >/dev/null 2>&1 ) || return 1 ;;
      git)
        git -C "$wt" remote add origin "file://$bare" ;;
    esac
  fi
  E13_WT="$wt"; E13_BARE="$bare"
}

# git-crypt encrypts through clean/smudge filters at staging, so `git push`
# alone would report it as free encryption. The push cell therefore times
# add+commit+push for every arm, so the same work is inside the timer.
arm_stage_push() {
  local arm="$1" wt="$2"
  git -C "$wt" add -A >/dev/null 2>&1 || return 1
  git -C "$wt" commit -qm "op" >/dev/null 2>&1 || return 1
  if [[ "$arm" == "safehub" ]]; then ( cd "$wt" && "$SIT" push >/dev/null 2>&1 )
  else git -C "$wt" push -q origin HEAD >/dev/null 2>&1; fi
}

arm_push_only() {
  local arm="$1" wt="$2"
  if [[ "$arm" == "safehub" ]]; then ( cd "$wt" && "$SIT" push >/dev/null 2>&1 )
  else git -C "$wt" push -q origin HEAD >/dev/null 2>&1; fi
}

arm_fetch() {
  local arm="$1" wt="$2"
  if [[ "$arm" == "safehub" ]]; then ( cd "$wt" && "$SIT" fetch >/dev/null 2>&1 )
  else git -C "$wt" fetch -q origin >/dev/null 2>&1; fi
}

echo "==> deltas: $DELTAS KiB | reps=$REPS (gcrypt=$GREPS) | base=${BASE_MB}MB"
for D in $DELTAS; do
  echo "==> delta ${D}KiB"
  for arm in "${ARMS[@]}"; do
    n="$(reps_for "$arm")"
    arm_setup "$arm" "d$D" || { echo "    $arm: setup FAILED"; continue; }
    wt="$E13_WT"; bare="$E13_BARE"

    for ((i=0;i<BASE_MB*8;i++)); do gen_blob "$wt/src/base/b_$i.rs" 128 $((1000+i)); done
    if ! arm_stage_push "$arm" "$wt"; then echo "    $arm: base push FAILED"; rm -rf "$wt" "$bare"; continue; fi

    declare -a S_PUSH=() S_FETCH=() S_FORCE=() F_PUSH=() F_FETCH=()
    failed=""

    # --- floors: the SAME operation at zero payload on the SAME tool ---
    for ((k=0;k<3;k++)); do
      e13_timed arm_push_only "$arm" "$wt"; e13_sample F_PUSH $? || true
      e13_timed arm_fetch "$arm" "$wt";     e13_sample F_FETCH $? || true
    done

    # --- push: one delta of D KiB, staged and pushed ---
    for ((k=0;k<n;k++)); do
      gen_blob "$wt/src/op/p_${k}.rs" "$D" $((5000+k))
      e13_timed arm_stage_push "$arm" "$wt"; rc=$?
      if [[ $rc -eq 0 ]]; then
        want=$(git -C "$wt" rev-parse HEAD)
        [[ "$arm" == "safehub" ]] || e13_remote_at "$bare" main "$want" || rc=1
      fi
      e13_sample S_PUSH "$rc" || { failed="push"; break; }
    done

    # --- fetch after a push (payload present) ---
    for ((k=0;k<n;k++)); do
      [[ -n "$failed" ]] && break
      e13_timed arm_fetch "$arm" "$wt"; e13_sample S_FETCH $? || { failed="fetch"; break; }
    done

    # --- force-push: rewrite the tip, non-fast-forward ---
    for ((k=0;k<n;k++)); do
      [[ -n "$failed" ]] && break
      old=$(git -C "$wt" rev-parse HEAD)
      gen_blob "$wt/src/op/f_${k}.rs" "$D" $((7000+k))
      git -C "$wt" add -A >/dev/null; git -C "$wt" commit -q --amend -m "fp$k" >/dev/null
      new=$(git -C "$wt" rev-parse HEAD)
      if ! e13_is_non_ff "$wt" "$old" "$new"; then failed="force-not-nonff"; break; fi
      if [[ "$arm" == "safehub" ]]; then
        e13_timed bash -c "cd '$wt' && '$SIT' push --force"; rc=$?
        [[ $rc -eq 0 ]] && { e13_push_was_forced "$wt" || rc=1; }
      else
        e13_timed git -C "$wt" push -q --force origin HEAD; rc=$?
      fi
      e13_sample S_FORCE "$rc" || { failed="force"; break; }
    done

    ARM="$arm" D="$D" N="$n" BASE="$BASE_MB" FAILED="$failed" \
    PUSH="$(stats_json "${S_PUSH[@]:-}")"   FETCH="$(stats_json "${S_FETCH[@]:-}")" \
    FORCE="$(stats_json "${S_FORCE[@]:-}")" \
    FPUSH="$(stats_json "${F_PUSH[@]:-}")"  FFETCH="$(stats_json "${F_FETCH[@]:-}")" \
    BYTES="$(dir_bytes "${bare:-$DATA}" 2>/dev/null || echo 0)" \
    ROWS="$ROWS" python3 - <<'PY'
import json, os
def st(k):
    try: return json.loads(os.environ[k])
    except Exception: return {"n": 0, "status": "no-samples"}
def corrected(total, floor):
    # Floor is the SAME operation at zero payload on the SAME tool. Absent or
    # exceeding what it corrects, no corrected value is emitted -- that
    # condition is a fact about the measurement, not something to clamp away.
    if not total.get("median") or not floor.get("median"): return None
    v = total["median"] - floor["median"]
    return round(v, 3) if v > 0 else None
failed = os.environ["FAILED"]
push, fetch, force = st("PUSH"), st("FETCH"), st("FORCE")
fpush, ffetch = st("FPUSH"), st("FFETCH")
row = {
    "arm": os.environ["ARM"], "delta_kib": int(os.environ["D"]),
    "base_repo_mb": int(os.environ["BASE"]), "reps_requested": int(os.environ["N"]),
    "push_ms": push, "fetch_ms": fetch, "force_push_ms": force,
    "push_floor_ms": fpush, "push_floor_kind": "push_noop",
    "fetch_floor_ms": ffetch, "fetch_floor_kind": "fetch_noop",
    "push_corrected_ms": corrected(push, fpush),
    "fetch_corrected_ms": corrected(fetch, ffetch),
    "n_push": push.get("n", 0), "n_fetch": fetch.get("n", 0),
    "n_force": force.get("n", 0),
    "thin_dispersion": push.get("n", 0) < 5,
    "remote_bytes": int(os.environ["BYTES"] or 0),
    "measured": not failed, "status": "failed" if failed else "measured",
}
if failed:
    row["failed_at"] = failed
    for k in ("push_ms","fetch_ms","force_push_ms",
              "push_corrected_ms","fetch_corrected_ms"): row[k] = None
with open(os.environ["ROWS"], "a") as f: f.write(json.dumps(row)+"\n")
print("    {:9s} push={} fetch={} force={} n={} {}".format(
    row["arm"], (push or {}).get("median"), (fetch or {}).get("median"),
    (force or {}).get("median"), row["n_push"],
    "FAILED:"+failed if failed else ""))
PY
    rm -rf "$wt" "$bare"
  done
  ROWS="$ROWS" OUT="$OUT" REPS="$REPS" GREPS="$GREPS" BASE="$BASE_MB" \
    python3 "$SCRIPT_DIR/publish_e13.py" 2>/dev/null || echo "    (publish deferred)"
done
echo "==> done; rows at $ROWS"
