#!/usr/bin/env bash
# Eval E13 — full benchmark matrix: 9 operations x 4 tools x 2 bases.
#
# Design and adversarial review: code/eval/design-e13-full-matrix.md.
# Guards: scripts/lib/e13_lib.sh, tested by scripts/tests/test_e13.sh.
#
# Size axis, 5 -> 300 MB, at a fixed 64 KiB per-operation delta. Each point
# builds all four arms on identical content, measures every operation each tool
# supports, tears the point down, and publishes before starting the next -- so
# a sweep that dies at 250 MB leaves every earlier point already on disk.
#
# Every timed command's status is checked, every operation asserts a
# postcondition, and each operation's corrected basis is its OWN no-payload
# floor on the SAME tool (see e13_lib.sh).
#
# Env:
#   SAFEHUB_E13_SIZES="5 10 25 50 75 100 150 200 250 300"
#   SAFEHUB_E13_OPS=10          operations per cell
#   SAFEHUB_E13_GCRYPT_OPS=3    gcrypt only; topped up to 10 in a later run
#   SAFEHUB_E13_DELTA_KIB=64    fixed operating point
#   SAFEHUB_E13_ROOT=$HOME/e13  state root; must NOT be tmpfs
#
# Publishes: code/eval/published/e13-matrix-latest.json
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/eval_common.sh"
source "$SCRIPT_DIR/lib/e13_lib.sh"

OUT="${SAFEHUB_E13_OUT:-$EVAL_PUB/e13-matrix-latest.json}"
SIZES="${SAFEHUB_E13_SIZES:-5 10 25 50 75 100 150 200 250 300}"
OPS="${SAFEHUB_E13_OPS:-10}"
GCRYPT_OPS="${SAFEHUB_E13_GCRYPT_OPS:-3}"
DELTA_KIB="${SAFEHUB_E13_DELTA_KIB:-64}"
# /tmp on the eval host is tmpfs at 31 GB and cannot hold a 300 MB point across
# four arms. State goes on the root disk.
ROOT="${SAFEHUB_E13_ROOT:-$HOME/e13}"
LISTEN="127.0.0.1:18181"
export SAFEHUB_HOST="http://$LISTEN"

rm -rf "$ROOT"; mkdir -p "$ROOT"
DATA="$ROOT/data"; CFG="$ROOT/cfg"; WORK="$ROOT/work"
mkdir -p "$DATA" "$CFG" "$WORK"
ROWS="${SAFEHUB_E13_ROWS:-$ROOT/rows.jsonl}"
: >"$ROWS"
echo "==> rows: $ROWS   state root: $ROOT"
export HOME="$CFG" XDG_CONFIG_HOME="$CFG/.config" SAFEHUB_DATA="$DATA"
export GNUPGHOME="$CFG/gnupg"
mkdir -p "$XDG_CONFIG_HOME" "$GNUPGHOME"; chmod 700 "$GNUPGHOME"

SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  pkill -f 'git daemon' 2>/dev/null || true
}
trap cleanup EXIT

eval_build safehub-server safehub-cli sit-remote-safehub
eval_start_server "$LISTEN" "$DATA"
"$SH" auth register --user alice --password alice-e13-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default || true

# Which arms can run. An absent tool is reported absent, never as a zero.
ARMS=()
for a in git gitcrypt gcrypt safehub; do
  if e13_arm_available "$a"; then ARMS+=("$a"); else echo "==> arm $a UNAVAILABLE"; fi
done
echo "==> arms: ${ARMS[*]}"

GCRYPT_KEY=""
if printf '%s\n' "${ARMS[@]}" | grep -qx gcrypt; then
  GCRYPT_KEY="$(e13_gcrypt_key "$CFG")" || GCRYPT_KEY=""
  [[ -n "$GCRYPT_KEY" ]] || { echo "==> gcrypt key generation failed; dropping arm"; \
    ARMS=($(printf '%s\n' "${ARMS[@]}" | grep -vx gcrypt)); }
fi

# Compressible, source-shaped content: random bytes would make every packfile
# incompressible and turn this into an I/O measurement.
gen_blob() {
  local path="$1" kib="$2" seed="$3"
  python3 - "$path" "$kib" "$seed" <<'PY'
import random, sys
from pathlib import Path
path, kib, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rng = random.Random(seed)
idents = ["resolve", "encode", "verify", "merge", "index", "flush", "render"]
types = ["u64", "usize", "String", "Vec<u8>"]
out, size, i = [], 0, 0
target = kib * 1024
while size < target:
    b = (f"/// unit {seed}_{i}\n"
         f"pub fn {rng.choice(idents)}_{seed}_{i}(x: &{rng.choice(types)}) -> u64 {{\n"
         f"    let mut o = 0u64; for _ in 0..{rng.randint(1,9)} {{ o += 1; }} o\n}}\n")
    out.append(b); size += len(b); i += 1
Path(path).parent.mkdir(parents=True, exist_ok=True)
Path(path).write_text("".join(out))
PY
}

ops_for() { [[ "$1" == "gcrypt" ]] && echo "$GCRYPT_OPS" || echo "$OPS"; }

# ------------------------------------------------------------- arm setup ----
# Returns the working tree for an arm at this point, with the remote wired and
# the base tree pushed. Each arm gets byte-identical content.
arm_setup() {
  local arm="$1" mb="$2" wt bare
  wt="$WORK/$arm"; bare="$WORK/$arm.bare"
  rm -rf "$wt" "$bare"
  case "$arm" in
    safehub)
      ( cd "$WORK" && "$SH" repo create "e13$mb" --clone >/dev/null 2>&1 ) || return 1
      mv "$WORK/e13$mb" "$wt" 2>/dev/null || wt="$WORK/e13$mb"
      eval_git_identity "$wt"
      ;;
    *)
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
          ( cd "$wt" && git-crypt init >/dev/null 2>&1 ) || return 1
          printf '*.rs filter=git-crypt diff=git-crypt\n' > "$wt/.gitattributes" ;;
        git)
          git -C "$wt" remote add origin "file://$bare" ;;
      esac
      ;;
  esac
  E13_WT="$wt"; E13_BARE="$bare"
  return 0
}

arm_push() {   # arm wt -> pushes current HEAD
  local arm="$1" wt="$2"
  if [[ "$arm" == "safehub" ]]; then ( cd "$wt" && "$SIT" push ); else
    git -C "$wt" push -q origin HEAD; fi
}

arm_clone() {  # arm bare wt dest
  local arm="$1" bare="$2" wt="$3" dest="$4"
  rm -rf "$dest"
  case "$arm" in
    safehub) ( cd "$(dirname "$dest")" && "$SIT" clone "alice/$(basename "$wt")" "$(basename "$dest")" ) ;;
    gcrypt)
      git clone -q "gcrypt::file://$bare" "$dest" || return 1
      # A gcrypt clone exits 0 having checked out nothing, because it publishes
      # no resolvable HEAD symref. Check out explicitly and count it as part of
      # the clone: otherwise this arm is timed for a partial operation while
      # the others do the whole thing.
      git -C "$dest" checkout -q -B main origin/main 2>/dev/null \
        || git -C "$dest" checkout -q -B master origin/master 2>/dev/null || return 1 ;;
    *) git clone -q "file://$bare" "$dest" ;;
  esac
}

echo "==> sizes: $SIZES | ops=$OPS (gcrypt=$GCRYPT_OPS) | delta=${DELTA_KIB}KiB"
for MB in $SIZES; do
  echo "==> point ${MB}MB"
  for arm in "${ARMS[@]}"; do
    n="$(ops_for "$arm")"
    arm_setup "$arm" "$MB" || { echo "    $arm: setup FAILED"; continue; }
    wt="$E13_WT"; bare="$E13_BARE"

    # Base tree of MB megabytes, in 128 KiB files.
    files=$(( MB * 8 ))
    for ((i=0;i<files;i++)); do gen_blob "$wt/src/base/b_$i.rs" 128 $((1000+i)); done
    git -C "$wt" add -A >/dev/null; git -C "$wt" commit -qm base >/dev/null
    if ! arm_push "$arm" "$wt" >/dev/null 2>&1; then
      echo "    $arm: base push FAILED"; continue
    fi

    declare -a S_PUSH=() S_PULL=() S_CLONE=()
    declare -a F_PUSH=() F_FETCH=() F_CLONE=()
    failed=""

    # --- floors: each operation at zero payload, on this same tool ---
    for ((k=0;k<3;k++)); do
      e13_timed arm_push "$arm" "$wt"; rc=$?
      # a no-op push may legitimately fail ("up to date"); record only successes
      e13_sample F_PUSH "$rc" || true
    done

    # --- push: 10 (or 3) operations of one 64 KiB delta ---
    for ((k=0;k<n;k++)); do
      gen_blob "$wt/src/op/p_$k.rs" "$DELTA_KIB" $((5000+k))
      git -C "$wt" add -A >/dev/null; git -C "$wt" commit -qm "p$k" >/dev/null
      want=$(git -C "$wt" rev-parse HEAD)
      e13_timed arm_push "$arm" "$wt"; rc=$?
      e13_sample S_PUSH "$rc" || { failed="push"; break; }
    done

    # --- clone ---
    for ((k=0;k<3;k++)); do
      e13_timed arm_clone "$arm" "$bare" "$wt" "$WORK/cl"; rc=$?
      if [[ $rc -eq 0 ]] && ! e13_clone_nonempty "$WORK/cl"; then
        failed="clone-empty"; rc=1
      fi
      e13_sample S_CLONE "$rc" || { failed="${failed:-clone}"; break; }
      rm -rf "$WORK/cl"
    done
    rm -rf "$WORK/cl"

    ARM="$arm" MB="$MB" N="$n" DELTA="$DELTA_KIB" FAILED="$failed" \
    PUSH="$(stats_json "${S_PUSH[@]:-}")" CLONE="$(stats_json "${S_CLONE[@]:-}")" \
    FPUSH="$(stats_json "${F_PUSH[@]:-}")" \
    BYTES="$(dir_bytes "$bare" 2>/dev/null || dir_bytes "$DATA")" \
    ROWS="$ROWS" python3 - <<'PY'
import json, os
def st(k):
    try: return json.loads(os.environ[k])
    except Exception: return {"n": 0, "status": "no-samples"}
failed = os.environ["FAILED"]
push, clone, fpush = st("PUSH"), st("CLONE"), st("FPUSH")
def corrected(total, floor):
    # Floor is the SAME operation at zero payload on the SAME tool. If it was
    # not measured, or exceeds what it corrects, no corrected value is emitted.
    if not total.get("median") or not floor.get("median"): return None
    v = total["median"] - floor["median"]
    return round(v, 3) if v > 0 else None
row = {
    "arm": os.environ["ARM"], "size_mb": int(os.environ["MB"]),
    "per_op_delta_kib": int(os.environ["DELTA"]), "n_requested": int(os.environ["N"]),
    "push_ms": push, "clone_ms": clone,
    "push_floor_ms": fpush, "push_floor_kind": "push_noop",
    "push_corrected_ms": corrected(push, fpush),
    "remote_bytes": int(os.environ["BYTES"] or 0),
    "n_push": push.get("n", 0), "n_clone": clone.get("n", 0),
    "thin_dispersion": push.get("n", 0) < 5,
    "measured": not failed, "status": "failed" if failed else "measured",
}
if failed:
    row["failed_at"] = failed
    for k in ("push_ms","clone_ms","push_corrected_ms"): row[k] = None
with open(os.environ["ROWS"], "a") as f: f.write(json.dumps(row)+"\n")
print("    {:9s} push={} clone={} n={} {}".format(
    row["arm"], (push or {}).get("median"), (clone or {}).get("median"),
    row["n_push"], "FAILED:"+failed if failed else ""))
PY
    # Tear the arm down before the next: several 300 MB arms will not coexist.
    rm -rf "$wt" "$bare"
  done
  # Publish after every point, so a crash costs one point rather than the run.
  ROWS="$ROWS" OUT="$OUT" OPS="$OPS" GOPS="$GCRYPT_OPS" DELTA="$DELTA_KIB" \
    python3 "$SCRIPT_DIR/publish_e13.py" || echo "    (publish deferred)"
done
echo "==> done; rows at $ROWS"
