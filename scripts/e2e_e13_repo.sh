#!/usr/bin/env bash
# Eval E13 B/C/D — how cost responds to the REPOSITORY, not the edit.
#
# Design: code/eval/design-e13-full-matrix.md.  Guards: scripts/lib/e13_lib.sh.
#
#   B  size     vary repository size; push, clone and stored bytes
#   C  depth    vary history depth at a fixed delta; clone
#   D  updates  vary version count at a fixed delta; stored bytes
#
# B measures push as well as clone. gcrypt's cost is O(repository), and update
# is where that bites hardest -- nothing else in the matrix would show it. If
# gcrypt comes out flat in B it is not re-encrypting and the arm is broken.
#
# Clone is asserted to have produced a non-empty, hash-equal working tree on
# every arm. A `git clone` of a gcrypt remote exits 0 having checked out
# nothing, so timing it unchecked compares a partial operation against complete
# ones -- which is exactly what the currently published gcrypt clone number does.
#
# Env:
#   SAFEHUB_E13_MODE=size|depth|updates|revisions
#   SAFEHUB_E13_POINTS   mode-specific; see defaults
#   SAFEHUB_E13_REPS=5 / SAFEHUB_E13_GCRYPT_REPS=3
#   SAFEHUB_E13_ROOT     state root; must NOT be tmpfs
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/eval_common.sh"
source "$SCRIPT_DIR/lib/e13_lib.sh"

MODE="${SAFEHUB_E13_MODE:-size}"
case "$MODE" in
  size)    DEF_POINTS="5 10 25 50 100 200 300" ; DELTA_KIB=50 ;;   # MB
  depth)   DEF_POINTS="10 32 100 316 1000"     ; DELTA_KIB=64 ;;   # heads
  updates) DEF_POINTS="10 20 40 60 80 100"     ; DELTA_KIB=50 ;;   # versions
  # E: successive edits to the SAME file, rather than a new file per version.
  # Nothing else in the matrix does this, and it is the case that separates
  # append-structured ciphertext from rewrite-in-place: SGitChar appends one
  # encrypted block per edit and a reader must replay all of them, so its read
  # cost grows with the number of revisions while its write cost stays small.
  # It is also the case SafeHub's consolidation exists to bound.
  revisions) DEF_POINTS="1 10 25 50 100 200"   ; DELTA_KIB=1 ;;   # edits to one file
  *) echo "unknown SAFEHUB_E13_MODE=$MODE" >&2; exit 2 ;;
esac
POINTS="${SAFEHUB_E13_POINTS:-$DEF_POINTS}"
DELTA_KIB="${SAFEHUB_E13_DELTA_KIB:-$DELTA_KIB}"
OUT="${SAFEHUB_E13_OUT:-$EVAL_PUB/e13-$MODE-latest.json}"
REPS="${SAFEHUB_E13_REPS:-5}"
GREPS="${SAFEHUB_E13_GCRYPT_REPS:-3}"
DEPTH_BASE_MB="${SAFEHUB_E13_DEPTH_BASE_MB:-4}"
REV_FILE_KIB="${SAFEHUB_E13_REV_FILE_KIB:-256}"
UPD_BASE_MB="${SAFEHUB_E13_UPD_BASE_MB:-8}"
ROOT="${SAFEHUB_E13_ROOT:-$HOME/e13-$MODE}"
# With a server box named, SafeHub talks to it over the network like every
# other arm; otherwise a server is started here on loopback.
if [[ -n "${SAFEHUB_E13_SERVER:-}" ]]; then
  export SAFEHUB_HOST="http://${SAFEHUB_E13_SERVER:?}:${SAFEHUB_E13_SH_PORT:-18190}"
  LISTEN=""
else
  LISTEN="127.0.0.1:18185"
  export SAFEHUB_HOST="http://$LISTEN"
fi

rm -rf "$ROOT"; mkdir -p "$ROOT"
DATA="$ROOT/data"; CFG="$ROOT/cfg"; WORK="$ROOT/work"
mkdir -p "$DATA" "$CFG" "$WORK"
ROWS="${SAFEHUB_E13_ROWS:-$ROOT/rows.jsonl}"; : >"$ROWS"
export HOME="$CFG" XDG_CONFIG_HOME="$CFG/.config" SAFEHUB_DATA="$DATA"
export GNUPGHOME="$CFG/gnupg"
mkdir -p "$XDG_CONFIG_HOME" "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
echo "==> mode=$MODE points=[$POINTS] delta=${DELTA_KIB}KiB reps=$REPS(gcrypt $GREPS)"
echo "==> rows: $ROWS  root: $ROOT"

SERVER_PID=""
cleanup() { [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

eval_build safehub-server safehub-cli sit-remote-safehub sgit-rs
[[ -n "$LISTEN" ]] && eval_start_server "$LISTEN" "$DATA"
SH_USER="${SAFEHUB_E13_NS:-alice}$$"
"$SH" auth register --user "$SH_USER" --password "e13-pw-$SH_USER" --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default || true

ARMS=()
for a in git gitcrypt gcrypt safehub sgitchar sgitline; do
  if e13_arm_available "$a"; then ARMS+=("$a")
  else echo "==> arm $a UNAVAILABLE (reported absent, never zero)"; fi
done
GCRYPT_KEY=""
if printf '%s\n' "${ARMS[@]}" | grep -qx gcrypt; then
  GCRYPT_KEY="$(e13_gcrypt_key "$CFG")" || GCRYPT_KEY=""
  [[ -n "$GCRYPT_KEY" ]] || { echo "==> gcrypt key failed; arm dropped"
    ARMS=($(printf '%s\n' "${ARMS[@]}" | grep -vx gcrypt)); }
fi
echo "==> arms: ${ARMS[*]}"

reps_for() { [[ "$1" == "gcrypt" ]] && echo "$GREPS" || echo "$REPS"; }

arm_setup() {
  local arm="$1" tag="$2" wt bare
  wt="$WORK/${arm}_$tag"; bare="$WORK/${arm}_$tag.bare"
  rm -rf "$wt" "$bare"
  if [[ "$arm" == "safehub" ]]; then
    ( cd "$WORK" && "$SH" repo create "${arm}_$tag" --clone >/dev/null 2>&1 ) || return 1
    eval_git_identity "$wt"
  else
    local url
    url="$(e13_make_remote "$bare")" || return 1
    mkdir -p "$wt"; git init -q --template= --initial-branch=main "$wt"
    eval_git_identity "$wt"
    case "$arm" in
      gcrypt) git -C "$wt" remote add origin "gcrypt::$url"
              git -C "$wt" config gcrypt.participants "$GCRYPT_KEY"
              git -C "$wt" config gcrypt.publish-participants true ;;
      gitcrypt) git -C "$wt" remote add origin "$url"
              printf '*.rs filter=git-crypt diff=git-crypt\n' > "$wt/.gitattributes"
              ( cd "$wt" && git-crypt init >/dev/null 2>&1 ) || return 1
              # A fresh git-crypt clone is LOCKED: the working tree holds
              # ciphertext until unlocked with the symmetric key. Export it here
              # so the clone can do that inside its timer, the way every other
              # encrypted arm decrypts inside its clone.
              ( cd "$wt" && git-crypt export-key "$bare.gckey" >/dev/null 2>&1 ) || return 1 ;;
      git)    git -C "$wt" remote add origin "$url" ;;
      sgitchar|sgitline)
              "$SGIT" init "$wt" "$(e13_sgit_ct "$wt")" "$url" \
                      --variant "$(e13_sgit_variant "$arm")" >/dev/null 2>&1 || return 1 ;;
    esac
  fi
  E13_WT="$wt"; E13_BARE="$bare"
}
arm_update() {
  local arm="$1" wt="$2"
  # sgit versions the CIPHERTEXT repository: `sgit push` stages, commits and
  # pushes there. Committing the plaintext tree as well would charge these arms
  # a second commit that no other arm pays and their protocol does not require.
  # Every arm's cell still spans the same work -- stage, commit, transmit.
  if ! e13_is_sgit "$arm"; then
    git -C "$wt" add -A >/dev/null 2>&1 || return 1
    git -C "$wt" commit -qm up >/dev/null 2>&1 || return 1
  fi
  arm_push_only "$arm" "$wt"
}
arm_push_only() {
  local arm="$1" wt="$2"
  if [[ "$arm" == "safehub" ]]; then ( cd "$wt" && "$SIT" push >/dev/null 2>&1 )
  elif e13_is_sgit "$arm"; then
    "$SGIT" push "$wt" "$(e13_sgit_ct "$wt")" --variant "$(e13_sgit_variant "$arm")" >/dev/null 2>&1
  else git -C "$wt" push -q origin HEAD >/dev/null 2>&1; fi
}
# Clone, then CHECK OUT explicitly, and time both. gcrypt publishes no
# resolvable HEAD symref, so a plain clone leaves an empty tree.
arm_clone() {
  local arm="$1" bare="$2" wt="$3" dest="$4"
  rm -rf "$dest"
  case "$arm" in
    safehub) ( cd "$(dirname "$dest")" && "$SIT" clone "$SH_USER/$(basename "$wt")" "$(basename "$dest")" >/dev/null 2>&1 ) ;;
    gcrypt)  git clone -q "gcrypt::$(e13_arm_url "$bare")" "$dest" >/dev/null 2>&1 || return 1
             git -C "$dest" checkout -q -B main origin/main >/dev/null 2>&1 \
               || git -C "$dest" checkout -q -B master origin/master >/dev/null 2>&1 || return 1 ;;
    gitcrypt)
             # Unlock inside the timer. Without it the clone "succeeds" holding
             # ciphertext -- non-empty, so a non-empty check passes it -- and
             # git-crypt's read cost is reported as if decryption were free.
             git clone -q "$(e13_arm_url "$bare")" "$dest" >/dev/null 2>&1 || return 1
             ( cd "$dest" && git-crypt unlock "$bare.gckey" >/dev/null 2>&1 ) ;;
    sgitchar|sgitline)
             # Clone the ciphertext repository and replay every appended block
             # to recover the plaintext. For SGitChar that replay is the read
             # cost the appended-delta design trades against, so it belongs
             # inside the clone timer rather than beside it. The reader is
             # handed the repository key, as a member would receive it.
             #
             # The ciphertext checkout is scratch for this repetition; a stale
             # one left behind makes the next `git clone` refuse a non-empty
             # destination.
             rm -rf "$dest.ct"
             "$SGIT" clone "$(e13_arm_url "$bare")" "$dest" "$dest.ct" \
                     --variant "$(e13_sgit_variant "$arm")" \
                     --keys "$(e13_sgit_keys "$wt")" >/dev/null 2>&1 ;;
    *)       git clone -q "$(e13_arm_url "$bare")" "$dest" >/dev/null 2>&1 ;;
  esac
}

for pt in $POINTS; do
  echo "==> point $pt"
  for arm in "${ARMS[@]}"; do
    n="$(reps_for "$arm")"
    arm_setup "$arm" "p$pt" || { echo "    $arm: setup FAILED"; continue; }
    wt="$E13_WT"; bare="$E13_BARE"
    failed=""; nheads=0

    # What the remote already held before this point put anything in it.
    #
    # Every git-family arm gets a fresh bare repository per point, so for them
    # this is ~0 and absolute size is the same as growth. SafeHub is different:
    # its server keeps ONE store -- blobs, heads and blobmeta are global, not
    # per repository -- so a directory measurement returns everything the run
    # has ever pushed. Reporting that beside a fresh bare repo compares a
    # running total against a single point. Growth is the quantity that means
    # the same thing for every arm.
    STORED0="$(e13_remote_size "$arm" "$bare" "$DATA")"

    case "$MODE" in
      size)    for ((i=0;i<pt*8;i++)); do gen_file "$wt/src/base/b_$i.rs" 128 $((1000+i)); done
               arm_update "$arm" "$wt" || failed="base"; nheads=1 ;;
      depth)   for ((i=0;i<DEPTH_BASE_MB*8;i++)); do gen_file "$wt/src/base/b_$i.rs" 128 $((1000+i)); done
               arm_update "$arm" "$wt" || failed="base"
               for ((i=1;i<=pt;i++)); do
                 [[ -n "$failed" ]] && break
                 gen_file "$wt/src/rev/r_$i.rs" "$DELTA_KIB" $((3000+i))
                 arm_update "$arm" "$wt" || { failed="grow"; break; }
               done
               nheads=$pt ;;
      revisions)
               for ((i=0;i<UPD_BASE_MB*8;i++)); do gen_file "$wt/src/base/b_$i.rs" 128 $((1000+i)); done
               # One hot file, edited over and over. Its size is fixed so the
               # only thing varying across points is how many revisions it has.
               gen_file "$wt/src/rev/hot.rs" "$REV_FILE_KIB" 424242
               arm_update "$arm" "$wt" || failed="base"
               BASE_BYTES="$(e13_remote_size "$arm" "$bare" "$DATA")"
               for ((i=1;i<=pt;i++)); do
                 [[ -n "$failed" ]] && break
                 edit_file "$wt/src/rev/hot.rs" "$DELTA_KIB" $((5000+i))
                 arm_update "$arm" "$wt" || { failed="grow"; break; }
               done
               nheads=$pt ;;
      updates) for ((i=0;i<UPD_BASE_MB*8;i++)); do gen_file "$wt/src/base/b_$i.rs" 128 $((1000+i)); done
               arm_update "$arm" "$wt" || failed="base"
               # D's metric is storage growth PER VERSION. Recording what the
               # base alone costs makes a single point readable on its own,
               # rather than only as a slope across the whole sweep.
               BASE_BYTES="$(e13_remote_size "$arm" "$bare" "$DATA")"
               for ((i=1;i<=pt;i++)); do
                 [[ -n "$failed" ]] && break
                 gen_file "$wt/src/rev/r_$i.rs" "$DELTA_KIB" $((4000+i))
                 arm_update "$arm" "$wt" || { failed="grow"; break; }
               done
               nheads=$pt ;;
    esac

    declare -a S_PUSH=() S_CLONE=() F_PUSH=()
    if [[ -z "$failed" ]]; then
      # Pinned gc: receive.autogc firing mid-sweep made git's arm non-monotonic
      # in an earlier experiment. Every clone is timed against a defined state.
      [[ "$arm" == "safehub" ]] || git -C "$bare" gc --quiet >/dev/null 2>&1 || true

      for ((k=0;k<3;k++)); do rc=0; e13_timed arm_push_only "$arm" "$wt" || rc=$?; e13_sample F_PUSH "$rc" || true; done

      if [[ "$MODE" == "size" ]]; then
        for ((k=0;k<n;k++)); do
          gen_file "$wt/src/op/p_$k.rs" "$DELTA_KIB" $((6000+k))
          rc=0; e13_timed arm_update "$arm" "$wt" || rc=$?; e13_sample S_PUSH "$rc" || { failed="push"; break; }
        done
      elif [[ "$MODE" == "revisions" ]]; then
        # One MORE edit to the same file, at this revision depth: does writing
        # get more expensive as the appended history grows?
        for ((k=0;k<n;k++)); do
          edit_file "$wt/src/rev/hot.rs" "$DELTA_KIB" $((6500+k))
          rc=0; e13_timed arm_update "$arm" "$wt" || rc=$?; e13_sample S_PUSH "$rc" || { failed="push"; break; }
        done
      fi

      if [[ "$MODE" != "updates" ]]; then
        for ((k=0;k<n;k++)); do
          [[ -n "$failed" ]] && break
          rc=0; e13_timed arm_clone "$arm" "$bare" "$wt" "$WORK/cl" || rc=$?
          # Non-empty is not enough: a clone that checks out a stale or partial
          # tree is also non-empty. Compare content against the source.
          if [[ $rc -eq 0 ]] && ! e13_clone_nonempty "$WORK/cl"; then
            failed="clone-empty-tree"; rc=1
          elif [[ $rc -eq 0 ]] && ! e13_clone_matches "$wt" "$WORK/cl"; then
            failed="clone-content-mismatch"; rc=1
          fi
          e13_sample S_CLONE "$rc" || { failed="${failed:-clone}"; break; }
          rm -rf "$WORK/cl"
        done
        rm -rf "$WORK/cl"
      fi
    fi

    ARM="$arm" MODE="$MODE" PT="$pt" N="$n" DELTA="$DELTA_KIB" HEADS="$nheads" \
    BASEB="${BASE_BYTES:-}" \
    FAILED="$failed" PUSH="$(stats_json "${S_PUSH[@]:-}")" \
    CLONE="$(stats_json "${S_CLONE[@]:-}")" FLOOR="$(stats_json "${F_PUSH[@]:-}")" \
    BYTES="$(e13_remote_size "$arm" "$bare" "$DATA")" STORED0="$STORED0" \
    ROWS="$ROWS" python3 - <<'PY'
import json, os
def st(k):
    try: return json.loads(os.environ[k])
    except Exception: return {"n": 0, "status": "no-samples"}
def corrected(t, f):
    if not t.get("median") or not f.get("median"): return None
    v = t["median"] - f["median"]
    return round(v, 3) if v > 0 else None
failed = os.environ["FAILED"]
push, clone, floor = st("PUSH"), st("CLONE"), st("FLOOR")
row = {
    "arm": os.environ["ARM"], "mode": os.environ["MODE"],
    "point": int(os.environ["PT"]), "heads": int(os.environ["HEADS"]),
    "delta_kib": int(os.environ["DELTA"]), "reps_requested": int(os.environ["N"]),
    "push_ms": push if push.get("n") else None,
    "clone_ms": clone if clone.get("n") else None,
    "push_floor_ms": floor, "floor_kind": "push_noop",
    "push_corrected_ms": corrected(push, floor),
    # Absolute is kept for provenance; growth is what is comparable across
    # arms, because SafeHub's remote store is shared rather than per repository.
    "stored_bytes": int(os.environ["BYTES"] or 0),
    "stored_bytes_before": int(os.environ["STORED0"] or 0),
    "stored_growth_bytes": int(os.environ["BYTES"] or 0) - int(os.environ["STORED0"] or 0),
    # What the base alone cost, so storage growth per version is readable from a
    # single row rather than only as a slope across the sweep.
    "stored_base_bytes": (int(os.environ["BASEB"]) if os.environ.get("BASEB") else None),
    "n_push": push.get("n", 0), "n_clone": clone.get("n", 0),
    "thin_dispersion": max(push.get("n", 0), clone.get("n", 0)) < 5,
    "clone_checked_out": True,
    "measured": not failed, "status": "failed" if failed else "measured",
}
base_b = row["stored_base_bytes"]
row["stored_growth_per_version"] = (
    round((row["stored_bytes"] - base_b) / row["point"], 1)
    if base_b is not None and row["point"] else None)
if failed:
    row["failed_at"] = failed
    for k in ("push_ms", "clone_ms", "push_corrected_ms"): row[k] = None
with open(os.environ["ROWS"], "a") as f: f.write(json.dumps(row) + "\n")
print("    {:9s} pt={:<5} push={} clone={} stored={}MB {}".format(
    row["arm"], row["point"],
    (push or {}).get("median"), (clone or {}).get("median"),
    round(row["stored_growth_bytes"]/1e6, 1), "FAILED:"+failed if failed else ""))
PY
    rm -rf "$wt" "$bare"
    ROWS="$ROWS" OUT="$OUT" MODE="$MODE" REPS="$REPS" GREPS="$GREPS" \
      python3 "$SCRIPT_DIR/publish_e13.py" >/dev/null 2>&1 || echo "    (publish deferred)"
  done
done
ROWS="$ROWS" OUT="$OUT" MODE="$MODE" REPS="$REPS" GREPS="$GREPS" \
  python3 "$SCRIPT_DIR/publish_e13.py" || echo "==> PUBLISH FAILED"
cp "$ROWS" "${OUT%.json}-rows.jsonl" 2>/dev/null || true
echo "==> done; artifact $OUT ; rows copied beside it"
