#!/usr/bin/env bash
# Eval E13 A1/A2/A3 — how update cost responds to the SHAPE of an edit.
#
# Design and adversarial review: code/eval/design-e13-full-matrix.md.
# Guards: scripts/lib/e13_lib.sh, tested by scripts/tests/test_e13.sh.
#
# Four variables drive update cost and each tool responds to a different subset:
# git and SafeHub to the bytes changed, git-crypt to (files touched x file
# size), gcrypt to the whole repository. One sweep cannot separate them --
# writing a new delta-sized file makes delta equal file size, which collapses
# three arms onto one line. So this harness runs three modes over the same
# fixed base repository:
#
#   A1  delta   vary the size of NEW content            (L = delta, n_f = 1)
#   A2  filesz  vary file SIZE around a fixed 1 KiB edit (delta fixed, n_f = 1)
#   A3  nfiles  vary how many FILES a fixed edit touches (delta/file, L fixed)
#
# A2 is the one that earns the comparison: it is the only place git-crypt's
# real cost appears. If git-crypt comes out flat in A2 its .gitattributes
# filter is not engaging and the arm is broken, not cheap.
#
# The base repository is built ONCE per arm and reset between points, rather
# than rebuilt per point: construction dominates the runtime, not measurement.
#
# Env:
#   SAFEHUB_E13_MODE=delta|filesz|nfiles
#   SAFEHUB_E13_POINTS   mode-specific; see defaults below
#   SAFEHUB_E13_REPS=5   repetitions (gcrypt uses SAFEHUB_E13_GCRYPT_REPS=3)
#   SAFEHUB_E13_BASE_MB=16
#   SAFEHUB_E13_ROOT=$HOME/e13   state root; must NOT be tmpfs
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/eval_common.sh"
source "$SCRIPT_DIR/lib/e13_lib.sh"

MODE="${SAFEHUB_E13_MODE:-delta}"
case "$MODE" in
  delta)  DEF_POINTS="5 10 50 100 500 1024 1536 2048 2560 3072" ;;   # KiB of new content
  filesz) DEF_POINTS="10 50 100 500 1024 2048 4096 8192" ;;          # KiB file, 1 KiB edit
  nfiles) DEF_POINTS="1 2 5 10 20 50 100" ;;                         # files, 1 KiB edit each
  *) echo "unknown SAFEHUB_E13_MODE=$MODE" >&2; exit 2 ;;
esac
POINTS="${SAFEHUB_E13_POINTS:-$DEF_POINTS}"
OUT="${SAFEHUB_E13_OUT:-$EVAL_PUB/e13-$MODE-latest.json}"
REPS="${SAFEHUB_E13_REPS:-5}"
GREPS="${SAFEHUB_E13_GCRYPT_REPS:-3}"
BASE_MB="${SAFEHUB_E13_BASE_MB:-16}"
EDIT_KIB="${SAFEHUB_E13_EDIT_KIB:-1}"
NFILE_KIB="${SAFEHUB_E13_NFILE_KIB:-100}"
ROOT="${SAFEHUB_E13_ROOT:-$HOME/e13-$MODE}"
# With a server box named, SafeHub talks to it over the network like every
# other arm; otherwise a server is started here on loopback.
if [[ -n "${SAFEHUB_E13_SERVER:-}" ]]; then
  export SAFEHUB_HOST="http://${SAFEHUB_E13_SERVER:?}:${SAFEHUB_E13_SH_PORT:-18190}"
  LISTEN=""
else
  LISTEN="127.0.0.1:18183"
  export SAFEHUB_HOST="http://$LISTEN"
fi

rm -rf "$ROOT"; mkdir -p "$ROOT"
DATA="$ROOT/data"; CFG="$ROOT/cfg"; WORK="$ROOT/work"
mkdir -p "$DATA" "$CFG" "$WORK"
ROWS="${SAFEHUB_E13_ROWS:-$ROOT/rows.jsonl}"; : >"$ROWS"
export HOME="$CFG" XDG_CONFIG_HOME="$CFG/.config" SAFEHUB_DATA="$DATA"
export GNUPGHOME="$CFG/gnupg"
mkdir -p "$XDG_CONFIG_HOME" "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
echo "==> mode=$MODE points=[$POINTS] reps=$REPS(gcrypt $GREPS) base=${BASE_MB}MB"
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


arm_build_base() {   # build the base ONCE per arm; returns wt/bare in E13_WT/E13_BARE
  local arm="$1" wt bare
  wt="$WORK/$arm"; bare="$WORK/$arm.bare"
  rm -rf "$wt" "$bare"
  if [[ "$arm" == "safehub" ]]; then
    ( cd "$WORK" && "$SH" repo create "$arm" --clone >/dev/null 2>&1 ) || return 1
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
              ( cd "$wt" && git-crypt init >/dev/null 2>&1 ) || return 1 ;;
      git)    git -C "$wt" remote add origin "$url" ;;
      sgitchar|sgitline)
              # The developer's repository stays plaintext and local; sgit keeps
              # an encrypted mirror beside it and pushes THAT to an ordinary bare
              # Git remote with an ordinary push. The plaintext repository has no
              # remote of its own -- that is the whole shape of the add-on.
              "$SGIT" init "$wt" "$(e13_sgit_ct "$wt")" "$url" \
                      --variant "$(e13_sgit_variant "$arm")" >/dev/null 2>&1 || return 1 ;;
    esac
  fi
  local i
  for ((i=0;i<BASE_MB*8;i++)); do gen_file "$wt/src/base/b_$i.rs" 128 $((1000+i)); done
  git -C "$wt" add -A >/dev/null; git -C "$wt" commit -qm base >/dev/null
  E13_WT="$wt"; E13_BARE="$bare"
}

# git-crypt encrypts in clean/smudge filters at staging, so timing `push` alone
# would report it as free encryption. Every arm's update cell therefore times
# add + commit + push, so the same work sits inside every timer.
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
    # Encrypt, commit the ciphertext mirror, push it. One command, so the timer
    # covers the same span as every other arm's push.
    "$SGIT" push "$wt" "$(e13_sgit_ct "$wt")" --variant "$(e13_sgit_variant "$arm")" >/dev/null 2>&1
  else git -C "$wt" push -q origin HEAD >/dev/null 2>&1; fi
}

# Create the fixture a point edits, so that every measured repetition performs
# the SAME operation. Created lazily inside the measurement loop instead, the
# first repetition commits and pushes a whole new file while later ones push
# only an edit -- so an A2 point at 2 MiB was reporting the cost of shipping a
# 2 MiB file averaged with the cost of a 1 KiB edit, on every arm at once. This
# runs untimed and is landed on the remote before the floor is taken.
#
# A1 seeds nothing: there, writing a new file of the point's size IS the
# operation under measurement.
seed_point() {   # arm wt point
  local wt="$2" pt="$3" i
  case "$MODE" in
    delta)  : ;;
    filesz) gen_file "$wt/src/op/big_$pt.rs" "$pt" 424242 ;;
    nfiles) for ((i=0;i<pt;i++)); do gen_file "$wt/src/op/m_${i}.rs" "$NFILE_KIB" $((900+i)); done ;;
  esac
}

# Shape one point's edit. Returns the total bytes actually changed, so the row
# records the real payload rather than the nominal parameter.
apply_edit() {   # arm wt point rep -> echoes bytes changed
  local wt="$2" pt="$3" rep="$4" i changed=0
  case "$MODE" in
    delta)   gen_file "$wt/src/op/n_${pt}_$rep.rs" "$pt" $((7000+rep))
             changed=$((pt*1024)) ;;
    filesz)  # the file of `pt` KiB was seeded and landed before measuring;
             # this changes EDIT_KIB inside it and nothing else
             edit_file "$wt/src/op/big_$pt.rs" "$EDIT_KIB" $((8000+rep))
             changed=$((EDIT_KIB*1024)) ;;
    nfiles)  for ((i=0;i<pt;i++)); do
               edit_file "$wt/src/op/m_${i}.rs" "$EDIT_KIB" $((9000+rep*1000+i))
             done
             changed=$((pt*EDIT_KIB*1024)) ;;
  esac
  echo "$changed"
}

for arm in "${ARMS[@]}"; do
  n="$(reps_for "$arm")"
  echo "==> arm $arm: building base once (${BASE_MB}MB)"
  if ! arm_build_base "$arm"; then echo "    $arm: base build FAILED"; continue; fi
  wt="$E13_WT"; bare="$E13_BARE"
  if ! arm_push_only "$arm" "$wt"; then echo "    $arm: base push FAILED"; rm -rf "$wt" "$bare"; continue; fi
  BASE_REF=$(git -C "$wt" rev-parse HEAD)

  for pt in $POINTS; do
    declare -a S=() F=()
    failed=""; changed=0

    # Land the point's fixture first, untimed, so the floor and every measured
    # repetition all see the same repository state.
    # Keyed on the mode, not on the plaintext repository being dirty: the sgit
    # arms version the ciphertext repository, so the plaintext tree's Git status
    # says nothing about whether the fixture has been landed. seed_point creates
    # a fixture in exactly the two modes that edit one.
    seed_point "$arm" "$wt" "$pt"
    if [[ "$MODE" != "delta" ]]; then
      arm_update "$arm" "$wt" || failed="seed"
    fi

    # Floor: the SAME operation with nothing to send, on the SAME tool.
    for ((k=0;k<3;k++)); do rc=0; e13_timed arm_push_only "$arm" "$wt" || rc=$?; e13_sample F "$rc" || true; done

    R0="$(e13_remote_size "$arm" "$bare" "$DATA")"
    H0="$(e13_remote_tip "$arm" "$bare")"

    for ((k=0;k<n;k++)); do
      changed=$(apply_edit "$arm" "$wt" "$pt" "$k")
      rc=0; e13_timed arm_update "$arm" "$wt" || rc=$?
      # The remote-tip assertion only applies to arms whose remote exposes a
      # plaintext ref map. gcrypt stores an encrypted manifest and SafeHub an
      # encrypted RefHead, so `rev-parse refs/heads/main` on their remotes
      # reads nothing -- that opacity is the security property, not a defect.
      # Those two are checked by clone-and-compare in experiment B instead.
      if [[ $rc -eq 0 && ( "$arm" == "git" || "$arm" == "gitcrypt" ) ]]; then
        want=$(git -C "$wt" rev-parse HEAD)
        e13_remote_at "$bare" main "$want" || rc=1
      elif [[ $rc -eq 0 ]] && e13_is_sgit "$arm"; then
        # The sgit remote holds the CIPHERTEXT repository, so its tip is that
        # repository's HEAD rather than the plaintext one. Checking it is still
        # worth doing: it catches a push that reported success without landing.
        want=$(git -C "$(e13_sgit_ct "$wt")" rev-parse HEAD)
        e13_remote_at "$bare" main "$want" || rc=1
      fi
      e13_sample S "$rc" || { failed="update"; break; }
    done

    # Bytes the point cost the remote, and -- where the transport is an ordinary
    # Git push -- the bytes those pushes put on the wire. The thin pack is built
    # against the remote tip from BEFORE the point: computed afterwards it is
    # empty, because by then the remote already holds everything.
    WIRE=""
    if [[ -n "$H0" && -z "$failed" ]]; then
      WIRE="$(e13_thin_bytes "$(e13_pushing_repo "$arm" "$wt")" "$H0")"
    fi
    R1="$(e13_remote_size "$arm" "$bare" "$DATA")"

    ARM="$arm" MODE="$MODE" PT="$pt" N="$n" BASE="$BASE_MB" CHANGED="$changed" \
    EDIT="$EDIT_KIB" NFKIB="$NFILE_KIB" FAILED="$failed" \
    UPD="$(stats_json "${S[@]:-}")" FLOOR="$(stats_json "${F[@]:-}")" \
    R0="$R0" R1="$R1" WIRE="$WIRE" \
    ROWS="$ROWS" python3 - <<'PY'
import json, os
def st(k):
    try: return json.loads(os.environ[k])
    except Exception: return {"n": 0, "status": "no-samples"}
def corrected(t, f):
    # Floor is the SAME operation at zero payload on the SAME tool. Absent, or
    # exceeding what it corrects, no corrected value is emitted.
    if not t.get("median") or not f.get("median"): return None
    v = t["median"] - f["median"]
    return round(v, 3) if v > 0 else None
failed = os.environ["FAILED"]; upd, floor = st("UPD"), st("FLOOR")
row = {
    "arm": os.environ["ARM"], "mode": os.environ["MODE"],
    "point": int(os.environ["PT"]), "bytes_changed": int(os.environ["CHANGED"]),
    "base_repo_mb": int(os.environ["BASE"]), "edit_kib": int(os.environ["EDIT"]),
    "nfile_kib": int(os.environ["NFKIB"]), "reps_requested": int(os.environ["N"]),
    "update_ms": upd, "update_floor_ms": floor, "floor_kind": "push_noop",
    "update_corrected_ms": corrected(upd, floor),
    "n_update": upd.get("n", 0), "thin_dispersion": upd.get("n", 0) < 5,
    # Storage the point added to the remote, packed at both ends, and the wire
    # bytes of the pushes that added it. wire_bytes is None where the transport
    # is not an ordinary Git push and no thin pack exists to measure.
    "remote_bytes_before": int(os.environ["R0"] or 0),
    "remote_bytes_after": int(os.environ["R1"] or 0),
    "remote_growth_bytes": int(os.environ["R1"] or 0) - int(os.environ["R0"] or 0),
    "wire_bytes_total": (int(os.environ["WIRE"]) if os.environ.get("WIRE") else None),
    "measured": not failed, "status": "failed" if failed else "measured",
}
nu = row["n_update"] or 0
row["wire_bytes_per_update"] = (round(row["wire_bytes_total"] / nu, 1)
                                if row["wire_bytes_total"] is not None and nu else None)
row["remote_growth_per_update"] = round(row["remote_growth_bytes"] / nu, 1) if nu else None
if failed:
    row["failed_at"] = failed
    for k in ("update_ms", "update_corrected_ms", "wire_bytes_total",
              "wire_bytes_per_update", "remote_growth_per_update"): row[k] = None
with open(os.environ["ROWS"], "a") as f: f.write(json.dumps(row) + "\n")
print("    {:9s} {:>6} -> {} ms (n={}, changed={}B, wire={}, growth={}) {}".format(
    row["arm"], row["point"], (upd or {}).get("median"), row["n_update"],
    row["bytes_changed"], row["wire_bytes_per_update"], row["remote_growth_per_update"],
    "FAILED:" + failed if failed else ""))
PY
    # Reset to the base commit so the next point starts from identical state
    # rather than inheriting the previous point's edits.
    # Return the TREE to its base state by deleting the point's files in a
    # normal forward commit, rather than rewinding to the base commit. A rewind
    # makes the next push a non-fast-forward on every arm, which for SafeHub is
    # correctly refused without an admin co-signature -- a failure that has
    # nothing to do with what is being measured. Going forward costs one extra
    # commit per point, identically on every arm.
    rm -rf "$wt/src/op"
    git -C "$wt" add -A >/dev/null 2>&1 || true
    git -C "$wt" commit -qm "reset to base tree" >/dev/null 2>&1 || true
    arm_push_only "$arm" "$wt" >/dev/null 2>&1 || true

    # Publish after every point. Rows live under $ROOT, which the caller may
    # clear between experiments; the artifact must already be written by then.
    ROWS="$ROWS" OUT="$OUT" MODE="$MODE" REPS="$REPS" GREPS="$GREPS" \
      python3 "$SCRIPT_DIR/publish_e13.py" >/dev/null 2>&1 || echo "    (publish deferred)"
  done
  rm -rf "$wt" "$bare"
done
ROWS="$ROWS" OUT="$OUT" MODE="$MODE" REPS="$REPS" GREPS="$GREPS" \
  python3 "$SCRIPT_DIR/publish_e13.py" || echo "==> PUBLISH FAILED"
cp "$ROWS" "${OUT%.json}-rows.jsonl" 2>/dev/null || true
echo "==> done; artifact $OUT ; rows copied beside it"
