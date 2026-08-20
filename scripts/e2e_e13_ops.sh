#!/usr/bin/env bash
# Eval E13 sweep 2 — the operations sweep 1 does not cover, against history depth.
#
# Plan: code/eval/SWEEP2-PLAN.md. Guards: scripts/lib/e13_lib.sh, tested by
# scripts/tests/test_e13.sh and scripts/tests/test_e13_ops.sh.
#
# Sweep 1 times stage-commit-push, its floor, and clone. This times pull, fetch,
# merge, rebase, force-push, rotate and consolidation, on the axis they were
# originally scoped against: history depth at a fixed delta.
#
# One base per arm per point. Building history to depth 1000 dominates the cost
# and is shared by every operation at that point, so the base is built once and
# every operation is measured against it. Rebuilding per operation would make
# this seven sweeps.
#
# Which cells exist is decided by e13_op_defined, not by whether a number came
# back: an operation a design cannot express is reported as a dash, never zero.
#
# Env:
#   SAFEHUB_E13_POINTS="10 100 316 1000"   history depth
#   SAFEHUB_E13_OPS="pull fetch merge rebase forcepush rotate consolidate"
#   SAFEHUB_E13_DELTA_KIB=50               fixed delta per head
#   SAFEHUB_E13_REPS=5 / _GCRYPT_REPS=3
#   SAFEHUB_E13_SERVER=<ip>                split-host mode (see e13_lib.sh)
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/eval_common.sh"
# eval_common.sh sets -e. This harness reports per-cell failures instead of
# aborting, so errexit goes back off here -- otherwise one bad rev-parse ends
# the sweep, including points and arms not yet measured.
set +e
source "$SCRIPT_DIR/lib/e13_lib.sh"

POINTS="${SAFEHUB_E13_POINTS:-10 100 316 1000}"
OPS="${SAFEHUB_E13_OPS:-pull fetch merge rebase forcepush rotate consolidate}"
DELTA_KIB="${SAFEHUB_E13_DELTA_KIB:-50}"
REPS="${SAFEHUB_E13_REPS:-5}"
GREPS="${SAFEHUB_E13_GCRYPT_REPS:-3}"
BASE_MB="${SAFEHUB_E13_OPS_BASE_MB:-4}"
ROOT="${SAFEHUB_E13_ROOT:-$HOME/e13-ops}"
OUT="${SAFEHUB_E13_OUT:-$EVAL_PUB/e13-ops-latest.json}"

if [[ -n "${SAFEHUB_E13_SERVER:-}" ]]; then
  export SAFEHUB_HOST="http://${SAFEHUB_E13_SERVER:?}:${SAFEHUB_E13_SH_PORT:-18190}"
  LISTEN=""
else
  LISTEN="127.0.0.1:18187"
  export SAFEHUB_HOST="http://$LISTEN"
fi

rm -rf "$ROOT"; mkdir -p "$ROOT"
DATA="$ROOT/data"; CFG="$ROOT/cfg"; WORK="$ROOT/work"
mkdir -p "$DATA" "$CFG" "$WORK"
ROWS="${SAFEHUB_E13_ROWS:-$ROOT/rows.jsonl}"; : >"$ROWS"
export HOME="$CFG" XDG_CONFIG_HOME="$CFG/.config" SAFEHUB_DATA="$DATA"
export GNUPGHOME="$CFG/gnupg"; mkdir -p "$XDG_CONFIG_HOME" "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
echo "==> ops=[$OPS] points=[$POINTS] delta=${DELTA_KIB}KiB reps=$REPS(gcrypt $GREPS)"

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
  if [[ -z "$GCRYPT_KEY" ]]; then
    echo "==> gcrypt key generation FAILED; arm dropped (reported absent, never zero)"
    ARMS=($(printf '%s\n' "${ARMS[@]}" | grep -vx gcrypt))
  fi
fi
echo "==> arms: ${ARMS[*]}"
reps_for() { [[ "$1" == "gcrypt" ]] && echo "$GREPS" || echo "$REPS"; }

# --------------------------------------------------------- definedness -----
#
# Whether an (operation, arm) pair exists at all. This is consulted before
# measuring, so an undefined cell is a dash in the record rather than a zero
# that reads as "free".
e13_op_defined() {   # op arm
  local op="$1" arm="$2"
  case "$op" in
    pull|fetch|merge|rebase) return 0 ;;
    forcepush)
      # SGit's ciphertext repository only ever appends: a plaintext history
      # rewrite still lands as a forward-only ciphertext commit, so the host
      # cannot tell a rewrite from an ordinary push and cannot enforce branch
      # protection. The operation is undefined host-side, which is a result
      # about the design rather than a missing measurement.
      ! e13_is_sgit "$arm" ;;
    rotate|consolidate)
      # An MLS epoch advance and an admin-authorized compaction have no
      # counterpart in the other tools; git-crypt has no rekey mechanism at all.
      [[ "$arm" == "safehub" ]] ;;
    *) return 1 ;;
  esac
}

# ------------------------------------------------------------- per-arm ops --

arm_pull() {   # arm wt
  local arm="$1" wt="$2"
  if [[ "$arm" == "safehub" ]]; then ( cd "$wt" && "$SIT" pull >/dev/null 2>&1 )
  elif e13_is_sgit "$arm"; then
    "$SGIT" pull "$wt" "$(e13_sgit_ct "$wt")" --variant "$(e13_sgit_variant "$arm")" \
            --keys "$(e13_sgit_keys "$wt")" >/dev/null 2>&1
  else git -C "$wt" pull -q --ff-only origin "$(e13_ops_trunk "$wt")" >/dev/null 2>&1; fi
}

arm_fetch() {  # arm wt
  local arm="$1" wt="$2"
  if [[ "$arm" == "safehub" ]]; then ( cd "$wt" && "$SIT" fetch >/dev/null 2>&1 )
  elif e13_is_sgit "$arm"; then
    git -C "$(e13_sgit_ct "$wt")" fetch -q origin >/dev/null 2>&1
  else git -C "$wt" fetch -q origin >/dev/null 2>&1; fi
}

# Merge and rebase happen in the working copy and are then transmitted. For the
# sgit arms the working copy is a Git repository too, so the shape is the same:
# resolve locally, then push. Both halves are inside the timer, because a merge
# whose result is never sent is not an operation a collaborator can observe.
arm_merge() {  # arm wt branch
  local arm="$1" wt="$2" br="$3"
  git -C "$wt" merge --no-ff -q -m "merge $br" "$br" >/dev/null 2>&1 || return 1
  arm_push_only "$arm" "$wt"
}

arm_rebase() { # arm wt branch base
  local arm="$1" wt="$2" br="$3" base="$4"
  git -C "$wt" checkout -q "$br" >/dev/null 2>&1 || return 1
  git -C "$wt" rebase -q "$base" >/dev/null 2>&1 || return 1
  arm_force_push "$arm" "$wt" "$br"
}

arm_force_push() {  # arm wt ref
  local arm="$1" wt="$2" ref="${3:-HEAD}"
  if [[ "$arm" == "safehub" ]]; then ( cd "$wt" && "$SIT" push --force >/dev/null 2>&1 )
  elif e13_is_sgit "$arm"; then
    "$SGIT" push "$wt" "$(e13_sgit_ct "$wt")" --variant "$(e13_sgit_variant "$arm")" >/dev/null 2>&1
  else git -C "$wt" push -q --force origin "$ref" >/dev/null 2>&1; fi
}

arm_rotate() {      # wt (safehub only)
  ( cd "$1" && "$SH" repo rotate "$SH_USER/$(basename "$1")" >/dev/null 2>&1 )
}
arm_consolidate() { # wt (safehub only)
  ( cd "$1" && "$SH" repo consolidate "$SH_USER/$(basename "$1")" >/dev/null 2>&1 )
}

arm_push_only() {
  local arm="$1" wt="$2"
  if [[ "$arm" == "safehub" ]]; then ( cd "$wt" && "$SIT" push >/dev/null 2>&1 )
  elif e13_is_sgit "$arm"; then
    "$SGIT" push "$wt" "$(e13_sgit_ct "$wt")" --variant "$(e13_sgit_variant "$arm")" >/dev/null 2>&1
  else git -C "$wt" push -q origin HEAD >/dev/null 2>&1; fi
}
arm_update() {
  local arm="$1" wt="$2"
  # Every arm commits the working tree here, the sgit arms included. Sweep 1
  # skips their plaintext commit because there the measured operation is a push
  # and the commit would be charged twice. This sweep measures merge and rebase,
  # which are operations *on* that tree: without commits it has no branches, so
  # there is nothing to merge and `checkout -B` fails.
  git -C "$wt" add -A >/dev/null 2>&1 || return 1
  git -C "$wt" commit -qm up >/dev/null 2>&1 || return 1
  arm_push_only "$arm" "$wt"
}

# The trunk branch name. `git init` here uses main, but a repository created by
# another tool may be on master, so it is resolved rather than assumed.
e13_ops_trunk() {   # wt -> branch name
  local wt="$1"
  for b in main master; do
    git -C "$wt" rev-parse --verify -q "refs/heads/$b" >/dev/null 2>&1 && { echo "$b"; return; }
  done
  git -C "$wt" symbolic-ref --short HEAD 2>/dev/null || echo main
}

# ------------------------------------------------------------- fixtures -----

arm_setup() {  # arm tag -> E13_WT / E13_BARE
  local arm="$1" tag="$2" wt bare url
  wt="$WORK/${arm}_$tag"; bare="$WORK/${arm}_$tag.bare"
  rm -rf "$wt" "$bare"
  if [[ "$arm" == "safehub" ]]; then
    ( cd "$WORK" && "$SH" repo create "${arm}_$tag" --clone >/dev/null 2>&1 ) || return 1
    eval_git_identity "$wt"
  else
    url="$(e13_make_remote "$bare")" || return 1
    mkdir -p "$wt"; git init -q --template= --initial-branch=main "$wt"
    eval_git_identity "$wt"
    case "$arm" in
      gcrypt)   git -C "$wt" remote add origin "gcrypt::$url"
                git -C "$wt" config gcrypt.participants "$GCRYPT_KEY"
                git -C "$wt" config gcrypt.publish-participants true ;;
      gitcrypt) git -C "$wt" remote add origin "$url"
                printf '*.rs filter=git-crypt diff=git-crypt\n' > "$wt/.gitattributes"
                ( cd "$wt" && git-crypt init >/dev/null 2>&1 ) || return 1
                ( cd "$wt" && git-crypt export-key "$bare.gckey" >/dev/null 2>&1 ) || return 1 ;;
      git)      git -C "$wt" remote add origin "$url" ;;
      sgitchar|sgitline)
                "$SGIT" init "$wt" "$(e13_sgit_ct "$wt")" "$url" \
                        --variant "$(e13_sgit_variant "$arm")" >/dev/null 2>&1 || return 1 ;;
    esac
  fi
  E13_WT="$wt"; E13_BARE="$bare"
}

# Build history to `depth` heads, one delta-sized file per head. This is the
# expensive part and is shared by every operation at this point.
build_depth() {  # arm wt depth
  local arm="$1" wt="$2" depth="$3" i
  for ((i=0;i<BASE_MB*8;i++)); do gen_file "$wt/src/base/b_$i.rs" 128 $((1000+i)); done
  arm_update "$arm" "$wt" || return 1
  for ((i=1;i<=depth;i++)); do
    gen_file "$wt/src/rev/r_$i.rs" "$DELTA_KIB" $((3000+i))
    arm_update "$arm" "$wt" || return 1
  done
}

# A second clone, so pull and fetch have somewhere to pull into.
peer_clone() {  # arm wt dest
  local arm="$1" wt="$2" dest="$3"
  rm -rf "$dest" "$dest.ct"
  case "$arm" in
    safehub) ( cd "$(dirname "$dest")" && "$SIT" clone "$SH_USER/$(basename "$wt")" "$(basename "$dest")" >/dev/null 2>&1 ) ;;
    gcrypt)  git clone -q "gcrypt::$(e13_arm_url "$(dirname "$wt")/$(basename "$wt").bare")" "$dest" >/dev/null 2>&1 || return 1
             git -C "$dest" checkout -q -B main origin/main >/dev/null 2>&1 \
               || git -C "$dest" checkout -q -B master origin/master >/dev/null 2>&1 || return 1 ;;
    gitcrypt) git clone -q "$(e13_arm_url "$(dirname "$wt")/$(basename "$wt").bare")" "$dest" >/dev/null 2>&1 || return 1
             ( cd "$dest" && git-crypt unlock "$(dirname "$wt")/$(basename "$wt").bare.gckey" >/dev/null 2>&1 ) ;;
    sgitchar|sgitline)
             "$SGIT" clone "$(e13_arm_url "$(dirname "$wt")/$(basename "$wt").bare")" "$dest" "$dest.ct" \
                     --variant "$(e13_sgit_variant "$arm")" --keys "$(e13_sgit_keys "$wt")" >/dev/null 2>&1 || return 1
             # arm_pull/arm_fetch operate on the peer and resolve the key from
             # the peer's own path, so place it there. A reader is given the
             # repository key out of band; this is that hand-off.
             cp "$(e13_sgit_keys "$wt")" "$(e13_sgit_keys "$dest")" 2>/dev/null || true ;;
    *)       git clone -q "$(e13_arm_url "$(dirname "$wt")/$(basename "$wt").bare")" "$dest" >/dev/null 2>&1 ;;
  esac
}

# --------------------------------------------------------- measurement ------

for pt in $POINTS; do
  echo "==> depth $pt"
  for arm in "${ARMS[@]}"; do
    n="$(reps_for "$arm")"
    arm_setup "$arm" "d$pt" || { echo "    $arm: setup FAILED"; continue; }
    wt="$E13_WT"; bare="$E13_BARE"
    if ! build_depth "$arm" "$wt" "$pt"; then
      echo "    $arm: base build FAILED at depth $pt"; continue
    fi
    [[ "$arm" == "safehub" ]] || git -C "$bare" gc --quiet >/dev/null 2>&1 || true
    peer="$WORK/peer_${arm}_$pt"
    peer_clone "$arm" "$wt" "$peer" || echo "    $arm: peer clone failed (pull/fetch will be skipped)"

    for op in $OPS; do
      if ! e13_op_defined "$op" "$arm"; then
        ARM="$arm" OP="$op" PT="$pt" DELTA="$DELTA_KIB" N="$n" ROWS="$ROWS" \
          python3 -c '
import json, os
row = {"arm": os.environ["ARM"], "op": os.environ["OP"], "point": int(os.environ["PT"]),
       "delta_kib": int(os.environ["DELTA"]), "reps_requested": int(os.environ["N"]),
       "op_ms": None, "op_floor_ms": None, "op_corrected_ms": None, "n_op": 0,
       "measured": False, "status": "undefined-for-arm",
       "why": "the operation has no counterpart in this design; a dash, not a zero"}
open(os.environ["ROWS"], "a").write(json.dumps(row) + "\n")
print("    {:9s} {:<12} depth {:<5} --  undefined for this arm".format(
    row["arm"], row["op"], row["point"]))'
        continue
      fi

      declare -a S=() F=()
      failed=""
      case "$op" in
        pull|fetch)
          # Non-empty, not merely present: a gcrypt clone can exit 0 having
          # checked out nothing, and a directory test passes that.
          e13_clone_nonempty "$peer" || failed="no-peer"
          # Floor: the same operation with nothing to deliver.
          if [[ -z "$failed" ]]; then
            for ((k=0;k<3;k++)); do rc=0
              if [[ "$op" == pull ]]; then e13_timed arm_pull "$arm" "$peer" || rc=$?
              else e13_timed arm_fetch "$arm" "$peer" || rc=$?; fi
              e13_sample F "$rc" || true
            done
            for ((k=0;k<n;k++)); do
              # The filename and seed carry the operation. Without that, fetch
              # regenerates the file pull already published, byte for byte, so
              # there is nothing to commit and the publish step fails -- which
              # looks like a broken arm and is really a name collision.
              # Seeds must not overlap between operations: gen_file is a pure
              # function of (size, seed), so an overlapping seed reproduces a
              # blob the remote already has and the push ships nothing.
              case "$op" in pull) ofs=5000 ;; fetch) ofs=6000 ;; *) ofs=7000 ;; esac
              gen_file "$wt/src/rev/x_${op}_${pt}_$k.rs" "$DELTA_KIB" $((ofs+k))
              arm_update "$arm" "$wt" || { failed="publish"; break; }
              rc=0
              if [[ "$op" == fetch ]]; then
                fr="$peer"; e13_is_sgit "$arm" && fr="$(e13_sgit_ct "$peer")"
                before_ref="$(git -C "$fr" rev-parse --verify -q "refs/remotes/origin/$(e13_ops_trunk "$fr")" 2>/dev/null)"
              fi
              if [[ "$op" == pull ]]; then e13_timed arm_pull "$arm" "$peer" || rc=$?
              else e13_timed arm_fetch "$arm" "$peer" || rc=$?; fi
              # Postcondition: a pull must have produced the content; a fetch
              # must have advanced the remote-tracking ref.
              if [[ $rc -eq 0 && "$op" == pull ]] && ! e13_clone_matches "$wt" "$peer"; then
                failed="pull-content-mismatch"; rc=1
              fi
              # A fetch moves a ref rather than the working tree, so its
              # postcondition is that the remote-tracking ref advanced. Without
              # this, `git fetch` exiting 0 having delivered nothing is recorded
              # as a measured fetch.
              if [[ $rc -eq 0 && "$op" == fetch ]]; then
                fr="$peer"; e13_is_sgit "$arm" && fr="$(e13_sgit_ct "$peer")"
                after="$(git -C "$fr" rev-parse --verify -q "refs/remotes/origin/$(e13_ops_trunk "$fr")" 2>/dev/null)"
                if [[ -n "$before_ref" && "$after" == "$before_ref" ]]; then
                  failed="fetch-delivered-nothing"; rc=1
                fi
                before_ref="$after"
              fi
              e13_sample S "$rc" || { failed="${failed:-$op}"; break; }
            done
          fi ;;
        merge)
          # The topic branch is built LOCALLY and never published. Pushing a
          # sibling branch and then the trunk changes the ref map
          # non-monotonically, which SafeHub correctly refuses without an admin
          # co-signature -- a refusal that has nothing to do with merge cost.
          # It is also the real workflow: you do not publish a topic branch in
          # order to measure merging it.
          main_br="$(e13_ops_trunk "$wt")"
          for ((k=0;k<n;k++)); do
            br="topic-$pt-$k"
            git -C "$wt" checkout -q -B "$br" "$main_br" >/dev/null 2>&1 || { failed="branch"; break; }
            gen_file "$wt/src/rev/m_${pt}_$k.rs" "$DELTA_KIB" $((6000+k))
            git -C "$wt" add -A >/dev/null 2>&1 || { failed="stage"; break; }
            git -C "$wt" commit -qm "topic $k" >/dev/null 2>&1 || { failed="commit"; break; }
            git -C "$wt" checkout -q "$main_br" >/dev/null 2>&1 || { failed="trunk"; break; }
            # Diverge the trunk so the merge cannot fast-forward.
            gen_file "$wt/src/rev/t_${pt}_$k.rs" "$DELTA_KIB" $((6500+k))
            git -C "$wt" add -A >/dev/null 2>&1 || { failed="stage"; break; }
            git -C "$wt" commit -qm "trunk $k" >/dev/null 2>&1 || { failed="commit"; break; }
            rc=0; e13_timed arm_merge "$arm" "$wt" "$br" || rc=$?
            if [[ $rc -eq 0 ]] && ! e13_is_merge "$wt"; then failed="not-a-merge"; rc=1; fi
            e13_sample S "$rc" || { failed="${failed:-merge}"; break; }
          done ;;
        rebase)
          # Same discipline as merge: the branch and the upstream commit are
          # local, and only the rebased result is transmitted. A rebase of an
          # already-published branch is a force-push, which the forcepush
          # operation measures on its own.
          main_br="$(e13_ops_trunk "$wt")"
          for ((k=0;k<n;k++)); do
            br="rb-$pt-$k"; base=$(git -C "$wt" rev-parse "$main_br" 2>/dev/null)
            git -C "$wt" checkout -q -B "$br" "$base" >/dev/null 2>&1 || { failed="branch"; break; }
            gen_file "$wt/src/rev/rb_${pt}_$k.rs" "$DELTA_KIB" $((7000+k))
            git -C "$wt" add -A >/dev/null 2>&1 || { failed="stage"; break; }
            git -C "$wt" commit -qm "rb $k" >/dev/null 2>&1 || { failed="commit"; break; }
            old=$(git -C "$wt" rev-parse HEAD 2>/dev/null)
            git -C "$wt" checkout -q "$main_br" >/dev/null 2>&1 || { failed="trunk"; break; }
            gen_file "$wt/src/rev/up_${pt}_$k.rs" "$DELTA_KIB" $((7500+k))
            git -C "$wt" add -A >/dev/null 2>&1 || { failed="stage"; break; }
            git -C "$wt" commit -qm "up $k" >/dev/null 2>&1 || { failed="commit"; break; }
            newbase=$(git -C "$wt" rev-parse HEAD 2>/dev/null)
            # Publish the branch before rebasing it, so the push that follows
            # is a genuine non-fast-forward update of an existing remote ref on
            # every arm rather than a new-branch create on some of them.
            git -C "$wt" checkout -q "$br" >/dev/null 2>&1 || { failed="branch"; break; }
            arm_push_only "$arm" "$wt" || true
            rc=0; e13_timed arm_rebase "$arm" "$wt" "$br" "$newbase" || rc=$?
            new=$(git -C "$wt" rev-parse HEAD 2>/dev/null)
            if [[ $rc -eq 0 ]] && ! e13_is_rebase "$wt" "$old" "$new" "$newbase"; then
              failed="not-a-rebase"; rc=1
            fi
            e13_sample S "$rc" || { failed="${failed:-rebase}"; break; }
            git -C "$wt" checkout -q "$main_br" >/dev/null 2>&1 || true
          done ;;
        forcepush)
          main_br="$(e13_ops_trunk "$wt")"
          git -C "$wt" checkout -q "$main_br" >/dev/null 2>&1 || true
          # The tip must be published before it can be rewritten, or the push is
          # an ordinary one.
          arm_push_only "$arm" "$wt" || true
          for ((k=0;k<n;k++)); do
            old=$(git -C "$wt" rev-parse HEAD 2>/dev/null)
            git -C "$wt" reset -q --hard HEAD~1 >/dev/null 2>&1 || { failed="no-history-to-rewrite"; break; }
            gen_file "$wt/src/rev/fp_${pt}_$k.rs" "$DELTA_KIB" $((8000+k))
            git -C "$wt" add -A >/dev/null 2>&1 || { failed="stage"; break; }
            git -C "$wt" commit -qm "fp $k" >/dev/null 2>&1 || { failed="commit"; break; }
            new=$(git -C "$wt" rev-parse HEAD 2>/dev/null)
            if ! e13_is_non_ff "$wt" "$old" "$new"; then failed="not-non-ff"; break; fi
            rc=0; e13_timed arm_force_push "$arm" "$wt" "$main_br" || rc=$?
            # The local rewrite was asserted before the push; this asserts the
            # push landed. Without it a push that exited 0 without the remote
            # accepting a rewrite still reports a number.
            if [[ $rc -eq 0 ]]; then
              case "$arm" in
                safehub)
                  # SafeHub records what the client sent; read it by sequence.
                  e13_push_was_forced "$wt" || { failed="force-not-recorded"; rc=1; } ;;
                git|gitcrypt)
                  e13_remote_at "$bare" "$main_br" "$new" \
                    || { failed="force-not-at-remote"; rc=1; } ;;
                *)
                  # gcrypt keeps an encrypted manifest and sgit pushes a
                  # ciphertext mirror whose tip is not the plaintext tip, so
                  # neither exposes a ref map to compare against -- that opacity
                  # is the security property, not a defect. Their force-push is
                  # attested by the local non-fast-forward assertion above plus
                  # the command's exit status; sweep 1 scopes the same check the
                  # same way.
                  : ;;
              esac
            fi
            e13_sample S "$rc" || { failed="${failed:-forcepush}"; break; }
          done ;;
        rotate)
          # Warm up but record NO floor. A rotate has no zero-payload variant --
          # every call advances an epoch at full cost -- so sampling it as a
          # floor would subtract one draw of a distribution from another and
          # present the difference as cost net of overhead.
          for ((k=0;k<3;k++)); do e13_timed arm_rotate "$wt" || true; done
          for ((k=0;k<n;k++)); do rc=0; e13_timed arm_rotate "$wt" || rc=$?
            e13_sample S "$rc" || { failed="rotate"; break; }; done ;;
        consolidate)
          # Same: consolidation re-plans the whole span every call.
          for ((k=0;k<3;k++)); do e13_timed arm_consolidate "$wt" || true; done
          for ((k=0;k<n;k++)); do rc=0; e13_timed arm_consolidate "$wt" || rc=$?
            e13_sample S "$rc" || { failed="consolidate"; break; }; done ;;
      esac

      ARM="$arm" OP="$op" PT="$pt" DELTA="$DELTA_KIB" N="$n" FAILED="$failed" \
      FLOOR_KIND="$(e13_floor_kind "$op")" \
      S_JSON="$(stats_json "${S[@]:-}")" F_JSON="$(stats_json "${F[@]:-}")" \
      ROWS="$ROWS" python3 - <<'PY'
import json, os
def st(k):
    try: return json.loads(os.environ[k])
    except Exception: return {"n": 0, "status": "no-samples"}
def corrected(t, f):
    # Floor is the SAME operation with nothing to do, on the SAME tool.
    if not t.get("median") or not f.get("median"): return None
    v = t["median"] - f["median"]
    return round(v, 3) if v > 0 else None
failed = os.environ["FAILED"]; s, f = st("S_JSON"), st("F_JSON")
row = {"arm": os.environ["ARM"], "op": os.environ["OP"], "point": int(os.environ["PT"]),
       "delta_kib": int(os.environ["DELTA"]), "reps_requested": int(os.environ["N"]),
       "op_ms": s if s.get("n") else None, "op_floor_ms": f if f.get("n") else None,
       # From e13_floor_kind, so the library's own matcher accepts it. Null
       # where no floor was measured, rather than asserting one that was not.
       "floor_kind": (os.environ.get("FLOOR_KIND") or None) if f.get("n") else None,
       "op_corrected_ms": corrected(s, f), "n_op": s.get("n", 0),
       "thin_dispersion": s.get("n", 0) < 5,
       "measured": not failed, "status": "failed" if failed else "measured"}
if failed:
    row["failed_at"] = failed
    for k in ("op_ms", "op_corrected_ms"): row[k] = None
open(os.environ["ROWS"], "a").write(json.dumps(row) + "\n")
print("    {:9s} {:<12} depth {:<5} {} ms (n={}) {}".format(
    row["arm"], row["op"], row["point"], (s or {}).get("median"), row["n_op"],
    "FAILED:" + failed if failed else ""))
PY
      unset S F
    done
    # The ciphertext mirror and its sidecars are as large as the plaintext; at
    # depth 1000 leaving them behind costs ~50 MB per sgit arm per point.
    rm -rf "$peer" "$peer.ct" "$wt" "$wt.ct" "$bare"
    rm -f "$WORK"/.sgit-*.keys.json "$WORK"/.sgit-*.snapshot.json 2>/dev/null || true
  done
  ROWS="$ROWS" OUT="$OUT" MODE="ops" REPS="$REPS" GREPS="$GREPS" \
    python3 "$SCRIPT_DIR/publish_e13_ops.py" >/dev/null 2>&1 || echo "    (publish deferred)"
done
# Final publish, unsilenced: a publisher exception during the per-point passes
# prints one deferred line and leaves no artifact and no traceback.
ROWS="$ROWS" OUT="$OUT" MODE="ops" REPS="$REPS" GREPS="$GREPS" \
  python3 "$SCRIPT_DIR/publish_e13_ops.py" || echo "==> PUBLISH FAILED"
cp "$ROWS" "${OUT%.json}-rows.jsonl" 2>/dev/null || true
echo "==> done; artifact $OUT ; rows beside it"
