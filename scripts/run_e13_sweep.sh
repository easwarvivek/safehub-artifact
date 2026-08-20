#!/usr/bin/env bash
# Full E13 sweep: every experiment, every arm, one point at a time.
#
# Run this ON the benchmark host, detached. It exists so a sweep is launched
# the same way twice, and so the things that went wrong before cannot recur
# silently:
#
#   * state lives on the ROOT DISK. /tmp on these hosts is a tmpfs; a 300 MB
#     base repository across six arms with clones would sit in RAM, change
#     what is being measured, and can take the host down.
#   * artifacts and rows are written OUTSIDE the state root, because the state
#     root is deleted between experiments -- an earlier sweep published nothing
#     for four completed experiments because its rows were cleaned up with it.
#   * each experiment publishes per point, so an interrupted sweep keeps
#     everything it had already measured.
#   * binaries are hashed into the log, so which build produced a number is
#     recoverable afterwards rather than inferred.
set -uo pipefail
. "$HOME/.cargo/env" 2>/dev/null || true
TREE="${SAFEHUB_TREE:-$HOME/safehub}"
cd "$TREE"

# A dated directory per sweep. Earlier sweeps' artifacts stay exactly where
# they are: some of them predate measurement fixes and must not be silently
# mixed with, or overwritten by, results that are not comparable to them.
ART="${SAFEHUB_E13_ART:-$HOME/e13-artifacts/sweep-$(date -u +%Y%m%dT%H%M%SZ)}"
STATE="${SAFEHUB_E13_STATE:-$HOME/e13-run}"
[ -e "$ART" ] && { echo "refusing to reuse an existing artifact directory: $ART"; exit 1; }
mkdir -p "$ART" "$STATE"
LOG="$ART/sweep.log"

REPS="${SAFEHUB_E13_REPS:-5}"
GREPS="${SAFEHUB_E13_GCRYPT_REPS:-3}"

say() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$LOG"; }

case "$(df -P "$STATE" | awk 'NR==2{print $1}')" in
  tmpfs|*tmpfs*) say "FATAL: state root $STATE is on tmpfs"; exit 1 ;;
esac

say "=== sweep start on $(hostname) ==="
# Hashes are logged so a stale binary on one host is detectable, not so hosts
# can be compared: a release build is not bit-reproducible across machines --
# codegen unit partitioning differs -- so two hosts on identical source produce
# differing hashes. Source parity is what establishes that two hosts ran the
# same thing; the hash establishes that a host did not run something older.
say "binaries:"
for b in safehub-server shub sit sgit; do
  p="$TREE/code/target/release/$b"
  [ -x "$p" ] || { say "FATAL: $b missing -- build before sweeping"; exit 1; }
  say "  $(printf '%-16s' "$b") $(md5sum "$p" | cut -d' ' -f1)  $(date -r "$p" '+%b %d %H:%M')"
done

# SAFEHUB_E13_ONLY selects which experiments this host runs, so the sweep can
# be split across identical hosts. Each experiment still runs ALL arms together
# on one host, so arms are always compared on the same machine at the same
# moment; only comparisons BETWEEN experiments would cross hosts, and the
# figures do not make those.
ONLY="${SAFEHUB_E13_ONLY:-}"

run() {  # label script mode points [extra env...]
  local label="$1" script="$2" mode="$3" points="$4"; shift 4
  if [ -n "$ONLY" ] && ! printf '%s\n' $ONLY | grep -qx "$label"; then
    say "--- $label skipped (not in SAFEHUB_E13_ONLY)"
    return 0
  fi
  local root="$STATE/$label" t0 t1 rc
  rm -rf "$root"; mkdir -p "$root"
  say "--- $label  mode=$mode points=[$points]"
  t0=$(date +%s)
  env "$@" \
    SAFEHUB_E13_MODE="$mode" SAFEHUB_E13_POINTS="$points" \
    SAFEHUB_E13_REPS="$REPS" SAFEHUB_E13_GCRYPT_REPS="$GREPS" \
    SAFEHUB_E13_ROOT="$root" \
    SAFEHUB_E13_OUT="$ART/e13-$label.json" \
    SAFEHUB_E13_ROWS="$ART/$label-rows.jsonl" \
    bash "scripts/$script" >>"$ART/$label.out" 2>&1
  rc=$?
  t1=$(date +%s)
  say "--- $label rc=$rc elapsed=$(( (t1-t0)/60 ))m"
  grep -E "^    " "$ART/$label.out" | tail -40 >>"$LOG"
  # Free the state before the next experiment; rows and artifacts are elsewhere.
  rm -rf "$root"
}

# Point lists keep both endpoints of every axis, so each shape stays pinned,
# and drop interior points. Interior points can be added later without
# re-running anything else: each experiment publishes per point and retains
# raw samples per cell, so a later run infills rather than replaces.
#
# B stops at 200 MB. The 300 MB point is the clearest view of gcrypt's O(R) and
# is worth adding later, but it alone costs about as much as the rest of B.
run A1-delta   e2e_e13_edit.sh delta     "${P_A1:-5 50 500 1024 2048 3072}"  SAFEHUB_E13_BASE_MB=16
run A2-filesz  e2e_e13_edit.sh filesz    "${P_A2:-10 100 1024 4096 8192}"    SAFEHUB_E13_BASE_MB=16 SAFEHUB_E13_EDIT_KIB=1
run A3-nfiles  e2e_e13_edit.sh nfiles    "${P_A3:-1 2 5 10 20 50}"            SAFEHUB_E13_BASE_MB=16 SAFEHUB_E13_EDIT_KIB=1 SAFEHUB_E13_NFILE_KIB=100
run B-size     e2e_e13_repo.sh size      "${P_B:-5 25 100 200}"
run C-depth    e2e_e13_repo.sh depth     "${P_C:-10 100 316 1000}"
run D-updates  e2e_e13_repo.sh updates   "${P_D:-10 40 80 100}"
run E-revs     e2e_e13_repo.sh revisions "${P_E:-1 25 50 100 200}"           SAFEHUB_E13_REV_FILE_KIB=256

say "=== sweep complete ==="
say "artifacts:"; ls -la "$ART"/*.json 2>/dev/null | tee -a "$LOG"
