#!/usr/bin/env bash
# Postcondition guards for the E12 history-operations arm.
#
# These live here rather than inside the harness so the test suite exercises
# the same code the sweep does. A guard that is only reimplemented in a test
# proves nothing about the harness.
#
# The guards exist because of one recurring defect: an operation that returns
# zero having done nothing still yields a plausible number. `git merge --no-ff`
# can fast-forward, `git rebase` can be a no-op, and `commit --amend` can
# produce a descendant -- each would publish a timing for work that never
# happened. Every operation therefore has to prove, from the resulting DAG,
# that it is the operation it claims to be.

# A merge commit has exactly two parents. `rev-list --parents -n1` prints
# "<commit> <parent>..." so a real merge is three fields.
ho_is_merge_commit() {
  local repo="$1" rev="${2:-HEAD}" fields
  fields=$(git -C "$repo" rev-list --parents -n1 "$rev" 2>/dev/null | wc -w | tr -d ' ')
  [[ "$fields" == "3" ]]
}

# A rebase rewrote history iff the tip changed, the new tip descends from the
# intended base, and the old tip is NOT an ancestor of the new one. The last
# clause is what separates a rebase from a fast-forward: appending commits
# would also change the tip and keep the base, but leaves the old tip reachable.
ho_is_rebase() {
  local repo="$1" old="$2" new="$3" base="$4"
  [[ -n "$old" && -n "$new" && -n "$base" ]] || return 1
  [[ "$old" != "$new" ]] || return 1
  git -C "$repo" merge-base --is-ancestor "$base" "$new" 2>/dev/null || return 1
  ! git -C "$repo" merge-base --is-ancestor "$old" "$new" 2>/dev/null
}

# A non-fast-forward update replaces a tip with a commit the old tip does not
# reach. If the old tip is still an ancestor the update is an ordinary
# fast-forward and the co-signature gate never fires.
ho_is_non_ff() {
  local repo="$1" old="$2" new="$3"
  [[ -n "$old" && -n "$new" ]] || return 1
  [[ "$old" != "$new" ]] || return 1
  ! git -C "$repo" merge-base --is-ancestor "$old" "$new" 2>/dev/null
}

# SafeHub records per-push metadata; the force flag there is what the client
# actually sent, as opposed to what the command line asked for.
ho_push_was_forced() {
  local repo="$1" meta
  # Select by head sequence, not mtime. push-<seq>.json is written per push and
  # seq increases monotonically, whereas several pushes land inside one mtime
  # second and `ls -t` then orders them arbitrarily -- which reads the wrong
  # file and reports an honest force push as unforced.
  meta=$(ls "$repo/.git/safehub"/push-*.json 2>/dev/null \
         | sed 's/.*\/push-\([0-9]*\)\.json/\1 &/' \
         | sort -n -k1,1 | tail -1 | cut -d' ' -f2-)
  [[ -n "$meta" ]] || return 1
  python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("force") else 1)' \
    "$meta" 2>/dev/null
}

# Time a command and keep its status. HO_MS is set either way; the caller must
# consult the return value before using it. Publishing HO_MS for a command that
# returned nonzero is the defect this exists to prevent.
ho_timed() {
  local t0 t1 rc had_e=0
  # Restore the caller's errexit rather than forcing it on: a helper that turns
  # on -e for a script that did not ask for it makes the next failing guard
  # kill the run instead of reporting.
  case "$-" in *e*) had_e=1 ;; esac
  t0=$(ms_now)
  set +e
  "$@" >/dev/null 2>&1
  rc=$?
  t1=$(ms_now)
  if [[ "$had_e" == "1" ]]; then set -e; fi
  HO_MS=$((t1 - t0))
  return $rc
}

# Accumulate a sample only when its command succeeded. Usage:
#   ho_sample ARRNAME <rc>   # appends $HO_MS to ARRNAME iff rc == 0
# Returns the rc it was given, so callers propagate failure rather than
# silently dropping a rep.
ho_sample() {
  local arr="$1" rc="$2"
  if [[ "$rc" -eq 0 ]]; then
    eval "$arr+=($HO_MS)"
  fi
  return "$rc"
}

# Refs must be gone from both remotes after cleanup. A leaked scratch branch
# would make later checkpoints measure a different repository than earlier ones,
# which is invisible in the numbers and fatal to the comparison.
ho_ref_absent_git() {
  local bare="$1" ref="$2"
  ! git -C "$bare" show-ref --verify --quiet "refs/heads/$ref" 2>/dev/null
}
