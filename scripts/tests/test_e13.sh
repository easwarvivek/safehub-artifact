#!/usr/bin/env bash
# E13 guard tests: the rules that stop the matrix publishing numbers for work
# that did not happen, or corrected values with no basis.
#
# Cases 1-8 test the guards in scripts/lib/e13_lib.sh directly, each fed the
# case it must reject. Cases 9-12 test them against real repositories and real
# tools. A sweep with broken guards is worse than no sweep: it produces
# confident numbers, so these run before any timing.
#
# Run: bash scripts/tests/test_e13.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
source "$ROOT/scripts/lib/eval_common.sh" >/dev/null 2>&1 || {
  ms_now() { python3 -c 'import time;print(int(time.time()*1000))'; }
}
set +e   # eval_common sets -e; this suite reports rather than aborting
source "$ROOT/scripts/lib/e13_lib.sh"

PASS=0; FAIL=0
ok()  { printf "  \033[32mok\033[0m    %s\n" "$1"; PASS=$((PASS+1)); }
bad() { printf "  \033[31mFAIL\033[0m  %s\n        %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkrepo() { local d="$1"; git init -q "$d"; git -C "$d" config user.email t@t; git -C "$d" config user.name t; }

echo "== 1. a failed timed command yields no sample =="
S=(); e13_timed false; e13_sample S $?
if [ "${#S[@]}" -ne 0 ]; then bad "failed command contributed a sample" "${#S[@]} samples"; else
  e13_timed true; e13_sample S $?
  [ "${#S[@]}" -eq 1 ] && ok "failure yields none, success yields one" \
    || bad "successful command yielded no sample" "${#S[@]}"
fi

echo "== 2. e13_timed restores the caller's errexit =="
( set +e; e13_timed true; case "$-" in *e*) exit 1;; esac; exit 0 ) \
  && ok "errexit stays off when the caller had it off" \
  || bad "e13_timed turned errexit on" "a helper must not change the caller's shell"

echo "== 3. a floor from the wrong operation is refused =="
if e13_floor_matches push "$(e13_floor_kind push)"; then
  if e13_floor_matches push "$(e13_floor_kind fetch)"; then
    bad "a fetch floor was accepted for push" "this is the defect the withdrawn columns had"
  else ok "push accepts its own floor and refuses fetch's"; fi
else bad "push refused its own floor" "e13_floor_kind/e13_floor_matches disagree"; fi

echo "== 4. clone with no working tree is refused =="
mkdir -p "$TMP/empty/.git"
if e13_clone_nonempty "$TMP/empty"; then
  bad "a .git-only directory counted as a clone" "this is the gcrypt case"
else
  mkdir -p "$TMP/full/.git"; echo hi > "$TMP/full/f.txt"
  e13_clone_nonempty "$TMP/full" && ok "empty tree refused, populated tree accepted" \
    || bad "a populated clone was refused" "guard is too strict"
fi

echo "== 5. a fast-forward is not counted as a merge =="
mkrepo "$TMP/m"; ( cd "$TMP/m"; echo a > a; git add .; git commit -qm a
  git checkout -q -b side; echo b > b; git add .; git commit -qm b
  git checkout -q - ; git merge -q side ) >/dev/null 2>&1
e13_is_merge "$TMP/m" HEAD \
  && bad "a fast-forward counted as a merge" "guard does not check parent count" \
  || ok "fast-forward that produced no merge commit is refused"

echo "== 6. a no-op rebase is not counted as a rebase =="
mkrepo "$TMP/r"; ( cd "$TMP/r"; echo a > a; git add .; git commit -qm a
  git checkout -q -b f; echo b > b; git add .; git commit -qm b ) >/dev/null 2>&1
BASE=$(git -C "$TMP/r" rev-parse master 2>/dev/null || git -C "$TMP/r" rev-parse main)
OLD=$(git -C "$TMP/r" rev-parse f)
( cd "$TMP/r" && git rebase -q "$BASE" ) >/dev/null 2>&1
NEW=$(git -C "$TMP/r" rev-parse f)
e13_is_rebase "$TMP/r" "$OLD" "$NEW" "$BASE" \
  && bad "a no-op rebase counted as a rebase" "guard does not require rewritten ids" \
  || ok "rebase that rewrote nothing is refused"

echo "== 7. a descendant tip is not non-fast-forward =="
mkrepo "$TMP/n"; ( cd "$TMP/n"; echo a > a; git add .; git commit -qm a ) >/dev/null 2>&1
O=$(git -C "$TMP/n" rev-parse HEAD)
( cd "$TMP/n"; echo b > b; git add .; git commit -qm b ) >/dev/null 2>&1
N=$(git -C "$TMP/n" rev-parse HEAD)
e13_is_non_ff "$TMP/n" "$O" "$N" \
  && bad "an ordinary commit counted as non-fast-forward" "guard does not test ancestry" \
  || ok "descendant tip refused as non-fast-forward"

echo "== 8. forced flag is read by sequence, not mtime =="
mkdir -p "$TMP/p/.git/safehub"
echo '{"force": false}' > "$TMP/p/.git/safehub/push-9.json"
echo '{"force": true}'  > "$TMP/p/.git/safehub/push-10.json"
touch -t 202601010000 "$TMP/p/.git/safehub/push-10.json"   # highest seq, OLDEST
touch -t 202612310000 "$TMP/p/.git/safehub/push-9.json"    # lowest seq, NEWEST
if e13_push_was_forced "$TMP/p"; then
  echo '{"force": true}'  > "$TMP/p/.git/safehub/push-9.json"
  echo '{"force": false}' > "$TMP/p/.git/safehub/push-10.json"
  touch -t 202601010000 "$TMP/p/.git/safehub/push-10.json"
  touch -t 202612310000 "$TMP/p/.git/safehub/push-9.json"
  e13_push_was_forced "$TMP/p" \
    && bad "guard reported forced when the newest sequence was not" "reads mtime" \
    || ok "forced flag follows sequence even when mtime disagrees"
else
  bad "read the wrong push metadata" "picked push-9 (newer mtime) over push-10"
fi

echo "== 9. an absent tool is reported absent, never zero =="
if e13_arm_available git && e13_arm_available safehub; then
  e13_arm_available definitely-not-a-tool \
    && bad "an unknown arm reported available" "would publish a zero" \
    || ok "known arms available, unknown arm reported absent"
else bad "git or safehub reported unavailable" "arm detection is broken"; fi

echo "== 10. remote-tip assertion catches a push that did not land =="
mkrepo "$TMP/s"; git init --bare -q "$TMP/s.bare"
( cd "$TMP/s"; git remote add origin "file://$TMP/s.bare"
  echo a > a; git add .; git commit -qm a; git push -q origin HEAD ) >/dev/null 2>&1
BR=$(git -C "$TMP/s" symbolic-ref --short HEAD)
WANT=$(git -C "$TMP/s" rev-parse HEAD)
if e13_remote_at "$TMP/s.bare" "$BR" "$WANT"; then
  ( cd "$TMP/s"; echo b > b; git add .; git commit -qm b ) >/dev/null 2>&1
  W2=$(git -C "$TMP/s" rev-parse HEAD)
  e13_remote_at "$TMP/s.bare" "$BR" "$W2" \
    && bad "remote reported at an unpushed commit" "assertion is vacuous" \
    || ok "remote tip matches after push, mismatches before"
else bad "remote tip mismatched after a successful push" "assertion too strict"; fi

echo "== 11. tree equality detects divergent content =="
mkrepo "$TMP/t1"; mkrepo "$TMP/t2"
( cd "$TMP/t1"; echo same > f; git add .; git commit -qm x ) >/dev/null 2>&1
( cd "$TMP/t2"; echo same > f; git add .; git commit -qm x ) >/dev/null 2>&1
if e13_tree_equal "$TMP/t1" "$TMP/t2"; then
  ( cd "$TMP/t2"; echo different > f; git add .; git commit -qm y ) >/dev/null 2>&1
  e13_tree_equal "$TMP/t1" "$TMP/t2" \
    && bad "divergent trees compared equal" "hash comparison is broken" \
    || ok "identical trees equal, divergent trees not"
else bad "identical trees compared unequal" "guard is broken"; fi

echo "== 12. git-crypt actually encrypts what it stores =="
# The A2 experiment rests on git-crypt encrypting whole files. If the filter is
# not engaging, its cost would look flat and the arm would be silently wrong.
if e13_arm_available gitcrypt; then
  mkrepo "$TMP/gc"; git init --bare -q "$TMP/gc.bare"
  ( cd "$TMP/gc"
    git remote add origin "file://$TMP/gc.bare"
    printf '*.rs filter=git-crypt diff=git-crypt\n' > .gitattributes
    git-crypt init >/dev/null 2>&1
    printf 'CANARY_PLAINTEXT_MARKER\n' > secret.rs
    git add -A; git commit -qm x; git push -q origin HEAD ) >/dev/null 2>&1
  if git -C "$TMP/gc.bare" grep -q CANARY_PLAINTEXT_MARKER --all 2>/dev/null; then
    bad "git-crypt stored plaintext on the remote" "filter is not engaging; A2 would be wrong"
  else
    ok "git-crypt ciphertext on the remote carries no plaintext marker"
  fi
else
  echo "  (skipped: git-crypt not installed)"
fi

echo "== 13. sgit arms resolve to the right variant, repo and availability =="
if [ "$(e13_sgit_variant sgitchar)" = char ] && [ "$(e13_sgit_variant sgitline)" = line ] \
   && e13_is_sgit sgitchar && e13_is_sgit sgitline \
   && ! e13_is_sgit git && ! e13_is_sgit safehub \
   && [ "$(e13_pushing_repo sgitchar /w/r)" = /w/r.ct ] \
   && [ "$(e13_pushing_repo git /w/r)" = /w/r ]; then
  ok "variant, arm predicate and pushing repository all agree"
else
  bad "sgit arm resolution is wrong" "an sgit push would be timed against the plaintext repo"
fi
if ( SGIT=/nonexistent/sgit; e13_arm_available sgitchar ); then
  bad "sgitchar reported available with no binary" "the arm would silently measure nothing"
else
  ok "an sgit arm with no binary is reported absent, never zero"
fi

echo "== 14. thin-pack bytes measure the delta, not the repository =="
mkrepo "$TMP/tp"; git init --bare -q "$TMP/tp.bare"
python3 -c 'import sys;open(sys.argv[1],"w").write("".join("line %d\n"%i for i in range(20000)))' "$TMP/tp/f.txt"
git -C "$TMP/tp" add -A >/dev/null; git -C "$TMP/tp" commit -qm one >/dev/null
git -C "$TMP/tp" push -q "file://$TMP/tp.bare" HEAD:main >/dev/null 2>&1
HAVE="$(git -C "$TMP/tp.bare" rev-parse main 2>/dev/null)"
NOTHING="$(e13_thin_bytes "$TMP/tp" "$HAVE")"
printf 'appended\n' >> "$TMP/tp/f.txt"
git -C "$TMP/tp" add -A >/dev/null; git -C "$TMP/tp" commit -qm two >/dev/null
DELTA="$(e13_thin_bytes "$TMP/tp" "$HAVE")"
FULL="$(e13_thin_bytes "$TMP/tp" "")"
# Passing no have-oid is exactly the mistake of measuring what the remote
# already holds: it reports the whole repository. The harness therefore
# captures the remote tip BEFORE the push, not after -- measured after, the
# remote has everything and the pack is empty.
if [ "$DELTA" -gt 0 ] && [ "$FULL" -gt $((DELTA * 20)) ]; then
  ok "delta-sized against the remote tip (${DELTA}B), repo-sized without it (${FULL}B)"
else
  bad "thin pack did not separate delta from repository" "delta=$DELTA full=$FULL"
fi
if [ "$NOTHING" -le 32 ]; then
  ok "a push with nothing new measures an empty pack (${NOTHING}B)"
else
  bad "an empty push measured $NOTHING bytes" "the floor would be subtracted wrong"
fi

echo "== 15. a clone is checked on content, not merely non-empty =="
mkdir -p "$TMP/cm/src/x" "$TMP/cm/good/x" "$TMP/cm/bad/x" "$TMP/cm/empty"
printf 'content\n' > "$TMP/cm/src/x/a.txt"
printf 'content\n' > "$TMP/cm/good/x/a.txt"
printf 'DIFFERENT\n' > "$TMP/cm/bad/x/a.txt"
if e13_clone_matches "$TMP/cm/src" "$TMP/cm/good" \
   && ! e13_clone_matches "$TMP/cm/src" "$TMP/cm/bad" \
   && ! e13_clone_matches "$TMP/cm/src" "$TMP/cm/empty"; then
  ok "identical accepted, divergent and empty both refused"
else
  bad "clone content check is wrong" "a stale or partial clone would pass as measured"
fi

echo "== 16. no function reads a variable that is another function's local =="
# These scripts run under set -u, where reading an unset variable is fatal even
# inside set +e -- it kills the run rather than failing one cell. Three
# experiments died this way after fifteen minutes each when a rename left
# arm_clone reading $url, a local of arm_setup.
if python3 "$ROOT/scripts/tests/lint_unbound.py" \
     --also "$ROOT/scripts/lib/eval_common.sh" --also "$ROOT/scripts/lib/e13_lib.sh" \
     "$ROOT/scripts/e2e_e13_repo.sh" "$ROOT/scripts/e2e_e13_edit.sh" \
     "$ROOT/scripts/lib/e13_lib.sh" "$ROOT/scripts/run_e13_sweep.sh"; then
  ok "every variable read is a local in scope, a global, or from the environment"
else
  bad "a variable is read out of scope" "under set -u this aborts the sweep, not the cell"
fi

echo
echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
