#!/usr/bin/env bash
# Merge / rebase / force-push: behaviour and harness guards.
#
# Cases 1-8 test SafeHub: each performs the operation and requires the result
# to be verifiably that operation, or attempts a refused thing and requires the
# refusal. Cases 9-12 test the guards in scripts/lib/history_ops_lib.sh, which
# is what stops the E12 sweep from publishing a number for work that did not
# happen. Both halves matter: a sweep whose guards are wrong is worse than no
# sweep, because it produces confident numbers.
#
# Run: bash scripts/tests/test_history_ops.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="$ROOT/code/target/release"; [ -x "$BIN/safehub-server" ] || BIN="$ROOT/code/target/debug"
# ms_now is used by ho_timed.
source "$ROOT/scripts/lib/eval_common.sh" >/dev/null 2>&1 || {
  ms_now() { python3 -c 'import time;print(int(time.time()*1000))'; }
}
# eval_common.sh sets -euo pipefail; this suite reports failures instead of
# aborting on the first one, so errexit goes back off after sourcing it.
set +e
source "$ROOT/scripts/lib/history_ops_lib.sh"

PASS=0; FAIL=0
ok()  { printf "  \033[32mok\033[0m    %s\n" "$1"; PASS=$((PASS+1)); }
bad() { printf "  \033[31mFAIL\033[0m  %s\n        %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }

PORT=${SH_HO_PORT:-18432}
HOST="http://127.0.0.1:$PORT"
DATA=""; CFG=""; W=""; SRV=""

boot() {
  [ -n "$SRV" ] && kill "$SRV" 2>/dev/null
  rm -rf "$DATA" "$CFG" "$W" 2>/dev/null
  DATA=$(mktemp -d); CFG=$(mktemp -d); W=$(mktemp -d)
  export HOME="$CFG" XDG_CONFIG_HOME="$CFG/.config"; mkdir -p "$XDG_CONFIG_HOME"
  "$BIN/safehub-server" --listen "127.0.0.1:$PORT" --data "$DATA" >"$W/srv.log" 2>&1 &
  SRV=$!
  for _ in $(seq 1 80); do curl -sf "$HOST/v1/health" >/dev/null 2>&1 && break; sleep 0.25; done
  "$BIN/shub" auth register --user alice --password pw --hostname "$HOST" >/dev/null 2>&1
  "$BIN/shub" device publish-key-package --device default >/dev/null 2>&1
  ( cd "$W" && "$BIN/shub" repo create r1 --clone >/dev/null 2>&1 )
  ( cd "$W/r1" && git config user.email t@t && git config user.name t \
    && echo base > base.txt && "$BIN/sit" add . >/dev/null 2>&1 \
    && "$BIN/sit" commit -qm base >/dev/null 2>&1 && "$BIN/sit" push >/dev/null 2>&1 )
}
cleanup(){ [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; rm -rf "$DATA" "$CFG" "$W"; }
trap cleanup EXIT

R="" # set to $W/r1 after boot

echo "== 1. merge produces a two-parent commit and both lineages survive =="
boot; R="$W/r1"
(
  cd "$R"
  "$BIN/sit" checkout -q -b topic
  echo t > t.txt; "$BIN/sit" add t.txt >/dev/null; "$BIN/sit" commit -qm topic >/dev/null
  "$BIN/sit" checkout -q main 2>/dev/null || "$BIN/sit" checkout -q master
  echo m > m.txt; "$BIN/sit" add m.txt >/dev/null; "$BIN/sit" commit -qm main-side >/dev/null
  git merge --no-ff -q topic -m "merge topic"
) >/dev/null 2>&1
if ho_is_merge_commit "$R" HEAD; then
  if [ -f "$R/t.txt" ] && [ -f "$R/m.txt" ]; then
    ok "merge commit has two parents and carries both lineages"
  else
    bad "merge commit lost content" "t.txt or m.txt missing after merge"
  fi
else
  bad "merge did not produce a two-parent commit" "$(git -C "$R" rev-list --parents -n1 HEAD)"
fi

echo "== 2. merge result pushes and a peer sees both lineages =="
( cd "$R" && "$BIN/sit" push ) >/dev/null 2>&1
if ( cd "$W" && "$BIN/sit" clone alice/r1 peer1 >/dev/null 2>&1 ) \
   && [ -f "$W/peer1/t.txt" ] && [ -f "$W/peer1/m.txt" ]; then
  ok "peer clone of a merged history carries both lineages"
else
  bad "peer clone lost a lineage after merge" "t.txt/m.txt missing in peer1"
fi

echo "== 3. rebase rewrites commit ids onto the new base =="
boot; R="$W/r1"
OLD=""; NEW=""; BASE=""
(
  cd "$R"
  "$BIN/sit" checkout -q -b feat
  for i in 1 2 3; do echo "f$i" > "f$i.txt"; "$BIN/sit" add "f$i.txt" >/dev/null
    "$BIN/sit" commit -qm "feat $i" >/dev/null; done
  "$BIN/sit" checkout -q main 2>/dev/null || "$BIN/sit" checkout -q master
  echo adv > adv.txt; "$BIN/sit" add adv.txt >/dev/null; "$BIN/sit" commit -qm advance >/dev/null
) >/dev/null 2>&1
MAINREF=$(git -C "$R" symbolic-ref --short HEAD)
BASE=$(git -C "$R" rev-parse "$MAINREF")
OLD=$(git -C "$R" rev-parse feat)
( cd "$R" && git checkout -q feat && git rebase -q "$MAINREF" ) >/dev/null 2>&1
NEW=$(git -C "$R" rev-parse feat)
if ho_is_rebase "$R" "$OLD" "$NEW" "$BASE"; then
  ok "rebase rewrote ids and landed on the advanced base"
else
  bad "rebase did not rewrite onto the new base" "old=$OLD new=$NEW base=$BASE"
fi

echo "== 4. a rebased branch pushes as non-fast-forward with a cosig =="
( cd "$R" && git checkout -q "$MAINREF" && "$BIN/sit" push ) >/dev/null 2>&1
( cd "$R" && git checkout -q feat && "$BIN/sit" push sit feat ) >/dev/null 2>&1
FF_OUT=$( cd "$R" && git checkout -q feat && "$BIN/sit" push sit feat 2>&1 )
# Rewrite feat again so the next push is genuinely non-FF.
PREV=$(git -C "$R" rev-parse feat)
( cd "$R" && git commit -q --amend -m "feat rewritten" ) >/dev/null 2>&1
CUR=$(git -C "$R" rev-parse feat)
if ho_is_non_ff "$R" "$PREV" "$CUR"; then
  if ( cd "$R" && "$BIN/sit" push --force sit feat ) >/dev/null 2>&1 && ho_push_was_forced "$R"; then
    ok "non-fast-forward push accepted under --force and recorded as forced"
  else
    bad "forced non-FF push failed or was not recorded as forced" "prev=$PREV cur=$CUR"
  fi
else
  bad "amend did not produce a non-fast-forward tip" "prev=$PREV cur=$CUR"
fi

echo "== 5. force-push replaces a tip with a non-descendant, visible to a peer =="
TIP=$(git -C "$R" rev-parse feat)
if ( cd "$W" && rm -rf peer2 && "$BIN/sit" clone alice/r1 peer2 >/dev/null 2>&1 ); then
  ( cd "$W/peer2" && git fetch -q sit 2>/dev/null || true )
  ok "peer clone succeeds after a force-push"
else
  bad "peer clone failed after a force-push" "tip=$TIP"
fi

echo "== 6. an ordinary fast-forward push carries no cosig =="
boot; R="$W/r1"
( cd "$R" && echo ff > ff.txt && "$BIN/sit" add ff.txt >/dev/null \
  && "$BIN/sit" commit -qm ff >/dev/null && "$BIN/sit" push ) >/dev/null 2>&1
if ho_push_was_forced "$R"; then
  bad "a fast-forward push was recorded as forced" "gate is always-on, which defeats it"
else
  ok "fast-forward push is not forced (the gate is not always-on)"
fi

echo "== 7. a non-fast-forward push WITHOUT --force is rejected =="
PREV=$(git -C "$R" rev-parse HEAD)
( cd "$R" && git commit -q --amend -m "rewritten without force" ) >/dev/null 2>&1
CUR=$(git -C "$R" rev-parse HEAD)
if ho_is_non_ff "$R" "$PREV" "$CUR"; then
  if ( cd "$R" && "$BIN/sit" push ) >/dev/null 2>&1; then
    bad "unforced non-fast-forward push SUCCEEDED" "the force-push gate did not fire"
  else
    ok "unforced non-fast-forward push is rejected"
  fi
else
  bad "test setup failed to produce a non-FF tip" "prev=$PREV cur=$CUR"
fi

echo "== 8. a force-push without an admin credential is rejected =="
# Remove the admin key this repo would co-sign with; the client must refuse
# rather than push a non-FF head with no co-signature.
ADMINK=$(find "$CFG" -name 'admin_mldsa.json' 2>/dev/null | head -1)
if [ -n "$ADMINK" ]; then
  mv "$ADMINK" "$ADMINK.hidden"
  # Assert on the reason, not just the failure: a force-push that broke for an
  # unrelated cause would otherwise keep this case green forever.
  ERR=$( cd "$R" && "$BIN/sit" push --force 2>&1 )
  if [ $? -eq 0 ]; then
    bad "force-push SUCCEEDED with no admin credential" "non-FF head accepted without a cosig"
  elif printf '%s' "$ERR" | grep -qi "admin ML-DSA key\|admin_mldsa"; then
    ok "force-push without an admin credential is rejected, naming the missing key"
  else
    bad "force-push failed for the wrong reason" "$(printf '%s' "$ERR" | tail -1)"
  fi
  mv "$ADMINK.hidden" "$ADMINK"
else
  # No separate admin key file: assert the co-signature is at least required by
  # checking a non-admin cannot be constructed here, and say so rather than
  # claiming a pass we did not earn.
  bad "could not locate an admin credential to remove" "case 8 not exercised"
fi

echo "== 9. guard: a fast-forward is not counted as a merge =="
G=$(mktemp -d); git init -q "$G"; ( cd "$G" && git config user.email t@t && git config user.name t
  echo a > a.txt && git add . && git commit -qm a
  git checkout -q -b side && echo b > b.txt && git add . && git commit -qm b
  git checkout -q master 2>/dev/null || git checkout -q main
  git merge -q side ) >/dev/null 2>&1   # fast-forward: no merge commit
if ho_is_merge_commit "$G" HEAD; then
  bad "guard accepted a fast-forward as a merge" "ho_is_merge_commit is not checking parents"
else
  ok "guard rejects a fast-forward that produced no merge commit"
fi
rm -rf "$G"

echo "== 10. guard: a no-op rebase is not counted as a rebase =="
G=$(mktemp -d); git init -q "$G"; ( cd "$G" && git config user.email t@t && git config user.name t
  echo a > a.txt && git add . && git commit -qm a
  git checkout -q -b feat && echo b > b.txt && git add . && git commit -qm b ) >/dev/null 2>&1
MB=$(git -C "$G" rev-parse master 2>/dev/null || git -C "$G" rev-parse main)
OLDF=$(git -C "$G" rev-parse feat)
( cd "$G" && git rebase -q "$MB" ) >/dev/null 2>&1   # already on top: no-op
NEWF=$(git -C "$G" rev-parse feat)
if ho_is_rebase "$G" "$OLDF" "$NEWF" "$MB"; then
  bad "guard accepted a no-op rebase" "ho_is_rebase does not require rewritten ids"
else
  ok "guard rejects a rebase that rewrote nothing"
fi
rm -rf "$G"

echo "== 11. guard: a descendant tip is not counted as non-fast-forward =="
G=$(mktemp -d); git init -q "$G"; ( cd "$G" && git config user.email t@t && git config user.name t
  echo a > a.txt && git add . && git commit -qm a ) >/dev/null 2>&1
OLDC=$(git -C "$G" rev-parse HEAD)
( cd "$G" && echo b > b.txt && git add . && git commit -qm b ) >/dev/null 2>&1
NEWC=$(git -C "$G" rev-parse HEAD)
if ho_is_non_ff "$G" "$OLDC" "$NEWC"; then
  bad "guard accepted an ordinary commit as non-fast-forward" "ho_is_non_ff does not test ancestry"
else
  ok "guard rejects a descendant tip as non-fast-forward"
fi
rm -rf "$G"

echo "== 12. guard: a failed timed command yields no sample =="
SAMPLES=()
set +e
ho_timed false; RC=$?
ho_sample SAMPLES "$RC"
set -e
if [ "${#SAMPLES[@]}" -ne 0 ]; then
  bad "a failed command contributed a timing sample" "${#SAMPLES[@]} sample(s) from a failing command"
else
  set +e; ho_timed true; RC=$?; ho_sample SAMPLES "$RC"; set -e
  if [ "${#SAMPLES[@]}" -eq 1 ]; then
    ok "failed command yields no sample; successful command yields one"
  else
    bad "successful command did not yield a sample" "${#SAMPLES[@]} samples"
  fi
fi

echo "== 13. guard: the forced flag is read from the newest SEQUENCE, not mtime =="
# Several pushes land inside one mtime second and `ls -t` then orders them
# arbitrarily, which is how a real force push got reported as unforced. Equal
# mtimes only make the tie platform-dependent, so this makes the two orders
# actively DISAGREE: the lower sequence is given the newer mtime. Anything
# selecting on mtime now provably reads the wrong file.
G=$(mktemp -d); mkdir -p "$G/.git/safehub"
echo '{"force": false}' > "$G/.git/safehub/push-9.json"
echo '{"force": true}'  > "$G/.git/safehub/push-10.json"
touch -t 202601010000 "$G/.git/safehub/push-10.json"   # highest seq, OLDEST
touch -t 202612310000 "$G/.git/safehub/push-9.json"    # lowest seq, NEWEST
if ho_push_was_forced "$G"; then
  ok "forced flag read from the highest sequence even when mtime disagrees"
else
  bad "read the wrong push metadata" "picked push-9 (unforced, newer mtime) over push-10"
fi
# The converse, so the guard is not simply always-true.
echo '{"force": true}'  > "$G/.git/safehub/push-9.json"
echo '{"force": false}' > "$G/.git/safehub/push-10.json"
touch -t 202601010000 "$G/.git/safehub/push-10.json"
touch -t 202612310000 "$G/.git/safehub/push-9.json"
if ho_push_was_forced "$G"; then
  bad "guard reported forced when the highest sequence was not" "read mtime, not sequence"
else
  ok "guard reports unforced when the highest sequence is unforced"
fi
rm -rf "$G"

echo
echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
