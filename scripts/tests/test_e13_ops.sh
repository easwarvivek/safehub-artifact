#!/usr/bin/env bash
# Guards for E13 sweep 2 (scripts/e2e_e13_ops.sh).
#
# Cases 1-4 test definedness, because that is the one thing this sweep decides
# that sweep 1 did not: whether a cell exists at all. Cases 5-10 feed each
# postcondition the case it must reject. A guard whose removal leaves its case
# passing is decoration, so every negative case here is mutation-checked in
# scripts/tests/mutate_e13_ops.sh.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
source "$ROOT/scripts/lib/eval_common.sh" >/dev/null 2>&1 || true
set +e
source "$ROOT/scripts/lib/e13_lib.sh"

# e13_op_defined lives in the harness, which runs a sweep when sourced. Extract
# just that function rather than executing the file.
eval "$(awk '/^e13_op_defined\(\) \{/,/^\}/' "$ROOT/scripts/e2e_e13_ops.sh")"

PASS=0; FAIL=0
ok()  { printf "  \033[32mok\033[0m    %s\n" "$1"; PASS=$((PASS+1)); }
bad() { printf "  \033[31mFAIL\033[0m  %s\n        %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkrepo() { git init -q "$1"; git -C "$1" config user.email t@t; git -C "$1" config user.name t; }
commit() { echo "$2" > "$1/f$2.txt"; git -C "$1" add -A >/dev/null; git -C "$1" commit -qm "c$2"; }

echo "== 1. every arm can pull, fetch, merge and rebase =="
miss=""
for arm in git gitcrypt gcrypt safehub sgitchar sgitline; do
  for op in pull fetch merge rebase; do
    e13_op_defined "$op" "$arm" || miss="$miss $arm/$op"
  done
done
[ -z "$miss" ] && ok "all four defined for all six arms" \
  || bad "undefined where it should be defined" "$miss"

echo "== 2. force-push is undefined for the sgit arms and defined elsewhere =="
if e13_op_defined forcepush sgitchar || e13_op_defined forcepush sgitline; then
  bad "force-push reported defined for an sgit arm" \
      "their ciphertext repo only appends, so the host cannot see a rewrite"
elif e13_op_defined forcepush git && e13_op_defined forcepush safehub \
     && e13_op_defined forcepush gitcrypt && e13_op_defined forcepush gcrypt; then
  ok "undefined for sgitchar/sgitline, defined for the other four"
else
  bad "force-push reported undefined for an arm that supports it" ""
fi

echo "== 3. rotate and consolidation are SafeHub only =="
wrong=""
for arm in git gitcrypt gcrypt sgitchar sgitline; do
  for op in rotate consolidate; do
    e13_op_defined "$op" "$arm" && wrong="$wrong $arm/$op"
  done
done
if [ -n "$wrong" ]; then bad "defined for an arm with no such operation" "$wrong"
elif e13_op_defined rotate safehub && e13_op_defined consolidate safehub; then
  ok "SafeHub only; git-crypt has no rekey mechanism at all"
else bad "undefined for SafeHub" ""; fi

echo "== 4. an unknown operation is refused, not silently accepted =="
if e13_op_defined nonsense git; then
  bad "an unknown operation was reported defined" "a typo would become a measured cell"
else ok "unknown operation refused"; fi

echo "== 5. a fast-forward is not counted as a merge =="
mkrepo "$TMP/m"; commit "$TMP/m" 1
git -C "$TMP/m" checkout -q -b topic; commit "$TMP/m" 2
git -C "$TMP/m" checkout -q master 2>/dev/null || git -C "$TMP/m" checkout -q main
git -C "$TMP/m" merge -q topic >/dev/null 2>&1     # fast-forward, no merge commit
if e13_is_merge "$TMP/m"; then bad "a fast-forward passed as a merge" "one parent, not two"
else ok "fast-forward refused as a merge"; fi

echo "== 6. a real merge is accepted =="
git -C "$TMP/m" checkout -q -b topic2; commit "$TMP/m" 3
git -C "$TMP/m" checkout -q master 2>/dev/null || git -C "$TMP/m" checkout -q main
commit "$TMP/m" 4
git -C "$TMP/m" merge --no-ff -q -m merge topic2 >/dev/null 2>&1
if e13_is_merge "$TMP/m"; then ok "two-parent merge accepted"
else bad "a real merge was refused" ""; fi

echo "== 7. a no-op rebase is not counted as a rebase =="
mkrepo "$TMP/r"; commit "$TMP/r" 1; base=$(git -C "$TMP/r" rev-parse HEAD)
commit "$TMP/r" 2; tip=$(git -C "$TMP/r" rev-parse HEAD)
if e13_is_rebase "$TMP/r" "$tip" "$tip" "$base"; then
  bad "an unchanged tip passed as a rebase" "nothing was rewritten"
else ok "unchanged tip refused as a rebase"; fi

echo "== 8. appending commits is not a rebase =="
commit "$TMP/r" 3; newtip=$(git -C "$TMP/r" rev-parse HEAD)
if e13_is_rebase "$TMP/r" "$tip" "$newtip" "$base"; then
  bad "an append passed as a rebase" "the old tip is still an ancestor"
else ok "append refused as a rebase"; fi

echo "== 9. a descendant tip is not non-fast-forward =="
if e13_is_non_ff "$TMP/r" "$tip" "$newtip"; then
  bad "a descendant passed as non-fast-forward" "this is the force-push guard"
else ok "descendant refused as non-fast-forward"; fi

echo "== 10. a genuine rewrite is non-fast-forward =="
git -C "$TMP/r" checkout -q -B rw "$base" >/dev/null 2>&1; commit "$TMP/r" 9
rw=$(git -C "$TMP/r" rev-parse HEAD)
if e13_is_non_ff "$TMP/r" "$newtip" "$rw"; then ok "rewrite accepted as non-fast-forward"
else bad "a genuine rewrite was refused" ""; fi

echo "== 11. a pull that delivered nothing fails its postcondition =="
mkdir -p "$TMP/src/x" "$TMP/dst_full/x" "$TMP/dst_empty"
printf 'content\n' > "$TMP/src/x/a.txt"; printf 'content\n' > "$TMP/dst_full/x/a.txt"
if e13_clone_matches "$TMP/src" "$TMP/dst_full" && ! e13_clone_matches "$TMP/src" "$TMP/dst_empty"; then
  ok "matching tree accepted, empty tree refused"
else bad "pull postcondition is wrong" "an empty pull would pass as measured"; fi

echo "== 12. a floor from another operation is refused =="
if e13_floor_matches pull "$(e13_floor_kind pull)" \
   && ! e13_floor_matches pull "$(e13_floor_kind fetch)"; then
  ok "pull accepts its own floor and refuses fetch's"
else bad "floor matching is wrong" "this is the defect the withdrawn columns had"; fi

echo
echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
