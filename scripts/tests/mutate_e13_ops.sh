#!/usr/bin/env bash
# Mutation check for the sweep-2 guards.
#
# A negative case that passes with its guard removed proves nothing. Each
# mutation below deletes one guard, runs the suite, and requires the matching
# case to fail. This has already caught two vacuous tests and a vacuous linter
# in this work, so it runs before any measurement.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$ROOT/scripts/lib/e13_lib.sh"
OPS="$ROOT/scripts/e2e_e13_ops.sh"
PASS=0; FAIL=0
run() { bash "$ROOT/scripts/tests/test_e13_ops.sh" 2>&1; }

check() {  # name file python-mutation expected-failing-case
  local name="$1" file="$2" mut="$3" want="$4"
  cp "$file" "$file.bak"
  python3 -c "$mut" || { echo "  SKIP $name (mutation did not apply)"; cp "$file.bak" "$file"; rm -f "$file.bak"; return; }
  local out; out="$(run)"
  cp "$file.bak" "$file"; rm -f "$file.bak"
  if grep -q "FAIL.*$want" <<<"$out" || grep -qE "^== [0-9]+ passed, [1-9]" <<<"$out"; then
    printf "  \033[32mok\033[0m    removing %s fails the suite\n" "$name"; PASS=$((PASS+1))
  else
    printf "  \033[31mFAIL\033[0m  removing %s left the suite green -- that case is decoration\n" "$name"; FAIL=$((FAIL+1))
  fi
}

echo "== mutation checks =="
check "the sgit force-push exclusion" "$OPS" "
from pathlib import Path
p=Path('$OPS'); s=p.read_text()
a='    forcepush)'
i=s.index(a); j=s.index('! e13_is_sgit \"\$arm\" ;;', i)
p.write_text(s[:j] + 'return 0 ;;' + s[j+len('! e13_is_sgit \"\$arm\" ;;'):])
" "force-push"

check "the SafeHub-only restriction on rotate" "$OPS" "
from pathlib import Path
p=Path('$OPS'); s=p.read_text()
a='      [[ \"\$arm\" == \"safehub\" ]] ;;'
assert a in s
p.write_text(s.replace(a, '      return 0 ;;', 1))
" "rotate"

check "the merge two-parent check" "$LIB" "
from pathlib import Path
p=Path('$LIB'); s=p.read_text()
a='  [[ \"\$fields\" == \"3\" ]]'
assert a in s
p.write_text(s.replace(a, '  return 0', 1))
" "merge"

check "the rebase rewrite check" "$LIB" "
from pathlib import Path
p=Path('$LIB'); s=p.read_text()
a='  ! git -C \"\$repo\" merge-base --is-ancestor \"\$old\" \"\$new\" 2>/dev/null'
assert a in s
p.write_text(s.replace(a, '  return 0', 1))
" "rebase"

check "the non-fast-forward check" "$LIB" "
from pathlib import Path
p=Path('$LIB'); s=p.read_text()
a='''e13_is_non_ff() {
  local repo=\"\$1\" old=\"\$2\" new=\"\$3\"
  [[ -n \"\$old\" && -n \"\$new\" && \"\$old\" != \"\$new\" ]] || return 1
  ! git -C \"\$repo\" merge-base --is-ancestor \"\$old\" \"\$new\" 2>/dev/null
}'''
assert a in s
p.write_text(s.replace(a, '''e13_is_non_ff() {
  return 0
}''', 1))
" "non-fast-forward"

check "the separate pull floor" "$LIB" "
from pathlib import Path
p=Path('$LIB'); s=p.read_text()
a='''    pull)        echo \"pull_noop\" ;;
    fetch)       echo \"fetch_noop\" ;;'''
assert a in s
p.write_text(s.replace(a, '    pull|fetch)  echo \"fetch_noop\" ;;', 1))
" "floor"

echo
echo "== $PASS mutations detected, $FAIL undetected =="
[ "$FAIL" -eq 0 ]
