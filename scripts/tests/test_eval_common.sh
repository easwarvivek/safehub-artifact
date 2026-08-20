#!/usr/bin/env bash
# Correctness tests for scripts/lib/eval_common.sh.
#
# Each case is a regression test for a defect that produced published numbers,
# or for the class that produced them: a helper returns something plausible
# instead of failing, and the result is indistinguishable from a measurement.
#
# Run: bash scripts/tests/test_eval_common.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0; FAIL=0
ok()  { printf "  ok   %s\n" "$1"; PASS=$((PASS+1)); }
bad() { printf "  FAIL %s\n     %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }

# eval_common.sh sets -e and mutates PATH/CARGO_TARGET_DIR; source it in a
# subshell-friendly way and turn errexit back off so a failing assertion does
# not abort the suite.
# shellcheck disable=SC1091
source "$HERE/../lib/eval_common.sh" >/dev/null 2>&1
set +e

echo "== time_cmd_ms =="
T=$(time_cmd_ms true); RC=$?
[[ "$RC" -eq 0 && "$T" =~ ^[0-9]+$ ]] && ok "returns elapsed ms and status 0 on success" \
  || bad "success path" "rc=$RC out=$T"

T=$(time_cmd_ms false); RC=$?
[[ "$RC" -ne 0 ]] && ok "propagates non-zero status of a failed command" \
  || bad "failure status swallowed" "a failed op would be timed as if it ran (rc=$RC)"

[[ "$T" =~ ^[0-9]+$ ]] && ok "still emits a number on failure (callers MUST check status)" \
  || bad "no timing on failure" "out=$T"

echo "== dir_bytes =="
TMPD=$(mktemp -d)
head -c 4096 /dev/zero > "$TMPD/a.bin"
B=$(dir_bytes "$TMPD")
[[ "$B" -eq 4096 ]] && ok "counts bytes of a known directory" || bad "dir_bytes wrong" "got $B want 4096"

B=$(dir_bytes "$TMPD/definitely-not-here")
[[ "$B" -eq 0 ]] && ok "missing path yields 0 (callers must not treat 0 as measured)" \
  || bad "missing path" "got $B"
rm -rf "$TMPD"

echo "== stats_json =="
S=$(stats_json 1 2 3 4 5)
echo "$S" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["n"]==5, d
assert d["median"]==3, d
assert d["min"]==1 and d["max"]==5, d
' 2>/dev/null && ok "median/min/max over a known sample" || bad "stats_json values" "$S"

S=$(stats_json)
echo "$S" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d.get("n")==0, d
assert d.get("median") is None or d.get("status")=="no-samples", d
' 2>/dev/null && ok "empty sample is flagged, not reported as 0" || bad "empty sample" "$S"

S=$(stats_json 42)
echo "$S" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["n"]==1, d
assert "single" in str(d.get("dispersion","")).lower(), d
' 2>/dev/null && ok "single shot is labelled as a single shot" || bad "single-shot labelling" "$S"

echo "== tree_sig (requires a working shasum) =="
if command -v shasum >/dev/null 2>&1; then
  H=$(printf 'x' | shasum -a 256 | cut -d' ' -f1)
  [[ ${#H} -eq 64 ]] && ok "shasum present and produces a 64-hex digest" \
    || bad "shasum output malformed" "len=${#H}"
else
  bad "shasum missing" "parity_sweep tree_sig/content_sig silently produce EMPTY signatures, so every postcondition comparing them passes vacuously"
fi

echo "== eval_machine_json =="
M=$(eval_machine_json 2>/dev/null)
echo "$M" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d.get("arch"), "arch empty"
populated=[k for k,v in d.items() if v not in (None,"","unspecified")]
assert len(populated)>3, f"machine block nearly empty: {d}"
' 2>/dev/null && ok "machine block is populated on this platform" \
  || bad "machine provenance nearly all null" "upstream probes macOS sysctl only; on Linux every field is null: $M"

echo
echo "== $PASS passed, $FAIL failed =="
[[ "$FAIL" -eq 0 ]]
