#!/usr/bin/env bash
# Evaluation-harness correctness suite.
#
# Run this before any sweep whose numbers will be published. It is deliberately
# fast and hermetic: no server, no network, no sweep.
#
#   preflight.sh          environment is WORKING, not merely installed
#   test_eval_publish.py  units, dispersion, ratio guards in the Python lib
#   test_eval_common.sh   timing, sizing, stats helpers in the shell lib
#   audit_harness.py      static scan for silent-failure patterns
#   test_crypto_endtoend  push encrypts, pull decrypts, server compare-and-swaps
#   test_safehub_ops      tamper/rollback/authz/history-window/consolidation
#   test_e13              floors, postconditions and arm detection for the matrix
#
# Exit non-zero if anything fails.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RC=0
run() {
  local name="$1"; shift
  printf "\n\033[1m=== %s ===\033[0m\n" "$name"
  "$@"
  local rc=$?
  [ $rc -ne 0 ] && RC=1
  return 0
}
run "preflight (environment)"        bash    "$HERE/preflight.sh"
run "eval_publish.py (unit)"         python3 "$HERE/test_eval_publish.py"
run "eval_common.sh (unit)"          bash    "$HERE/test_eval_common.sh"
run "harness audit (static)"         python3 "$HERE/audit_harness.py"
run "crypto end-to-end (live server)" bash   "$HERE/test_crypto_endtoend.sh"
run "safehub operations (adversarial)" bash  "$HERE/test_safehub_ops.sh"
run "E13 matrix guards"                bash  "$HERE/test_e13.sh"
printf "\n\033[1m=== suite: %s ===\033[0m\n" "$([ $RC -eq 0 ] && echo PASS || echo FAIL)"
exit $RC
