#!/usr/bin/env bash
# Run the whole test suite, including the paper-property checks, in both crypto
# build configurations.
#
# The property suite is the executable form of the paper's claims: if a change
# to the functionality breaks a property the UC proof depends on, this fails.
# Run it after every change to safehub-crypto, safehub-client, or
# safehub-storage, and before publishing any measurement.
#
# Both configurations matter. The default build links the development stub, and
# the property suite must still hold there for everything that is not
# MLS-specific; the `openmls` build is what the shipped binaries and the eval
# harness use, and is the only configuration whose numbers may be published.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/code"

FAIL=0
run() {
  local label="$1"
  shift
  echo
  echo "=============================================================="
  echo "== $label"
  echo "=============================================================="
  if "$@"; then
    echo "-- PASS: $label"
  else
    echo "-- FAIL: $label"
    FAIL=1
  fi
}

# Property suites first: they are the fastest signal that a security-relevant
# invariant moved.
run "paper properties (crypto, openmls/Category-5 build)" \
  cargo test --release -q -p safehub-crypto --features openmls \
  --test paper_properties

run "paper properties (crypto, default/stub build)" \
  cargo test --release -q -p safehub-crypto --test paper_properties

run "refhead acceptance path (client)" \
  cargo test --release -q -p safehub-client --test verification_path

run "read path verification (client)" \
  cargo test --release -q -p safehub-client --test read_path_verification

run "adversarial crypto scenarios" \
  cargo test --release -q -p safehub-crypto --features openmls \
  --test adversarial_scenarios

run "negative crypto" \
  cargo test --release -q -p safehub-crypto --test negative_crypto

run "head log negatives (storage)" \
  cargo test --release -q -p safehub-storage --test negative_headlog

run "crash recovery (storage)" \
  cargo test --release -q -p safehub-storage --test crash_recovery

# Then the full workspace, so nothing outside the property files regressed.
run "full workspace test suite" cargo test --release -q --workspace

echo
if ((FAIL)); then
  echo "RESULT: at least one suite failed. Do not publish measurements from"
  echo "this build, and do not treat the paper's claims as re-verified."
  exit 1
fi
echo "RESULT: all suites passed."
echo
echo "Linked crypto for the shipped CLI:"
cargo run -q -p safehub-cli --release --bin shub -- crypto report
