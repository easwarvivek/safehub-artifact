#!/usr/bin/env bash
# Guards for the SGitChar/SGitLine git add-on (code/crates/sgit-rs/src/bin/sgit.rs).
#
# The library tests in crates/sgit-rs/tests/protocol.rs check the construction.
# These check what the library cannot: that it behaves as a Git add-on against a
# real remote, and specifically that a push transmits the appended delta rather
# than the whole ciphertext file. That claim is the point of the system, and
# only a real push can measure it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SGIT="${SGIT_BIN:-$ROOT/code/target/release/sgit}"
[[ -x "$SGIT" ]] || { echo "missing $SGIT (cargo build --release -p sgit-rs)" >&2; exit 2; }

PASS=0; FAIL=0
ok(){ printf '  ok   %s\n' "$1"; PASS=$((PASS+1)); }
no(){ printf '  FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }
chk(){ if eval "$2"; then ok "$1"; else no "$1"; fi; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export GIT_CONFIG_GLOBAL="$T/gitconfig" GIT_CONFIG_SYSTEM=/dev/null
git config -f "$T/gitconfig" user.email sgit@test.invalid
git config -f "$T/gitconfig" user.name  sgit-test
git config -f "$T/gitconfig" init.defaultBranch main

# Source-shaped, compressible text: random bytes would defeat delta compression
# and make the thin-pack number meaningless.
body(){ python3 -c '
import sys
n,mark=int(sys.argv[1]),sys.argv[2]
print("".join("pub fn unit_%d(x:&u64)->u64{let mut o=0u64;o+=1;%s o}\n"%(i,mark) for i in range(n)),end="")' "$1" "$2"; }

# Bytes a push actually puts on the wire: the THIN pack, built against what the
# remote already has. Directory growth counts loose objects, and a
# self-contained pack counts a delta base the remote is not missing; both
# overstate transmission by two orders of magnitude here.
thin_bytes(){ # ct_repo have_oid   (have = the remote tip BEFORE the push)
  local have tip
  tip="$(git -C "$1" rev-parse HEAD)"
  have="$2"
  if [[ -n "$have" ]]; then
    printf '%s\n^%s\n' "$tip" "$have" | git -C "$1" pack-objects --thin --stdout --revs 2>/dev/null | wc -c | tr -d ' '
  else
    printf '%s\n' "$tip" | git -C "$1" pack-objects --stdout --revs 2>/dev/null | wc -c | tr -d ' '
  fi
}

echo "== sgit wrapper =="

git init --bare -q "$T/bare"
mkdir -p "$T/plain"; body 900 "//v0" > "$T/plain/a.rs"; printf 'static\n' > "$T/plain/b.rs"
"$SGIT" init "$T/plain" "$T/ct" "$T/bare" --variant char >/dev/null
"$SGIT" push "$T/plain" "$T/ct" --variant char >/dev/null
chk "clone reproduces the plaintext byte for byte" \
    '"$SGIT" clone "$T/bare" "$T/plain2" "$T/ct2" --variant char --keys "$T/.sgit-ct.keys.json" >/dev/null && diff -r "$T/plain" "$T/plain2" >/dev/null'

# A LOCALIZED edit -- one token in one function. Rewriting every line would be a
# legitimate large delta and would prove nothing about delta-sized transmission.
L0=$(wc -l < "$T/ct/a.rs.sgit" | tr -d ' ')
PREV=$(git -C "$T/bare" rev-parse main)
python3 -c 'import pathlib,sys
p=pathlib.Path(sys.argv[1]); p.write_text(p.read_text().replace("unit_450(","unit_450_RENAMED(",1))' "$T/plain/a.rs"
"$SGIT" push "$T/plain" "$T/ct" --variant char >/dev/null
L1=$(wc -l < "$T/ct/a.rs.sgit" | tr -d ' ')
chk "an edit APPENDS one block rather than rewriting ($L0 -> $L1 lines)" '[[ "$L1" -eq $((L0+1)) ]]'
chk "the appended block is small next to the whole file" \
    '[[ $(tail -1 "$T/ct/a.rs.sgit" | wc -c) -lt $(( $(wc -c < "$T/ct/a.rs.sgit") / 10 )) ]]'

WHOLE=$(wc -c < "$T/ct/a.rs.sgit" | tr -d ' ')
THIN=$(thin_bytes "$T/ct" "$PREV")
chk "a push transmits the delta, not the ciphertext file (thin ${THIN}B vs file ${WHOLE}B)" \
    '[[ "$THIN" -lt $((WHOLE / 50)) && "$THIN" -gt 100 ]]'

# NEGATIVE / mutation-checkable: a push with nothing to send must send nothing.
# Without the short-circuit in `push`, tag.json is re-signed every time -- ECDSA
# is randomized, so its bytes differ even when the Merkle root does not -- and
# each no-op would carry a fresh commit and blob. That corrupts every corrected
# number in E13, which subtracts exactly this floor.
BEFORE=$(git -C "$T/ct" rev-parse HEAD)
NOOP_PREV=$(git -C "$T/bare" rev-parse main)
"$SGIT" push "$T/plain" "$T/ct" --variant char >/dev/null
"$SGIT" push "$T/plain" "$T/ct" --variant char >/dev/null
AFTER=$(git -C "$T/ct" rev-parse HEAD)
chk "repeated no-op pushes create no commits" '[[ "$BEFORE" == "$AFTER" ]]'
# Measured against the remote tip from BEFORE the two no-ops: with the
# short-circuit removed, each no-op writes a re-signed tag blob and a commit, so
# the pack stops being empty. An empty pack is 32 bytes of header and trailer.
NOOP=$(thin_bytes "$T/ct" "$NOOP_PREV")
chk "two no-op pushes transmit an EMPTY pack (${NOOP}B)" '[[ "$NOOP" -le 32 ]]'

# line variant: replaces in place, accumulates no blocks
git init --bare -q "$T/barel"
mkdir -p "$T/plainl"; body 200 "//v0" > "$T/plainl/a.rs"
"$SGIT" init "$T/plainl" "$T/ctl" "$T/barel" --variant line >/dev/null
"$SGIT" push "$T/plainl" "$T/ctl" --variant line >/dev/null
P0=$(wc -l < "$T/ctl/a.rs.sgit" | tr -d ' ')
body 200 "//v1" > "$T/plainl/a.rs"
"$SGIT" push "$T/plainl" "$T/ctl" --variant line >/dev/null
P1=$(wc -l < "$T/ctl/a.rs.sgit" | tr -d ' ')
chk "line variant rewrites in place, appending nothing ($P0 -> $P1 lines)" '[[ "$P0" -eq "$P1" ]]'
chk "line variant round-trips through a clone" \
    '"$SGIT" clone "$T/barel" "$T/plainl2" "$T/ctl2" --variant line --keys "$T/.sgit-ctl.keys.json" >/dev/null && diff -r "$T/plainl" "$T/plainl2" >/dev/null'

# NEGATIVE: a host must not be able to rewrite ciphertext undetected
cp -R "$T/ct2" "$T/ct_tamper"
python3 - "$T/ct_tamper/a.rs.sgit" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); b = bytearray(p.read_bytes()); i = len(b)//2
b[i] = ord('B') if b[i] == ord('A') else ord('A')
p.write_bytes(bytes(b))
PY
chk "tampered ciphertext is refused, not silently decrypted" \
    '! "$SGIT" pull "$T/plain_t" "$T/ct_tamper" --variant char --keys "$T/.sgit-ct.keys.json" >/dev/null 2>&1'

# NEGATIVE: the master key must never reach the remote
chk "the signing/master key is NOT inside the pushed repository" \
    '! git -C "$T/ct" ls-files | grep -q "sgit-keys"'

# NEGATIVE: a dropped appended block must not go unnoticed
cp -R "$T/ct" "$T/ct_drop"
python3 - "$T/ct_drop/a.rs.sgit" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); ls = p.read_text().splitlines(True)
p.write_text("".join(ls[:-1]))
PY
chk "dropping an appended delta breaks verification" \
    '! "$SGIT" pull "$T/plain_d" "$T/ct_drop" --variant char --keys "$T/.sgit-ct.keys.json" >/dev/null 2>&1'

# NEGATIVE: two ciphertext repositories in ONE directory must not share state.
# The key and snapshot sidecars live beside the repository rather than inside
# it, so that the master key is never pushed. With fixed names they were shared
# by every repository in that directory, and a sweep that gives each measurement
# point its own repository under one working directory would diff each point
# against the PREVIOUS point's tree -- wrong ciphertext, wrong delta size, no
# error anywhere.
mkdir -p "$T/multi/pA" "$T/multi/pB"
git init --bare -q "$T/multi/bareA"; git init --bare -q "$T/multi/bareB"
body 300 "//A" > "$T/multi/pA/a.rs"
body 300 "//B" > "$T/multi/pB/a.rs"
"$SGIT" init "$T/multi/pA" "$T/multi/ctA" "$T/multi/bareA" --variant char >/dev/null
"$SGIT" init "$T/multi/pB" "$T/multi/ctB" "$T/multi/bareB" --variant char >/dev/null
"$SGIT" push "$T/multi/pA" "$T/multi/ctA" --variant char >/dev/null
"$SGIT" push "$T/multi/pB" "$T/multi/ctB" --variant char >/dev/null
# Each repository holds exactly its own base and no delta block: if B had
# diffed against A's snapshot it would have appended one instead.
chk "sibling repositories keep independent diff state" \
    '[[ $(wc -l < "$T/multi/ctA/a.rs.sgit") -eq 1 && $(wc -l < "$T/multi/ctB/a.rs.sgit") -eq 1 ]]'
chk "sibling repositories decrypt to their own plaintext" \
    '"$SGIT" clone "$T/multi/bareB" "$T/multi/outB" "$T/multi/ctB2" --variant char --keys "$T/multi/.sgit-ctB.keys.json" >/dev/null && diff "$T/multi/pB/a.rs" "$T/multi/outB/a.rs" >/dev/null'

# NEGATIVE: a clone with no key must refuse rather than mint a fresh one and
# decrypt to garbage. Minting silently turns "you cannot read this" into a
# wrong answer, and it made the clone tests above pass for the wrong reason
# while the key sidecar had a fixed name shared across repositories.
chk "a clone without key material is refused" \
    '! "$SGIT" clone "$T/bare" "$T/nokey_plain" "$T/nokey_ct" --variant char --keys "$T/absent.json" >/dev/null 2>&1'
chk "the refusal leaves no decrypted plaintext behind" \
    '[[ ! -s "$T/nokey_plain/a.rs" ]]'

echo "  ---- $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
