#!/usr/bin/env bash
# Preflight: verify the evaluation environment is not merely present but
# WORKING, before a multi-hour sweep produces numbers nobody can trust.
#
# Every check here corresponds to a defect that reached published output. The
# rule throughout: presence is not function. `command -v git-crypt` was true on
# a box where git-crypt could not build; `git gc` returned a timing on a repo
# it never touched; `shasum` was absent and tree signatures were empty strings
# that compared equal to each other.
#
# Run: bash scripts/tests/preflight.sh
set -uo pipefail
PASS=0; FAIL=0; WARN=0
ok()   { printf "  \033[32mok\033[0m    %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n        %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }
warn() { printf "  \033[33mwarn\033[0m  %s\n        %s\n" "$1" "${2:-}"; WARN=$((WARN+1)); }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

echo "== integrity tooling =="
if command -v shasum >/dev/null 2>&1 && [ "$(printf x | shasum -a 256 | cut -d' ' -f1 | wc -c)" -eq 65 ]; then
  ok "shasum produces a 64-hex digest"
else
  bad "shasum missing or broken" \
      "parity_sweep tree_sig/content_sig become EMPTY strings; postconditions then compare '' to '' and pass vacuously"
fi
for t in sha256sum md5sum python3 awk sed; do
  command -v "$t" >/dev/null 2>&1 && ok "$t present" || bad "$t missing" "required by the harness"
done

echo "== git and its server modes =="
command -v git >/dev/null 2>&1 && ok "git $(git --version | awk '{print $3}')" || bad "git missing" ""
git daemon --help >/dev/null 2>&1 && ok "git daemon available (parity git arm)" \
  || bad "git-daemon missing" "the git arm of parity_sweep cannot be served"
git multi-pack-index --help >/dev/null 2>&1 && ok "git multi-pack-index available" \
  || warn "multi-pack-index missing" "depth-clone replay optimisation unavailable"

echo "== git gc actually repacks (not a silent no-op) =="
# Build a bare repo with several packs, then require gc to reduce pack count.
GB="$TMP/gc.git"; WT="$TMP/gcwt"
git init --bare -q "$GB" 2>/dev/null
# receive.unpackLimit defaults to 100, so small pushes are exploded into loose
# objects and never form packs. Force a pack per push so gc has something to do.
git -C "$GB" config receive.unpackLimit 1 2>/dev/null
git init -q "$WT" 2>/dev/null
git -C "$WT" config user.email t@t; git -C "$WT" config user.name t
git -C "$WT" remote add origin "file://$GB" 2>/dev/null
for i in 1 2 3 4 5; do
  head -c 200000 /dev/urandom > "$WT/f$i.bin"
  git -C "$WT" add -A >/dev/null 2>&1
  git -C "$WT" commit -qm "c$i" >/dev/null 2>&1
  git -C "$WT" push -q origin HEAD >/dev/null 2>&1
done
PACKS_BEFORE=$(ls -1 "$GB"/objects/pack/*.pack 2>/dev/null | wc -l | tr -d ' ')
T0=$(python3 -c 'import time;print(int(time.time()*1000))')
git -C "$GB" gc --quiet >/dev/null 2>&1; GCRC=$?
T1=$(python3 -c 'import time;print(int(time.time()*1000))')
PACKS_AFTER=$(ls -1 "$GB"/objects/pack/*.pack 2>/dev/null | wc -l | tr -d ' ')
if [ "$GCRC" -eq 0 ] && [ "$PACKS_BEFORE" -gt 1 ] && [ "$PACKS_AFTER" -lt "$PACKS_BEFORE" ]; then
  ok "git gc consolidated $PACKS_BEFORE packs into $PACKS_AFTER ($((T1-T0)) ms)"
elif [ "$PACKS_BEFORE" -le 1 ]; then
  warn "could not build a multi-pack repo to test gc" "packs_before=$PACKS_BEFORE"
else
  bad "git gc did not repack" \
      "rc=$GCRC packs $PACKS_BEFORE->$PACKS_AFTER in $((T1-T0))ms. A gc that fails still returns a timing, so the git arm is then cloned from unconsolidated packs -- git's worst case -- and SafeHub appears to win."
fi

echo "== encrypted-git baseline peers =="
if command -v git-crypt >/dev/null 2>&1; then
  ok "git-crypt $(git-crypt --version 2>&1 | head -1 | awk '{print $2}')"
else
  warn "git-crypt missing" "the git-crypt arm of tab:egb is reported absent, not measured"
fi
command -v git-remote-gcrypt >/dev/null 2>&1 && ok "git-remote-gcrypt present" \
  || warn "git-remote-gcrypt missing" "the whole-remote arm of tab:egb is unmeasurable"
if command -v gpg >/dev/null 2>&1; then
  if command -v gpg-agent >/dev/null 2>&1; then
    ok "gpg and gpg-agent present"
  else
    bad "gpg-agent missing" "GnuPG 2.x cannot generate a key without it; the gcrypt arm fails with 'gpg key generation failed' and is silently dropped"
  fi
else
  warn "gpg missing" "gcrypt arm unmeasurable"
fi

echo "== SafeHub binaries =="
BIN="$ROOT/code/target/release"
for b in safehub-server shub sit; do
  [ -x "$BIN/$b" ] && ok "$b built" || warn "$b not built" "run cargo build --release"
done
if [ -e "$BIN/sh" ]; then
  if [ -L "$BIN/sh" ] && [ "$(readlink "$BIN/sh")" = "shub" ]; then
    ok "sh is a symlink to shub (cannot go stale)"
  else
    SH_T=$(date -r "$BIN/sh" +%s 2>/dev/null || stat -c %Y "$BIN/sh" 2>/dev/null)
    SHUB_T=$(date -r "$BIN/shub" +%s 2>/dev/null || stat -c %Y "$BIN/shub" 2>/dev/null)
    if [ -n "$SH_T" ] && [ -n "$SHUB_T" ] && [ "$SH_T" -lt "$SHUB_T" ]; then
      bad "sh is STALE relative to shub" "harnesses invoking 'sh' would run an old CLI; make it a symlink to shub"
    else
      ok "sh present and not older than shub"
    fi
  fi
else
  warn "no 'sh' in target/release" "http_overhead.sh invokes the CLI as 'sh' and would fall through to /bin/sh, reducing that arm to no-ops"
fi

echo "== library units =="
python3 -c "
import sys; sys.path.insert(0,'$ROOT/scripts/lib')
from eval_publish import aead_ms_per_byte
v=aead_ms_per_byte({'aead_seal_1mib_ns':7923185.0},'seal')*1024*1024
assert 0.1 < v < 10000, v
" 2>/dev/null && ok "aead_ms_per_byte returns milliseconds" \
  || bad "aead_ms_per_byte unit error" "1 MiB must be single-digit ms; seconds-per-byte makes every model 1000x small"

echo
printf "== %d passed, %d failed, %d warnings ==\n" "$PASS" "$FAIL" "$WARN"
[ "$FAIL" -eq 0 ]
