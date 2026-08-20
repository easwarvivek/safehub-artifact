#!/usr/bin/env bash
# Adversarial audit of the SafeHub operations themselves.
#
# Every case attempts the bad thing and requires it to be REFUSED, or performs
# the good thing and requires the result to be CORRECT. A test that only checks
# an operation returned quickly proves nothing; these check what the operation
# actually did, including against a host that tampers with what it stores.
#
# Run: bash scripts/tests/test_safehub_ops.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="$ROOT/code/target/release"; [ -x "$BIN/safehub-server" ] || BIN="$ROOT/code/target/debug"
PASS=0; FAIL=0
ok()  { printf "  \033[32mok\033[0m    %s\n" "$1"; PASS=$((PASS+1)); }
bad() { printf "  \033[31mFAIL\033[0m  %s\n        %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }
PORT=${SH_OPS_PORT:-18410}
HOST="http://127.0.0.1:$PORT"
DATA=""; CFG=""; W=""; SRV=""

boot() {   # fresh server + alice + repo r1 with one pushed commit
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
    && printf 'CANARY-%s\n' "$RANDOM" > a.txt \
    && "$BIN/sit" add . >/dev/null 2>&1 && "$BIN/sit" commit -qm one >/dev/null 2>&1 \
    && "$BIN/sit" push >/dev/null 2>&1 )
  REPO_ID=$(ls "$DATA/heads" | head -1)
}
cleanup(){ [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; rm -rf "$DATA" "$CFG" "$W"; }
trap cleanup EXIT

echo "== 1. host tampering with a sealed bundle is detected =="
boot
BLOB=$(find "$DATA/blobs" -type f | head -1)
if [ -n "$BLOB" ]; then
  # Flip bytes in the middle of the ciphertext. A committing AEAD must refuse it;
  # silently returning corrupted plaintext would be the worst possible outcome.
  python3 - "$BLOB" <<'PY'
import sys
p=sys.argv[1]; b=bytearray(open(p,'rb').read())
if len(b) > 64:
    for i in range(len(b)//2, len(b)//2+16): b[i] ^= 0xFF
open(p,'wb').write(bytes(b))
PY
  if ( cd "$W" && "$BIN/sit" clone alice/r1 tampered >/dev/null 2>&1 ); then
    if [ -f "$W/tampered/a.txt" ] && grep -q CANARY "$W/tampered/a.txt"; then
      bad "tampered bundle still produced correct plaintext" "AEAD may not be authenticating"
    else
      bad "clone SUCCEEDED against a tampered bundle" "returned wrong or empty content instead of failing"
    fi
  else
    ok "clone refuses a tampered bundle"
  fi
else
  bad "no blob found to tamper" "layout changed?"
fi

echo "== 2. host truncating a bundle is detected =="
boot
BLOB=$(find "$DATA/blobs" -type f | head -1)
python3 -c "
import sys;p='$BLOB';d=open(p,'rb').read();open(p,'wb').write(d[:max(1,len(d)//2)])"
if ( cd "$W" && "$BIN/sit" clone alice/r1 trunc >/dev/null 2>&1 ) \
   && [ -f "$W/trunc/a.txt" ] && grep -q CANARY "$W/trunc/a.txt"; then
  bad "clone succeeded against a truncated bundle" "length is not authenticated"
else
  ok "clone refuses a truncated bundle"
fi

echo "== 3. host rolling the tip back is detected against a checkpoint =="
boot
( cd "$W/r1" && printf 'second\n' >> a.txt && "$BIN/sit" add . >/dev/null 2>&1 \
  && "$BIN/sit" commit -qm two >/dev/null 2>&1 && "$BIN/sit" push >/dev/null 2>&1 )
LOG="$DATA/heads/$REPO_ID/log"
if [ "$(ls "$LOG" | wc -l | tr -d ' ')" -ge 2 ]; then
  # Anchor the honest state, exactly as the gossip/Compare mechanism intends.
  ( cd "$W/r1" && "$BIN/shub" repo export-checkpoint --out "$W/before.json" alice/r1 >/dev/null 2>&1 )
  # Malicious host rolls the log back to seq 1 and serves it as the tip. Done
  # cleanly, the served chain is internally consistent, so verify alone cannot
  # see it -- detection requires comparing against the earlier anchor.
  rm -f "$LOG/2.bin"
  cp "$LOG/1.bin" "$DATA/heads/$REPO_ID/tip.bin"
  ( cd "$W/r1" && "$BIN/shub" repo export-checkpoint --out "$W/after.json" alice/r1 >/dev/null 2>&1 )
  if [ -s "$W/before.json" ] && [ -s "$W/after.json" ]; then
    OUT=$( "$BIN/shub" repo compare "$W/before.json" "$W/after.json" 2>&1 ); RC=$?
    if [ $RC -ne 0 ] || echo "$OUT" | grep -qiE 'fork|rollback|behind|non-prefix|mismatch'; then
      ok "compare against a prior checkpoint detects the rollback"
    else
      bad "rollback NOT detected even against a checkpoint" "$(echo "$OUT" | head -2 | tr '\n' ' ')"
    fi
  else
    bad "could not export checkpoints" "before=$(wc -c <"$W/before.json" 2>/dev/null) after=$(wc -c <"$W/after.json" 2>/dev/null)"
  fi
else
  bad "could not create two heads" ""
fi

echo "== 4. host corrupting the head chain is detected =="
boot
# verify walks the append-only log, so corrupt the log entry, not just tip.bin.
for f in "$DATA/heads/$REPO_ID/log/1.bin" "$DATA/heads/$REPO_ID/tip.bin"; do
  python3 - "$f" <<'PY'
import sys
p=sys.argv[1]; b=bytearray(open(p,'rb').read())
if len(b) > 40:
    for i in range(len(b)//2, len(b)//2+8): b[i] ^= 0xFF
open(p,'wb').write(bytes(b))
PY
done
OUT=$( cd "$W/r1" && "$BIN/shub" repo verify alice/r1 2>&1 ); RC=$?
if [ $RC -ne 0 ] || echo "$OUT" | grep -qiE 'fail|invalid|mismatch|corrupt|error|bad'; then
  ok "repo verify flags a corrupted head record"
else
  bad "corrupted head NOT detected" "$(echo "$OUT" | head -3 | tr '\n' ' ')"
fi

echo "== 5. a non-member cannot read or push =="
boot
"$BIN/shub" auth logout >/dev/null 2>&1
"$BIN/shub" auth register --user mallory --password mpw --hostname "$HOST" >/dev/null 2>&1
"$BIN/shub" device publish-key-package --device default >/dev/null 2>&1
MTOK=$(curl -sf -X POST "$HOST/v1/auth/login" -H 'content-type: application/json' \
  -d '{"user":"mallory","secret":"mpw"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])' 2>/dev/null)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $MTOK" "$HOST/v1/repos/alice/r1")
[ "$CODE" = "403" ] && ok "non-member is refused repo access (403)" || bad "non-member got $CODE" "expected 403"
# A malformed body is rejected at deserialisation (422) before authorization is
# consulted, which proves nothing. Replay alice's real head instead.
ATOK=$(curl -sf -X POST "$HOST/v1/auth/login" -H 'content-type: application/json' \
  -d '{"user":"alice","secret":"pw"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])' 2>/dev/null)
REAL=$(curl -sf -H "Authorization: Bearer $ATOK" "$HOST/v1/repos/$REPO_ID/heads?after=0&limit=1" \
  | python3 -c 'import json,sys; h=json.load(sys.stdin)["heads"]; print(json.dumps({"head":h[0]}) if h else "")' 2>/dev/null)
if [ -n "$REAL" ]; then
  HCODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $MTOK" \
    -H 'content-type: application/json' -d "$REAL" "$HOST/v1/repos/$REPO_ID/heads")
  if [ "$HCODE" = "403" ]; then
    ok "non-member head append refused (403) on a well-formed head"
  else
    bad "non-member appending a well-formed head got $HCODE" "expected 403"
  fi
else
  bad "could not fetch a real head to replay" ""
fi
if ( cd "$W" && "$BIN/sit" clone alice/r1 mallory-clone >/dev/null 2>&1 ); then
  bad "non-member CLONED the repository" "read access not enforced"
else
  ok "non-member cannot clone"
fi

# Multi-user cases need isolated credential stores, so each identity gets its
# own HOME. Sharing one would let a later login silently answer for an earlier
# identity and make the whole test vacuous.
as_user() { export HOME="$1"; export XDG_CONFIG_HOME="$1/.config"; mkdir -p "$XDG_CONFIG_HOME"; }

echo "== 6. a forward-only member cannot recover superseded history =="
boot
A_HOME="$CFG"; B_HOME=$(mktemp -d)
OLD="SUPERSEDED-$RANDOM-ONLY-IN-HISTORY"
NEW="CURRENT-$RANDOM-AT-TIP"
# v1 is pushed BEFORE the invite, so it is pre-grant history.
as_user "$A_HOME"
( cd "$W/r1" && printf '%s\n' "$OLD" > secret.txt && "$BIN/sit" add . >/dev/null 2>&1 \
  && "$BIN/sit" commit -qm v1 >/dev/null 2>&1 && "$BIN/sit" push >/dev/null 2>&1 )
as_user "$B_HOME"
"$BIN/shub" auth register --user bob --password bpw --hostname "$HOST" >/dev/null 2>&1
"$BIN/shub" device publish-key-package --device default >/dev/null 2>&1
as_user "$A_HOME"
"$BIN/shub" repo invite alice/r1 bob --forward-only >/dev/null 2>&1
# v2 is pushed AFTER the invite, at or above bob's grant epoch. Without such a
# head bob's clone is refused outright ("epoch N before history grant M"),
# which is the window mechanism working, not a failure.
( cd "$W/r1" && printf '%s\n' "$NEW" > secret.txt && "$BIN/sit" add . >/dev/null 2>&1 \
  && "$BIN/sit" commit -qm v2 >/dev/null 2>&1 && "$BIN/sit" push >/dev/null 2>&1 )
as_user "$B_HOME"
"$BIN/shub" auth login --user bob --secret bpw --hostname "$HOST" >/dev/null 2>&1
"$BIN/shub" repo accept-welcome alice/r1 >/dev/null 2>&1
if ( cd "$W" && "$BIN/sit" clone alice/r1 bobfo >/dev/null 2>&1 ); then
  if grep -q "$NEW" "$W/bobfo/secret.txt" 2>/dev/null; then
    ok "forward-only member sees the current tip content"
  else
    bad "forward-only member could not read the tip" "graft did not deliver current state"
  fi
  # The claim under test: the superseded version must be unreachable, in the
  # working tree and anywhere in the object store.
  if grep -rq "$OLD" "$W/bobfo" 2>/dev/null; then
    bad "forward-only member RECOVERED superseded history" \
        "$(grep -rl "$OLD" "$W/bobfo" | head -2 | tr '\n' ' ')"
  else
    ok "superseded version is not recoverable by the forward-only member"
  fi
  DEPTH=$(git -C "$W/bobfo" rev-list --count HEAD 2>/dev/null || echo 0)
  [ "${DEPTH:-0}" -le 2 ] && ok "forward-only clone is a graft, not full history (depth=$DEPTH)" \
    || bad "forward-only clone carries $DEPTH commits" "expected a shallow graft"
else
  bad "forward-only member could not clone" "invite or welcome failed"
fi
rm -rf "$B_HOME"

echo "== 7. a removed member cannot read content pushed after removal =="
boot
A_HOME="$CFG"; C_HOME=$(mktemp -d)
AFTER="POST-REMOVAL-$RANDOM"
as_user "$C_HOME"
"$BIN/shub" auth register --user carol --password cpw --hostname "$HOST" >/dev/null 2>&1
"$BIN/shub" device publish-key-package --device default >/dev/null 2>&1
as_user "$A_HOME"
"$BIN/shub" repo invite alice/r1 carol >/dev/null 2>&1
BEFOREMARK="PRE-REMOVAL-$RANDOM"
( cd "$W/r1" && printf '%s\n' "$BEFOREMARK" > pre.txt && "$BIN/sit" add . >/dev/null 2>&1 \
  && "$BIN/sit" commit -qm pre >/dev/null 2>&1 && "$BIN/sit" push >/dev/null 2>&1 )
as_user "$C_HOME"
"$BIN/shub" auth login --user carol --secret cpw --hostname "$HOST" >/dev/null 2>&1
"$BIN/shub" repo accept-welcome alice/r1 >/dev/null 2>&1
CLONED=0
( cd "$W" && "$BIN/sit" clone alice/r1 carolwt >/dev/null 2>&1 ) && CLONED=1
# This must hold, or the post-removal assertion below proves nothing: a member
# who never had access trivially cannot read anything.
if [ "$CLONED" = "1" ] && grep -q "$BEFOREMARK" "$W/carolwt/pre.txt" 2>/dev/null; then
  ok "member could read content while still a member"
else
  bad "member could not read before removal" "the post-removal check would be vacuous"
fi
as_user "$A_HOME"
"$BIN/shub" repo remove-member alice/r1 carol >/dev/null 2>&1
"$BIN/shub" repo rotate alice/r1 >/dev/null 2>&1
( cd "$W/r1" && printf '%s\n' "$AFTER" > post.txt && "$BIN/sit" add . >/dev/null 2>&1 \
  && "$BIN/sit" commit -qm post >/dev/null 2>&1 && "$BIN/sit" push >/dev/null 2>&1 )
as_user "$C_HOME"
( cd "$W/carolwt" && "$BIN/sit" fetch >/dev/null 2>&1; "$BIN/sit" pull >/dev/null 2>&1 ) || true
if grep -rq "$AFTER" "$W/carolwt" 2>/dev/null; then
  bad "removed member READ content pushed after removal" "forward-block failed"
else
  ok "removed member cannot read content pushed after removal"
fi
rm -rf "$C_HOME"
as_user "$A_HOME"

echo "== 8. consolidation preserves content =="
boot
MARK="CONSOLIDATE-CANARY-$RANDOM"
( cd "$W/r1" && printf '%s\n' "$MARK" > c.txt && "$BIN/sit" add . >/dev/null 2>&1 \
  && "$BIN/sit" commit -qm c >/dev/null 2>&1 && "$BIN/sit" push >/dev/null 2>&1 )
BEFORE=$( cd "$W" && "$BIN/sit" clone alice/r1 pre >/dev/null 2>&1 && \
  git -C "$W/pre" ls-files -s | shasum -a 256 | cut -d' ' -f1 )
"$BIN/shub" repo rotate alice/r1 >/dev/null 2>&1
"$BIN/shub" repo consolidate alice/r1 --tip-mib 12 >/dev/null 2>&1
AFTERSIG=$( cd "$W" && "$BIN/sit" clone alice/r1 post >/dev/null 2>&1 && \
  git -C "$W/post" ls-files -s | shasum -a 256 | cut -d' ' -f1 )
if [ -n "$BEFORE" ] && [ "$BEFORE" = "$AFTERSIG" ]; then
  ok "clone after rotate+consolidate is byte-identical ($BEFORE)"
else
  bad "consolidation changed the tree" "before=${BEFORE:-none} after=${AFTERSIG:-none}"
fi
grep -q "$MARK" "$W/post/c.txt" 2>/dev/null && ok "content readable after consolidation" \
  || bad "content lost after consolidation" ""

echo "== 9. a full-history grant spans a rotation (multi-segment window) =="
boot
A_HOME="$CFG"; D_HOME=$(mktemp -d)
SEG_A="SEGMENT-A-$RANDOM"; SEG_B="SEGMENT-B-$RANDOM"
as_user "$A_HOME"
( cd "$W/r1" && printf '%s\n' "$SEG_A" > seg.txt && "$BIN/sit" add . >/dev/null 2>&1 \
  && "$BIN/sit" commit -qm segA >/dev/null 2>&1 && "$BIN/sit" push >/dev/null 2>&1 )
# rotate installs a fresh random DKR seed, so the epochs above and below it sit
# in cryptographically independent segments. One interval token cannot span
# both; a full grant must therefore carry the retained seeds for each.
"$BIN/shub" repo rotate alice/r1 >/dev/null 2>&1
( cd "$W/r1" && printf '%s\n' "$SEG_B" >> seg.txt && "$BIN/sit" add . >/dev/null 2>&1 \
  && "$BIN/sit" commit -qm segB >/dev/null 2>&1 && "$BIN/sit" push >/dev/null 2>&1 )
as_user "$D_HOME"
"$BIN/shub" auth register --user dave --password dpw --hostname "$HOST" >/dev/null 2>&1
"$BIN/shub" device publish-key-package --device default >/dev/null 2>&1
as_user "$A_HOME"
"$BIN/shub" repo invite alice/r1 dave >/dev/null 2>&1
as_user "$D_HOME"
"$BIN/shub" auth login --user dave --secret dpw --hostname "$HOST" >/dev/null 2>&1
"$BIN/shub" repo accept-welcome alice/r1 >/dev/null 2>&1
if ( cd "$W" && "$BIN/sit" clone alice/r1 davewt >/dev/null 2>&1 ); then
  grep -q "$SEG_A" "$W/davewt/seg.txt" 2>/dev/null \
    && ok "full member reads content sealed BEFORE the rotation" \
    || bad "full member cannot read pre-rotation content" "the grant did not cover the earlier segment"
  grep -q "$SEG_B" "$W/davewt/seg.txt" 2>/dev/null \
    && ok "full member reads content sealed after the rotation" \
    || bad "full member cannot read post-rotation content" ""
else
  bad "full member could not clone across a rotation" "multi-segment window not delivered"
fi
rm -rf "$D_HOME"; as_user "$A_HOME"

echo "== 11. a no-op push does not grow with history =="
# A push with nothing to send used to cost more than a real push: the only
# available negative rev is the remote tip, which equals local HEAD, and it was
# skipped (git refuses an empty bundle), leaving `git bundle create` to bundle
# everything. The defining symptom is that the cost SCALES WITH HISTORY, so that
# is what is asserted -- comparing against a real push is too weak to catch it
# at small repository sizes.
boot
ms_now_(){ python3 -c 'import time;print(int(time.time()*1000))'; }
bulk_(){ ( cd "$W/r1" && python3 -c "
import random, sys
from pathlib import Path
tag=sys.argv[1]
# Distinct content per file. Identical repeated bytes would compress to almost
# nothing, so a bundle of the whole history would stay small and the defect
# would not show -- the corpus has to be varied for this test to bite.
for i in range(30):
    r=random.Random(hash((tag,i)) & 0xffffffff)
    Path(f'bulk_{tag}_{i}.txt').write_text(
        ''.join(f'{r.randrange(10**12)} {r.randrange(10**12)}\n' for _ in range(12000)))" "$1" \
    && "$BIN/sit" add . >/dev/null 2>&1 && "$BIN/sit" commit -qm "bulk$1" >/dev/null 2>&1 \
    && "$BIN/sit" push >/dev/null 2>&1 ) >/dev/null 2>&1; }
noop_(){ local t0 t1; t0=$(ms_now_); ( cd "$W/r1" && "$BIN/sit" push >/dev/null 2>&1 ); t1=$(ms_now_); echo $((t1-t0)); }
bulk_ a; SMALL=$(noop_)
for r in b c d e; do bulk_ $r; done
BIG=$(noop_)
if [ "$BIG" -lt $(( SMALL * 2 + 60 )) ]; then
  ok "no-op push flat in history (${SMALL}ms at 1x, ${BIG}ms at 5x history)"
else
  bad "no-op push grows with history" "${SMALL}ms at 1x vs ${BIG}ms at 5x: history is being re-bundled"
fi

echo "== 10. a forward-only grant carries no retained history material =="
boot
A_HOME="$CFG"; E_HOME=$(mktemp -d)
as_user "$E_HOME"
"$BIN/shub" auth register --user erin --password epw --hostname "$HOST" >/dev/null 2>&1
"$BIN/shub" device publish-key-package --device default >/dev/null 2>&1
as_user "$A_HOME"
"$BIN/shub" repo invite alice/r1 erin --forward-only >/dev/null 2>&1
as_user "$E_HOME"
"$BIN/shub" auth login --user erin --secret epw --hostname "$HOST" >/dev/null 2>&1
"$BIN/shub" repo accept-welcome alice/r1 >/dev/null 2>&1
# The joiner's on-disk material must hold no prior-epoch seeds at all: shipping
# them would silently undo the backward block that makes the grant forward-only.
MAT=$(find "$E_HOME" -name 'epoch.json' 2>/dev/null | head -1)
if [ -n "$MAT" ]; then
  N=$(python3 -c "
import json,sys
d=json.load(open('$MAT'))
print(len(d.get('prior_transport') or {}) + len(d.get('prior_refs_mac') or {}))" 2>/dev/null)
  [ "${N:-1}" = "0" ] && ok "forward-only material carries zero retained seeds" \
    || bad "forward-only joiner received $N retained seed(s)" "backward block undone"
else
  bad "could not locate the joiner's epoch material" ""
fi
rm -rf "$E_HOME"; as_user "$A_HOME"

echo
printf "== %d passed, %d failed ==\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
