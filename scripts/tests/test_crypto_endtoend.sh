#!/usr/bin/env bash
# End-to-end verification that SafeHub does what it claims, rather than that it
# merely produces timings.
#
# Three questions, each answered by observation rather than by reading code:
#   1. Does push encrypt BEFORE upload?  -> the host's data directory must not
#      contain the plaintext, nor the filename.
#   2. Does pull decrypt AFTER fetch?    -> a fresh clone must reproduce the
#      plaintext byte-for-byte.
#   3. Does the server compare-and-swap on the head? -> replaying a stale head
#      must be refused with 409, and the log must chain.
#
# Run: bash scripts/tests/test_crypto_endtoend.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="$ROOT/code/target/release"; [ -x "$BIN/safehub-server" ] || BIN="$ROOT/code/target/debug"
PASS=0; FAIL=0
ok()  { printf "  \033[32mok\033[0m    %s\n" "$1"; PASS=$((PASS+1)); }
bad() { printf "  \033[31mFAIL\033[0m  %s\n        %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }

DATA=$(mktemp -d); CFG=$(mktemp -d); WORK=$(mktemp -d)
PORT=${SH_TEST_PORT:-18391}; HOST="http://127.0.0.1:$PORT"
export HOME="$CFG" XDG_CONFIG_HOME="$CFG/.config"; mkdir -p "$XDG_CONFIG_HOME"
export PATH="$BIN:$PATH"
SRV=""
cleanup(){ [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; rm -rf "$DATA" "$CFG" "$WORK"; }
trap cleanup EXIT

"$BIN/safehub-server" --listen "127.0.0.1:$PORT" --data "$DATA" >"$WORK/srv.log" 2>&1 &
SRV=$!
for _ in $(seq 1 80); do curl -sf "$HOST/v1/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -sf "$HOST/v1/health" >/dev/null || { echo "server did not start"; exit 1; }

# Markers are unique per run so a stale artifact cannot make the test pass.
MARKER="PLAINTEXT-CANARY-$RANDOM$RANDOM-DO-NOT-LEAK"
FNAME="canary-filename-$RANDOM.txt"

"$BIN/shub" auth register --user alice --password pw --hostname "$HOST" >/dev/null 2>&1
"$BIN/shub" auth login --user alice --secret pw --hostname "$HOST" >/dev/null 2>&1
"$BIN/shub" device publish-key-package --device default >/dev/null 2>&1
cd "$WORK"
CREATE_OUT=$("$BIN/shub" repo create canary --clone 2>&1)
REPO_ID=$(echo "$CREATE_OUT" | awk '/^id /{print $2}')
[ -d "$WORK/canary/.git/safehub" ] || { echo "repo create failed: $CREATE_OUT"; exit 1; }
cd "$WORK/canary"
git config user.email t@t; git config user.name t
printf '%s\n' "$MARKER" > "$FNAME"
"$BIN/sit" add . >/dev/null 2>&1
"$BIN/sit" commit -qm "canary" >/dev/null 2>&1
"$BIN/sit" push >/dev/null 2>&1 || { echo "push failed"; exit 1; }

echo "== 1. push encrypts before upload =="
if grep -ra -l "$MARKER" "$DATA" >/dev/null 2>&1; then
  bad "plaintext CONTENT found in the host data directory" \
      "$(grep -ra -l "$MARKER" "$DATA" | head -3 | tr '\n' ' ')"
else
  ok "file content is not present in the host data directory"
fi
if grep -ra -l "$FNAME" "$DATA" >/dev/null 2>&1; then
  bad "plaintext FILENAME found in the host data directory" \
      "paths are supposed to be sealed; host should see sizes and order only"
else
  ok "filename is not present in the host data directory"
fi
CT=$(find "$DATA" -type f | wc -l | tr -d ' ')
[ "$CT" -gt 0 ] && ok "host stored $CT files (ciphertext present, not an empty push)" \
  || bad "host stored nothing" "push may not have transferred anything"

echo "== 2. pull decrypts after fetch =="
cd "$WORK"
if "$BIN/sit" clone alice/canary readback >/dev/null 2>&1; then
  if [ -f "$WORK/readback/$FNAME" ] && grep -q "$MARKER" "$WORK/readback/$FNAME"; then
    ok "fresh clone reproduced the plaintext byte-for-byte"
  else
    bad "clone did not reproduce plaintext" "decryption or checkout failed"
  fi
  A=$(shasum -a 256 < "$WORK/canary/$FNAME" | cut -d' ' -f1)
  B=$(shasum -a 256 < "$WORK/readback/$FNAME" 2>/dev/null | cut -d' ' -f1)
  [ -n "$B" ] && [ "$A" = "$B" ] && ok "round-trip digest matches ($A)" \
    || bad "round-trip digest mismatch" "writer=$A reader=${B:-none}"
else
  bad "sit clone failed" "cannot verify decryption"
fi

echo "== 3. server compare-and-swap on the head =="
TOK=$(curl -sf -X POST "$HOST/v1/auth/login" -H 'content-type: application/json' \
  -d '{"user":"alice","secret":"pw"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])' 2>/dev/null)
if [ -z "$TOK" ] || [ -z "$REPO_ID" ]; then
  bad "could not obtain token or repo id" "tok=${TOK:0:8} repo=${REPO_ID:0:8}"
else
  # second push so the log has at least two entries to chain
  cd "$WORK/canary"; printf 'second\n' >> "$FNAME"
  "$BIN/sit" add . >/dev/null 2>&1; "$BIN/sit" commit -qm two >/dev/null 2>&1
  "$BIN/sit" push >/dev/null 2>&1
  HEADS=$(curl -sf -H "Authorization: Bearer $TOK" "$HOST/v1/repos/$REPO_ID/heads?after=0&limit=10")
  N=$(echo "$HEADS" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["heads"]))' 2>/dev/null)
  [ "${N:-0}" -ge 2 ] && ok "head log has $N entries" || bad "head log too short" "n=${N:-0}"

  echo "$HEADS" | python3 -c '
import json,sys
hs=sorted(json.load(sys.stdin)["heads"], key=lambda h:h["seq"])
assert hs[0]["seq"]==1, hs[0]["seq"]
for a,b in zip(hs, hs[1:]):
    assert b["seq"]==a["seq"]+1, (a["seq"],b["seq"])
' 2>/dev/null && ok "sequence numbers are contiguous from 1" || bad "sequence not contiguous" ""

  # Replay head seq=1 now that seq>=2 exists. Its prev_head_hash no longer
  # matches the tip, so a real CAS must refuse it.
  REPLAY=$(echo "$HEADS" | python3 -c '
import json,sys
hs=sorted(json.load(sys.stdin)["heads"], key=lambda h:h["seq"])
print(json.dumps({"head": hs[0]}))' 2>/dev/null)
  CODE=$(curl -s -o "$WORK/replay.out" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $TOK" -H 'content-type: application/json' \
    -d "$REPLAY" "$HOST/v1/repos/$REPO_ID/heads")
  if [ "$CODE" = "409" ]; then
    ok "replaying a stale head is refused with 409 ($(head -c 60 "$WORK/replay.out"))"
  else
    bad "stale head was NOT refused with 409" \
        "got $CODE: $(head -c 120 "$WORK/replay.out"). Without CAS a concurrent or replayed push could silently overwrite the tip."
  fi
fi

echo
printf "== %d passed, %d failed ==\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
