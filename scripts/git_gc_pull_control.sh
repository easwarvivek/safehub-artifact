#!/usr/bin/env bash
# How much of git's pull cost is missing server maintenance?
#
# The parity sweep pins gc.auto=0 and receive.autogc=false so a repack cannot
# fire inside a timed sample. The side effect is that git's bare repo holds only
# loose objects and never packs, so `upload-pack` re-reads and re-compresses
# them on every fetch with no stored deltas to reuse. A real host runs
# maintenance. Measuring git only in that state overstates SafeHub's pull
# advantage by an unknown amount -- the sweep reports both states for clone but
# not for pull, and this closes that gap.
#
# Per size, on the git arm only, reproducing the sweep's schedule:
#   1. 100 push/pull cycles, delta = size/100     -> server accumulates loose objects
#   2. time TAIL pulls in that state              -> "loose"
#   3. git gc the bare repo
#   4. TAIL more push/pull cycles                 -> server has one pack + fresh loose
#   5. time those pulls                           -> "packed"
#
# Step 4 is what a maintained host actually looks like: a large pack plus the
# few objects pushed since the last gc.
#
# Env: GCC_SIZES (MB, default "50 100 250 500"), GCC_TAIL (default 20)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODE="$ROOT/code"; [[ -d "$CODE/crates" ]] || CODE="$ROOT"
SIZES="${GCC_SIZES:-50 100 250 500}"
PUSHES="${GCC_PUSHES:-100}"
TAIL="${GCC_TAIL:-20}"
OUT="${GCC_OUT:-$CODE/eval/published/git-gc-pull-control.json}"

free_port() { python3 -c "
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"; }

WORK="$(mktemp -d /tmp/gcctl.XXXXXX)"
HTTP_PID=""
cleanup() {
  [[ -n "$HTTP_PID" ]] && kill -9 "$HTTP_PID" 2>/dev/null
  pkill -9 -P $$ 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# Identical pinning to the sweep, so these numbers sit beside its git column.
export GIT_CONFIG_COUNT=8
export GIT_CONFIG_KEY_0=gc.auto             GIT_CONFIG_VALUE_0=0
export GIT_CONFIG_KEY_1=gc.autoPackLimit    GIT_CONFIG_VALUE_1=0
export GIT_CONFIG_KEY_2=receive.autogc      GIT_CONFIG_VALUE_2=false
export GIT_CONFIG_KEY_3=receive.unpackLimit GIT_CONFIG_VALUE_3=100
export GIT_CONFIG_KEY_4=core.compression    GIT_CONFIG_VALUE_4=6
export GIT_CONFIG_KEY_5=pack.compression    GIT_CONFIG_VALUE_5=6
export GIT_CONFIG_KEY_6=core.fsync          GIT_CONFIG_VALUE_6=objects,reference
export GIT_CONFIG_KEY_7=core.fsyncMethod    GIT_CONFIG_VALUE_7=fsync

ms() { python3 -c 'import time;print(int(time.time()*1000))'; }

PORT="$(free_port)"; BASE="$WORK/base"; mkdir -p "$BASE"
python3 "$ROOT/scripts/git_http_server.py" "$BASE" "$PORT" >"$WORK/http.log" 2>&1 &
HTTP_PID=$!
sleep 1.5

mkdir -p "$(dirname "$OUT")"
echo '{"mode":"git-gc-pull-control","sizes":[]}' > "$OUT"

for MB in $SIZES; do
  PERFILE=$(( MB*1024*1024 / PUSHES ))
  echo "==> ${MB} MB · ${PUSHES} pushes · $((PERFILE/1024)) KB delta · tail ${TAIL}"
  R="gc$MB"
  git init --bare -q "$BASE/$R.git"
  git -C "$BASE/$R.git" config http.receivepack true
  URL="http://127.0.0.1:$PORT/$R.git"

  W="$WORK/w$MB"; RD="$WORK/r$MB"; rm -rf "$W" "$RD"; mkdir -p "$W"
  ( cd "$W" && git init -q --template= \
      && git config user.email gc@safehub.local && git config user.name GcCtl )
  ( cd "$W" && echo seed > .seed && git add -A && git commit -qm seed >/dev/null \
      && git push -q "$URL" HEAD ) || { echo "  seed failed"; continue; }
  git clone -q "$URL" "$RD" || { echo "  clone failed"; continue; }
  ( cd "$RD" && git config user.email gc@safehub.local && git config user.name GcCtl )

  gen() { python3 -c "
import os,sys
open(sys.argv[1],'wb').write(os.urandom(int(sys.argv[2])))" "$W/src/f$1.bin" "$PERFILE"; }
  mkdir -p "$W/src"

  loose=(); packed=(); fail=""
  cycle() { # cycle <index> <array-name>
    gen "$1"
    ( cd "$W" && git add -A && git commit -qm "d$1" >/dev/null 2>&1 )
    ( cd "$W" && git push -q "$URL" HEAD ) >/dev/null 2>&1 || { fail="push $1"; return 1; }
    local a b; a=$(ms)
    ( cd "$RD" && git pull -q --no-rebase --ff-only "$URL" HEAD ) >/dev/null 2>&1 || { fail="pull $1"; return 1; }
    b=$(ms)
    printf -v "$2" '%s' "$((b-a))"
    return 0
  }

  # --- phase 1: loose server, as the sweep leaves it ---
  for ((i=1; i<=PUSHES; i++)); do
    t=""; cycle "$i" t || break
    (( i > PUSHES-TAIL )) && loose+=("$t")
  done
  [[ -n "$fail" ]] && { echo "  !! $fail"; continue; }

  # --- maintenance ---
  # Count before gc: afterwards the loose objects are gone, which is the point.
  LOOSE_N=$(find "$BASE/$R.git/objects" -type f ! -path '*pack*' | wc -l | tr -d ' ')
  a=$(ms); git -C "$BASE/$R.git" gc --quiet; b=$(ms); GCMS=$((b-a))

  # --- phase 2: packed server + freshly pushed objects ---
  for ((i=PUSHES+1; i<=PUSHES+TAIL; i++)); do
    t=""; cycle "$i" t || break
    packed+=("$t")
  done
  [[ -n "$fail" ]] && { echo "  !! $fail"; continue; }

  python3 - "$OUT" "$MB" "$PERFILE" "$GCMS" "$LOOSE_N" "${loose[*]}" "|" "${packed[*]}" <<'PY'
import json,sys,statistics as st
out,mb,delta,gcms,loosen = sys.argv[1:6]
parts=[[],[]]; k=0
for tok in sys.argv[6:]:
    if tok=="|": k+=1; continue
    parts[k].extend(int(x) for x in tok.split())
loose,packed = parts
def stats(v):
    return {"n":len(v),"mean":round(st.mean(v),1),"median":st.median(sorted(v))} if v else None
d=json.load(open(out))
rec={"size_mb":int(mb),"delta_bytes":int(delta),"gc_ms":int(gcms),
     "loose_objects_before_gc":int(loosen),
     "pull_loose_ms":stats(loose),"pull_packed_ms":stats(packed)}
if loose and packed:
    rec["maintenance_speedup"]=round(st.mean(loose)/max(st.mean(packed),1e-9),3)
d["sizes"].append(rec); json.dump(d,open(out,"w"),indent=2)
print(f"  loose {rec['pull_loose_ms']['mean']} ms -> packed {rec['pull_packed_ms']['mean']} ms "
      f"(x{rec.get('maintenance_speedup')}), gc {gcms} ms, {loosen} loose objects")
PY
  rm -rf "$W" "$RD" "$BASE/$R.git"
done
echo "==> wrote $OUT"
