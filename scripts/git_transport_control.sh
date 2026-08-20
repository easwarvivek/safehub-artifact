#!/usr/bin/env bash
# How much of git's measured push cost is my HTTP wrapper rather than git?
#
# The parity sweep serves git through `scripts/git_http_server.py`, a threaded
# Python loop around the stock `git-http-backend` CGI. That was chosen so both
# arms speak HTTP — but Python per-request
# overhead is charged to git, and the sweep reports SafeHub pushing ~0.7x git.
# If most of that gap is the wrapper, the honest claim is parity, not a win.
#
# This brackets it by pushing the SAME commits over three transports:
#   http    - git-http-backend behind the Python loop  (what the sweep uses)
#   daemon  - git daemon, native git:// protocol       (no Python, leanest git)
#   local   - a bare repo on a filesystem path         (no network at all)
#
# `local` is the floor: it is what git costs with every transport removed. The
# http-vs-daemon gap is the wrapper penalty; the daemon-vs-local gap is the
# protocol itself.
#
# Env: CONTROL_DELTA_KB (default 1024), CONTROL_PUSHES (default 40)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODE="$ROOT/code"; [[ -d "$CODE/crates" ]] || CODE="$ROOT"
DELTA_KB="${CONTROL_DELTA_KB:-1024}"
PUSHES="${CONTROL_PUSHES:-40}"
OUT="${CONTROL_OUT:-$CODE/eval/published/git-transport-control.json}"

free_port() { python3 -c "
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"; }

WORK="$(mktemp -d /tmp/gitctl.XXXXXX)"
HTTP_PID=""; DAEMON_PID=""
cleanup() {
  [[ -n "$HTTP_PID"   ]] && kill -9 "$HTTP_PID"   2>/dev/null
  [[ -n "$DAEMON_PID" ]] && kill -9 "$DAEMON_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

# Same git determinism knobs the sweep pins, so this is comparable to it.
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

HTTP_PORT="$(free_port)"; GIT_PORT="$(free_port)"
BASE="$WORK/base"; mkdir -p "$BASE"

python3 "$ROOT/scripts/git_http_server.py" "$BASE" "$HTTP_PORT" >"$WORK/http.log" 2>&1 &
HTTP_PID=$!
git daemon --base-path="$BASE" --export-all --enable=receive-pack \
  --listen=127.0.0.1 --port="$GIT_PORT" --reuseaddr >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
sleep 1.5

for name in http daemon local; do
  git init --bare -q "$BASE/$name.git"
  git -C "$BASE/$name.git" config http.receivepack true
done
URL_http="http://127.0.0.1:$HTTP_PORT/http.git"
URL_daemon="git://127.0.0.1:$GIT_PORT/daemon.git"
URL_local="$BASE/local.git"

echo "==> ${PUSHES} pushes x ${DELTA_KB} KB over three transports"
# bash 3.2 (macOS) has no associative arrays; stash each series in a file.
for transport in http daemon local; do
  W="$WORK/w_$transport"; rm -rf "$W"; mkdir -p "$W"
  ( cd "$W" && git init -q --template= \
      && git config user.email ctl@safehub.local && git config user.name Ctl )
  eval "URL=\$URL_$transport"
  times=()
  fail=""
  for ((i=1; i<=PUSHES; i++)); do
    # Identical byte count each iteration; content differs per push, as in the sweep.
    python3 -c "
import os,sys
open(sys.argv[1],'wb').write(os.urandom(int(sys.argv[2])*1024))" "$W/f$i.bin" "$DELTA_KB"
    ( cd "$W" && git add -A && git commit -qm "d$i" >/dev/null 2>&1 )
    a=$(ms); ( cd "$W" && git push -q "$URL" HEAD ) >/dev/null 2>&1; rc=$?; b=$(ms)
    if [[ $rc -ne 0 ]]; then fail="push $i"; break; fi
    times+=("$((b-a))")
  done
  if [[ -n "$fail" ]]; then
    echo "  $transport: FAILED at $fail"; : > "$WORK/res_$transport"
  else
    printf '%s' "${times[*]}" > "$WORK/res_$transport"
    mean=$(python3 -c "
import sys,statistics as st
v=[int(x) for x in sys.argv[1].split()]
print(f'{st.mean(v):.1f}')" "${times[*]}")
    echo "  $transport: mean ${mean} ms over ${#times[@]} pushes"
  fi
done

mkdir -p "$(dirname "$OUT")"
python3 - "$OUT" "$DELTA_KB" "$PUSHES" "$(cat "$WORK/res_http" 2>/dev/null)" "|" \
    "$(cat "$WORK/res_daemon" 2>/dev/null)" "|" "$(cat "$WORK/res_local" 2>/dev/null)" <<'PY'
import json,sys,statistics as st
out,dkb,pushes = sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
parts=[[],[],[]]; k=0
for tok in sys.argv[4:]:
    if tok=="|": k+=1; continue
    parts[k].extend(int(x) for x in tok.split())
http,daemon,local = parts
def stats(v):
    if not v: return None
    return {"n":len(v),"mean":round(st.mean(v),1),"median":st.median(sorted(v)),
            "sum":sum(v)}
rec={"delta_kb":dkb,"pushes":pushes,
     "http":stats(http),"daemon":stats(daemon),"local":stats(local)}
if http and daemon:
    rec["wrapper_penalty_ms"]=round(st.mean(http)-st.mean(daemon),1)
    rec["wrapper_penalty_x"]=round(st.mean(http)/max(st.mean(daemon),1e-9),3)
if daemon and local:
    rec["protocol_penalty_ms"]=round(st.mean(daemon)-st.mean(local),1)
json.dump(rec,open(out,"w"),indent=2)
print(json.dumps({k:v for k,v in rec.items() if not isinstance(v,dict)},indent=2))
PY
echo "==> wrote $OUT"
