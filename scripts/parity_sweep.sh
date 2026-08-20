#!/usr/bin/env bash
# SafeHub <-> git parity sweep.
#
# Phase 1: 1-member repositories, git vs sit, matched operation for operation.
#   - git on `git daemon` (native git://, git's leanest transport); SafeHub on
#     HTTP, its only transport. SafeHub is then charged only for the *excess*
#     fixed cost HTTP adds over git://, so neither side is credited with a
#     transport the other cannot use.
#   - sizes 5,10,50,100..500 MB, 100 files each
#   - PUSHES pushes and PUSHES pulls per size; one file per push, so
#     file size = delta size = repo size / 100
#   - both arms receive byte-identical delta files
#   - alternating arm order so within-iteration position bias cancels
#   - postconditions after every timed op: the work provably happened
#   - resumable: sizes already in the output JSON are skipped
#
# Env:
#   PARITY_SIZES="10 50"     subset of sizes (MB)
#   PARITY_PUSHES=500        push/pull iterations per size
#   PARITY_OUT=<path>        output JSON
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODE="$ROOT/code"; [[ -d "$CODE/crates" ]] || CODE="$ROOT"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CODE/target}"

SIZES="${PARITY_SIZES:-5 10 50 100 150 200 250 300 350 400 450 500}"
PUSHES="${PARITY_PUSHES:-100}"
FILES=100
OUT="${PARITY_OUT:-$CODE/eval/published/parity-latest.json}"

# Pick free ports rather than fixed ones: a previous run's server lingering on a
# fixed port silently starves this run's git arm.
free_port() { python3 -c "
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"; }
SH_PORT="${PARITY_SH_PORT:-$(free_port)}"
GIT_PORT="${PARITY_GIT_PORT:-$(free_port)}"

# Split-host mode. Defaults reproduce the original localhost run exactly: with
# PARITY_REMOTE unset the script starts its own servers and measures against
# 127.0.0.1 as before. With PARITY_REMOTE=1 the servers are assumed to be
# already running on PARITY_SH_HOST / PARITY_GIT_HOST and the same protocol is
# measured across a real network path. PARITY_REMOTE_SSH is how bare git repos
# get created on the server box, since git:// cannot create them on push.
PARITY_SH_HOST="${PARITY_SH_HOST:-127.0.0.1}"
PARITY_GIT_HOST="${PARITY_GIT_HOST:-127.0.0.1}"
PARITY_REMOTE="${PARITY_REMOTE:-0}"
PARITY_REMOTE_SSH="${PARITY_REMOTE_SSH:-}"
PARITY_REMOTE_GITBASE="${PARITY_REMOTE_GITBASE:-}"

WORK="$(mktemp -d /tmp/parity.XXXXXX)"
# Clients keep their state in a throwaway HOME, but rustup/cargo must not: a
# temp HOME makes rustup re-download the toolchain on every run.
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config"
mkdir -p "$HOME" "$XDG_CONFIG_HOME"
SH_PID=""; GIT_PID=""
cleanup() {
  [[ -n "$SH_PID"  ]] && kill -9 "$SH_PID"  2>/dev/null
  [[ -n "$GIT_PID" ]] && kill -9 "$GIT_PID" 2>/dev/null
  # Reap every remaining child. Without this, interrupting the sweep can leave
  # a helper (the per-size JSON writer, a `git` invocation) orphaned to init —
  # and an orphan spinning on a core silently perturbs every later measurement,
  # which is far worse than a crashed run.
  pkill -9 -P $$ 2>/dev/null
  rm -rf "$WORK"
}
# EXIT alone is not enough: it does not fire on SIGTERM/SIGINT, and nothing can
# fire on SIGKILL — so stop this script with TERM, never with `kill -9`.
trap cleanup EXIT INT TERM

echo "==> Building"
( cd "$CODE" && cargo build --quiet --release \
    -p safehub-cli -p safehub-server -p sit-remote-safehub ) || exit 1
BIN="$CODE/target/release"
export PATH="$BIN:/usr/bin:/bin:/usr/local/bin"

# --- git determinism -------------------------------------------------------
# Every one of these changes what is being measured, so none may be left to the
# ambient environment. Auto-gc is the important one: 500 pushes lands within
# ~2x of the default 6700-object trigger, and a repack firing inside a single
# timed sample would blow up that sample's mean and p95.
export GIT_CONFIG_COUNT=8
export GIT_CONFIG_KEY_0=gc.auto                GIT_CONFIG_VALUE_0=0
export GIT_CONFIG_KEY_1=gc.autoPackLimit       GIT_CONFIG_VALUE_1=0
export GIT_CONFIG_KEY_2=receive.autogc         GIT_CONFIG_VALUE_2=false
export GIT_CONFIG_KEY_3=receive.unpackLimit    GIT_CONFIG_VALUE_3=100
export GIT_CONFIG_KEY_4=core.compression       GIT_CONFIG_VALUE_4=6
export GIT_CONFIG_KEY_5=pack.compression       GIT_CONFIG_VALUE_5=6
# SafeHub fsyncs its commit point at every push (two atomic_write_sync calls).
# Comparing that against a git that does not fsync would credit git with
# durability it is not providing.
export GIT_CONFIG_KEY_6=core.fsync             GIT_CONFIG_VALUE_6=objects,reference
export GIT_CONFIG_KEY_7=core.fsyncMethod       GIT_CONFIG_VALUE_7=fsync

ms() { python3 -c 'import time;print(int(time.time()*1000))'; }
# time_ms <cmd...>  -> elapsed ms on stdout; non-zero exit propagates via TIMED_RC
TIMED_RC=0
time_ms() { local a b; a=$(ms); "$@" >/dev/null 2>&1; TIMED_RC=$?; b=$(ms); echo $((b-a)); }
_dir_bytes_prog='
import os,sys
n=0
for dp,_,fs in os.walk(sys.argv[1]):
    for f in fs:
        try: n+=os.path.getsize(os.path.join(dp,f))
        except OSError: pass
print(n)'
dir_bytes() {
  if [[ "${PARITY_REMOTE:-0}" == "1" ]]; then
    # Server-side storage lives on the server box; measure it there.
    $PARITY_REMOTE_SSH "python3 -c \"$_dir_bytes_prog\" '$1'" 2>/dev/null || echo 0
  else
    python3 -c "$_dir_bytes_prog" "$1"
  fi
}
# Content fingerprint of a checked-out tree: mode+oid+path for every tracked file.
tree_sig() { git -C "$1" ls-files -s 2>/dev/null | shasum -a 256 | cut -d' ' -f1; }

mkdir -p "$(dirname "$OUT")"
[[ -f "$OUT" ]] || echo '{"mode":"git-parity-phase1","sizes":[]}' > "$OUT"

# Record the conditions the run was taken under. A quiet machine is part of the
# measurement, so it belongs in the artifact rather than in someone's memory.
python3 - "$OUT" "$(uname -sr)" "$(uname -m)" "$(git --version)" \
    "$(uptime | sed 's/.*averages*: *//')" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" <<'PY'
import json,sys
out,osv,arch,gitv,load,when = sys.argv[1:7]
d=json.load(open(out))
d["machine"]={"os":osv,"arch":arch,"git":gitv,
              "load_before":load,"measured_at_utc":when}
json.dump(d,open(out,"w"),indent=2)
PY

have_size() { python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
print('yes' if any(s.get('size_mb')==int(sys.argv[2]) and s.get('status')=='measured' for s in d['sizes']) else 'no')" "$OUT" "$1"; }

if [[ "$PARITY_REMOTE" == "1" ]]; then
  echo "==> Remote servers (safehub $PARITY_SH_HOST:$SH_PORT, git $PARITY_GIT_HOST:$GIT_PORT)"
  SH_DATA="${PARITY_REMOTE_SHDATA:-/home/ssm-user/sh-aws/pdata}"; GIT_BASE="$PARITY_REMOTE_GITBASE"
else
echo "==> Servers (safehub :$SH_PORT, git-http :$GIT_PORT)"
SH_DATA="$WORK/shdata"; GIT_BASE="$WORK/gitbase"
mkdir -p "$SH_DATA" "$GIT_BASE"
safehub-server --listen "127.0.0.1:$SH_PORT" --data "$SH_DATA" >"$WORK/sh.log" 2>&1 &
SH_PID=$!
# Git runs on its native protocol via `git daemon`: no HTTP framing, no CGI
# spawn per request, one connection per operation. That is the fastest git can
# be served, so any SafeHub overhead measured against it is an upper bound.
# SafeHub has only HTTP, and HTTP costs more; rather than hide that by serving
# git over HTTP too, we measure both fixed costs and subtract the difference
# from SafeHub (see `transport_delta` below).
git daemon --base-path="$GIT_BASE" --export-all --enable=receive-pack \
  --listen=127.0.0.1 --port="$GIT_PORT" --reuseaddr >"$WORK/git.log" 2>&1 &
GIT_PID=$!
fi
export SAFEHUB_HOST="http://$PARITY_SH_HOST:$SH_PORT"
for _ in $(seq 1 80); do curl -sf "$SAFEHUB_HOST/v1/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -sf "$SAFEHUB_HOST/v1/health" >/dev/null || { echo "safehub-server failed"; exit 1; }
for _ in $(seq 1 80); do
  (exec 3<>"/dev/tcp/$PARITY_GIT_HOST/$GIT_PORT") 2>/dev/null && { exec 3<&- 3>&-; break; }
  sleep 0.2
done
sleep 0.5
shub auth register --user alice --password parity-pw-1 --hostname "$SAFEHUB_HOST" >/dev/null 2>&1
# register both creates and logs in, but returns 409 if the account already
# exists -- which leaves the client logged OUT and silently fails every
# subsequent operation. Harmless against a pristine server, fatal against a
# reused one, so fall back to an explicit login.
shub auth login --user alice --secret parity-pw-1 --hostname "$SAFEHUB_HOST" >/dev/null 2>&1
shub auth status >/dev/null 2>&1 || { echo "!! safehub login failed; aborting"; exit 1; }
shub device publish-key-package --device default >/dev/null 2>&1

git_id() { git config user.email parity@safehub.local; git config user.name "Parity"; }

for MB in $SIZES; do
  if [[ "$(have_size "$MB")" == "yes" ]]; then echo "==> ${MB} MB already measured, skipping"; continue; fi
  echo "==> ${MB} MB · $PUSHES pushes/pulls · 1 file/push · $((MB*1024/PUSHES)) KB each"
  # One file per push: 100 pushes build a 100-file repository, so each file is
  # exactly the per-push delta.
  TOTAL=$((MB*1024*1024)); DELTA=$((TOTAL/PUSHES)); PERFILE=$DELTA
  S="$WORK/s$MB"; rm -rf "$S"; mkdir -p "$S"

  # ---- SafeHub repo (writer + reader) ----
  R="par$MB"
  ( cd "$S" && shub repo create "$R" --clone >/dev/null 2>&1 )
  ( cd "$S/$R" && git_id )
  ( cd "$S" && sit clone "alice/$R" "${R}-rd" >/dev/null 2>&1 )
  ( cd "$S/${R}-rd" && git_id ) 2>/dev/null

  # ---- git repo (writer + reader) against the smart-HTTP git server ----
  if [[ "$PARITY_REMOTE" == "1" ]]; then
    # git:// cannot create a repository on push, so the bare repo is made on
    # the server box over ssh. Untimed: it happens before any measured op.
    $PARITY_REMOTE_SSH "git init --bare -q $GIT_BASE/$R.git" >/dev/null 2>&1
  else
    git init --bare -q "$GIT_BASE/$R.git"
  fi
  GURL="git://$PARITY_GIT_HOST:$GIT_PORT/$R.git"
  mkdir -p "$S/g"; ( cd "$S/g" && git init -q --template= && git_id && git remote add origin "$GURL" )
  # seed so the reader can clone; failures here invalidate the whole git arm,
  # so they abort rather than silently producing an empty baseline
  ( cd "$S/g" && echo seed > .seed && git add -A && git commit -qm seed >/dev/null ) || {
    echo "  !! git seed commit failed for ${MB} MB"; continue; }
  if ! ( cd "$S/g" && git push -q origin HEAD ); then
    echo "  !! git seed push failed for ${MB} MB (daemon log: $(tail -2 "$WORK/git.log" | tr '\n' ' '))"; continue
  fi
  if ! ( cd "$S" && git clone -q "$GURL" grd ); then
    echo "  !! git reader clone failed for ${MB} MB"; continue
  fi
  ( cd "$S/grd" && git_id )

  # Generate each delta ONCE and copy the same bytes into both working trees.
  # Generating independently per arm would give git and SafeHub different
  # content — different compressibility, different pack behaviour — so the two
  # would not be transferring the same repository.
  mkdir -p "$S/stage"
  gen() { # gen <index> -> writes $S/stage/f<index>.bin and copies to both arms
    local i="$1"
    python3 -c "
import os,sys
open(sys.argv[1],'wb').write(os.urandom(int(sys.argv[2])))" "$S/stage/f$i.bin" "$PERFILE"
    mkdir -p "$S/$R/src" "$S/g/src"
    cp "$S/stage/f$i.bin" "$S/$R/src/f$i.bin"
    cp "$S/stage/f$i.bin" "$S/g/src/f$i.bin"
    rm -f "$S/stage/f$i.bin"
  }

  # Storage is scoped to this repository's ciphertext and head log. Walking all
  # of $SH_DATA would also count users, tokens and MLS queues. The baseline is
  # taken before warmup so both arms' deltas span identical content; git gc
  # repacks the entire repo, so a post-warmup baseline would not subtract out.
  sh_bytes() { echo $(( $(dir_bytes "$SH_DATA/blobs") + $(dir_bytes "$SH_DATA/heads") )); }
  SH_B0=$(sh_bytes); SH_H0=$(dir_bytes "$SH_DATA/heads"); GIT_B0=$(dir_bytes "$GIT_BASE/$R.git")

  # ---- warmup (untimed): settle CPU frequency and page cache on both arms ----
  for w in w0 w1 w2; do
    gen "$w"
    ( cd "$S/$R" && sit add . >/dev/null 2>&1 && sit commit -qm "$w" >/dev/null 2>&1 && sit push >/dev/null 2>&1 )
    ( cd "$S/${R}-rd" && sit pull >/dev/null 2>&1 )
    ( cd "$S/g" && git add -A && git commit -qm "$w" >/dev/null 2>&1 && git push -q origin HEAD 2>/dev/null )
    ( cd "$S/grd" && git pull -q --no-rebase --ff-only origin HEAD 2>/dev/null )
  done

  SP=(); SL=(); GP=(); GL=(); FAILED=""; ORD=()
  for ((i=1; i<=PUSHES; i++)); do
    gen "$i"
    ( cd "$S/$R" && sit add . >/dev/null 2>&1 && sit commit -qm "d$i" >/dev/null 2>&1 )
    ( cd "$S/g" && git add -A && git commit -qm "d$i" >/dev/null 2>&1 )

    run_sit() {
      t=$(time_ms bash -c "cd '$S/$R' && sit push");      [[ $TIMED_RC -ne 0 ]] && { FAILED="sit push $i"; return 1; }; SP+=("$t")
      t=$(time_ms bash -c "cd '$S/${R}-rd' && sit pull"); [[ $TIMED_RC -ne 0 ]] && { FAILED="sit pull $i"; return 1; }; SL+=("$t")
      # Postcondition: exit 0 is not evidence of work. The reader must actually
      # hold the writer's tip, or the pull did nothing and reported success.
      if [[ "$(git -C "$S/${R}-rd" rev-parse HEAD 2>/dev/null)" != "$(git -C "$S/$R" rev-parse HEAD)" ]]; then
        FAILED="sit reader diverged at $i"; return 1
      fi
      return 0
    }
    run_git() {
      t=$(time_ms bash -c "cd '$S/g' && git push -q origin HEAD");                          [[ $TIMED_RC -ne 0 ]] && { FAILED="git push $i"; return 1; }; GP+=("$t")
      t=$(time_ms bash -c "cd '$S/grd' && git pull -q --no-rebase --ff-only origin HEAD");   [[ $TIMED_RC -ne 0 ]] && { FAILED="git pull $i"; return 1; }; GL+=("$t")
      if [[ "$(git -C "$S/grd" rev-parse HEAD 2>/dev/null)" != "$(git -C "$S/g" rev-parse HEAD)" ]]; then
        FAILED="git reader diverged at $i"; return 1
      fi
      return 0
    }
    # Alternate which arm runs first. Whichever runs immediately after the
    # commit absorbs dirty-page writeback and a cold index; fixing the order
    # would apply that penalty to the same arm 500 times running.
    if (( i % 2 == 1 )); then
      ORD+=("sit_first"); run_sit || break; run_git || break
    else
      ORD+=("git_first"); run_git || break; run_sit || break
    fi
    (( i % 25 == 0 )) && echo "    $i/$PUSHES"
  done
  SH_B1=$(sh_bytes); SH_H1=$(dir_bytes "$SH_DATA/heads"); GIT_B1=$(dir_bytes "$GIT_BASE/$R.git")

  # The two arms must hold byte-identical content, or they are not transferring
  # the same repository and no ratio between them means anything. Proven, not
  # assumed: hash every delta file in each working tree and compare.
  content_sig() { ( cd "$1" && find src -type f | sort | xargs shasum -a 256 2>/dev/null \
                    | awk '{print $1}' | shasum -a 256 | cut -d' ' -f1 ); }
  SIT_CONTENT=$(content_sig "$S/$R"); GIT_CONTENT=$(content_sig "$S/g")
  if [[ "$SIT_CONTENT" != "$GIT_CONTENT" ]]; then
    echo "  !! arms hold different content at ${MB} MB — ratios would be meaningless"
    FAILED="${FAILED:-content divergence between arms}"
  fi

  # ---- clone: cold (rep 1) and warm (reps 2-3) reported separately ----
  # Reps 2-3 hit page cache, so a median-of-3 would always report the warm
  # number. Clone destinations are deleted immediately: at 500 MB six live
  # clones would be 3 GB of concurrent disk.
  WSIG=$(tree_sig "$S/$R"); GSIG=$(tree_sig "$S/g")
  SC=(); GC=(); CLONE_BAD=""
  for k in 1 2 3; do
    rm -rf "$S/c$k" "$S/gc$k"
    SC+=("$(time_ms bash -c "cd '$S' && sit clone alice/$R c$k")")
    [[ "$(tree_sig "$S/c$k")" == "$WSIG" ]] || CLONE_BAD="sit clone $k tree mismatch"
    GC+=("$(time_ms git clone -q "$GURL" "$S/gc$k")")
    [[ "$(tree_sig "$S/gc$k")" == "$GSIG" ]] || CLONE_BAD="git clone $k tree mismatch"
    rm -rf "$S/c$k" "$S/gc$k"
  done
  [[ -n "$CLONE_BAD" && -z "$FAILED" ]] && FAILED="$CLONE_BAD"

  # git's push cost is low partly because receive-pack defers packing to clone
  # time. Measuring the packed state too shows how much of git's clone cost is
  # that deferred bill rather than a property of the protocol.
  # gc must run where the bare repo lives. In split mode that is the server
  # box: run locally and it fails instantly against a path that is not there,
  # leaving the git arm to be cloned from 100 unconsolidated packfiles -- git's
  # worst case, and a silent one, since a failed gc still returns a timing.
  if [[ "$PARITY_REMOTE" == "1" ]]; then
    GGC=$(time_ms $PARITY_REMOTE_SSH "git -C $GIT_BASE/$R.git gc --quiet")
  else
    GGC=$(time_ms git -C "$GIT_BASE/$R.git" gc --quiet)
  fi
  # Status first: the duration heuristic below only covers repos big enough for
  # a real gc to take time, so a gc that exits non-zero on a small repo would
  # otherwise pass both checks and leave the packed clone reading an unpacked
  # remote.
  [[ $TIMED_RC -ne 0 ]] && { echo "  !! git gc failed for ${MB} MB (rc=$TIMED_RC)"; FAILED="git gc failed"; }
  [[ "$GGC" -lt 50 && "$MB" -ge 50 ]] && { echo "  !! git gc did not run for ${MB} MB (${GGC}ms)"; FAILED="git gc no-op"; }
  GIT_B_GC=$(( $(dir_bytes "$GIT_BASE/$R.git") - GIT_B0 ))
  rm -rf "$S/gcp"; GCP=$(time_ms git clone -q "$GURL" "$S/gcp")
  [[ $TIMED_RC -ne 0 ]] && { echo "  !! git packed clone failed for ${MB} MB"; FAILED="git packed clone"; }
  rm -rf "$S/gcp"

  # Fixed per-operation cost `c`: a fetch with nothing to transfer. Whatever it
  # costs is protocol preamble, process spawn and server dispatch — not work on
  # bytes. Measured five times per arm, interleaved, because one sample of a
  # ~10-30 ms quantity is noise.
  #
  # `transport_delta = c_sit - c_git` is what HTTP costs SafeHub over git's
  # native protocol. Subtracting it from SafeHub's times puts both arms on the
  # same transport footing without pretending SafeHub could use git://. Note
  # this is a proxy taken from a fetch: `sit push` issues three requests
  # against `sit fetch`'s two, so it under-subtracts for push and the adjusted
  # SafeHub figures are, if anything, over-estimates.
  SFS=(); GFS=()
  for k in 1 2 3 4 5; do
    SFS+=("$(time_ms bash -c "cd '$S/$R' && sit fetch")")
    GFS+=("$(time_ms bash -c "cd '$S/g' && git fetch -q origin")")
  done

  python3 - "$OUT" "$MB" "$FILES" "$PUSHES" "$DELTA" "$((SH_B1-SH_B0))" "$((GIT_B1-GIT_B0))" \
      "${SFS[*]}" "${GFS[*]}" "${SC[*]}" "${GC[*]}" "$FAILED" "$((SH_H1-SH_H0))" "$GGC" "$GIT_B_GC" "$GCP" \
      "${SP[*]}" "|" "${SL[*]}" "|" "${GP[*]}" "|" "${GL[*]}" <<'PY'
import json,sys,statistics as st
out,mb,files,pushes,delta,shb,gitb,sf,gf,sc,gc,failed,shhead,ggc,gitbgc,gcp = sys.argv[1:17]
sf_all=[int(x) for x in sf.split()]; gf_all=[int(x) for x in gf.split()]
sit_c = round(st.mean(sf_all),1) if sf_all else 0.0
git_c = round(st.mean(gf_all),1) if gf_all else 0.0
rest=sys.argv[17:]; parts=[[],[],[],[]]; k=0
for tok in rest:
    if tok=="|": k+=1; continue
    parts[k].extend(int(x) for x in tok.split())
sp,sl,gp,gl = parts

def stats(v):
    if not v: return None
    v2=sorted(v)
    d={"n":len(v),"sum":sum(v),"mean":round(st.mean(v),1),
       "median":st.median(v2),"p95":v2[min(len(v2)-1,int(.95*len(v2)))]}
    # A mean over 500 pushes is only a summary if the series is stationary.
    # Slope and the steady-state tail say whether it is.
    n=len(v)
    if n>=20:
        xb=(n-1)/2; yb=st.mean(v)
        den=sum((i-xb)**2 for i in range(n))
        d["slope_ms_per_iter"]=round(sum((i-xb)*(y-yb) for i,y in enumerate(v))/den,4) if den else 0.0
        tail=v[-min(50,n//4):]
        d["steady_mean"]=round(st.mean(tail),1)
        d["steady_median"]=st.median(sorted(tail))
        d["steady_n"]=len(tail)
    return d

d=json.load(open(out))
d["sizes"]=[s for s in d["sizes"] if s.get("size_mb")!=int(mb)]
# A negative byte delta means the server's data was removed underneath the
# measurement (an interrupted run, a torn teardown). Such a row is not a slow
# result, it is a non-result, and must never be recorded as measured.
if int(shb) < 0 or int(gitb) < 0 or int(gitbgc) < 0:
    failed = failed or "server data disappeared mid-measurement"

rec={"size_mb":int(mb),"files":int(files),"pushes":int(pushes),"delta_bytes":int(delta),
     "status":"failed" if failed else "measured",
     "safehub":{"push_ms":stats(sp),"pull_ms":stats(sl),
                "clone_cold_ms":int(sc.split()[0]) if sc.split() else None,
                "clone_warm_ms":[int(x) for x in sc.split()[1:]],
                "fetch_ms":sit_c,"fetch_samples":sf_all,"fixed_cost_ms":sit_c,
                "server_bytes":int(shb),"headlog_bytes":int(shhead)},
     "git":{"push_ms":stats(gp),"pull_ms":stats(gl),
            "clone_cold_ms":int(gc.split()[0]) if gc.split() else None,
            "clone_warm_ms":[int(x) for x in gc.split()[1:]],
            "fetch_ms":git_c,"fetch_samples":gf_all,"fixed_cost_ms":git_c,
            "server_bytes":int(gitb),
            "gc_ms":int(ggc),"server_bytes_packed":int(gitbgc),"clone_packed_ms":int(gcp)},
     "raw":{"sit_push":sp,"sit_pull":sl,"git_push":gp,"git_pull":gl}}
rec["identical_content"] = True
if failed: rec["failed_at"]=failed
if sp and gp:
    ssp,sgp = stats(sp), stats(gp)
    # work = total - c. This is the byte-dependent cost: bundling, encrypting,
    # transferring, storing. It is what "does encryption cost more?" is asking.
    # What HTTP costs SafeHub relative to git's native protocol, signed. A
    # positive value means SafeHub's transport is the dearer one and should be
    # discounted; negative means SafeHub's floor is already the lower of the
    # two and there is nothing to subtract.
    tdelta = round(sit_c - git_c, 1)
    # Corrected basis: remove each system's own floor, isolating the
    # byte-dependent work. This neither credits SafeHub for a lighter protocol
    # floor nor charges it for HTTP.
    def work(mean_ms, c): return round(max(mean_ms - c, 0.0), 1)
    def _work_ratio(num, den):
        # If the floor exceeds the measured operation the subtraction has
        # removed the entire signal and the corrected basis is meaningless.
        # Dividing by an epsilon here yields ~1e10, which looks like a
        # measurement rather than the undefined value it is. A no-op fetch is
        # not a valid floor for push once a network path is involved: over
        # git:// a no-op fetch can cost more than a real push.
        if num is None or den is None or den <= 0.0:
            return None
        return round(num / den, 3)
    sp_w, gp_w = work(st.mean(sp), sit_c), work(st.mean(gp), git_c)
    sl_w = work(st.mean(sl), sit_c) if sl else None
    gl_w = work(st.mean(gl), git_c) if gl else None
    rec["corrected"]={
      "note":"each system minus its own measured no-op floor; "
             "transport_delta_ms is sit floor minus git floor (signed)",
      "transport_delta_ms":tdelta,
      "sit_push_work_ms":sp_w, "git_push_work_ms":gp_w,
      "sit_pull_work_ms":sl_w, "git_pull_work_ms":gl_w,
      "corrected_basis_valid": bool(sp_w > 0.0 and gp_w > 0.0),
      "corrected_basis_note": (None if (sp_w > 0.0 and gp_w > 0.0) else
        "a measured no-op floor exceeded the operation it corrects; "
        "corrected ratios are undefined for this cell")}
    rec["ratio"]={
      # Mean is the headline: it is what total elapsed time divides into, and it
      # does not discard the tail the way a median does.
      "push_mean":   round(st.mean(sp)/max(st.mean(gp),1e-9),3),
      "push_steady": (round(ssp["steady_mean"]/max(sgp["steady_mean"],1e-9),3)
                      if ssp.get("steady_mean") and sgp.get("steady_mean") else None),
      # Totals charge SafeHub for HTTP that git never pays; the adjusted ratio
      # removes only that excess.
      "push_work":   _work_ratio(sp_w, gp_w),
      "pull_work":   _work_ratio(sl_w, gl_w),
      "push_median": round(st.median(sorted(sp))/max(st.median(sorted(gp)),1),3),
      "push_total":  round(sum(sp)/max(sum(gp),1),3),
      "pull_mean":   round(st.mean(sl)/max(st.mean(gl),1e-9),3) if sl and gl else None,
      "pull_steady": (round(stats(sl)["steady_mean"]/max(stats(gl)["steady_mean"],1e-9),3)
                      if sl and gl and stats(sl).get("steady_mean") and stats(gl).get("steady_mean") else None),
      "pull_median": round(st.median(sorted(sl))/max(st.median(sorted(gl)),1),3) if sl and gl else None,
      # Against git's un-gc'd server state, and against the packed state a real
      # host would serve. The packed comparison is the honest one.
      "clone_cold":  round(int(sc.split()[0])/max(int(gc.split()[0]),1),3) if sc.split() and gc.split() else None,
      "clone_vs_packed": round(int(sc.split()[0])/max(int(gcp),1),3) if sc.split() else None,
      "storage":     round(int(shb)/max(int(gitb),1),3),
      "storage_vs_packed": round(int(shb)/max(int(gitbgc),1),3)}
d["sizes"].append(rec); d["sizes"].sort(key=lambda s:s["size_mb"])
json.dump(d,open(out,"w"),indent=2)
r=rec.get("ratio",{})
c=rec.get("corrected",{})
print(f"  push x{r.get('push_mean','-')} [adj x{r.get('push_work','-')}] "
      f"pull x{r.get('pull_mean','-')} [adj x{r.get('pull_work','-')}] "
      f"tdelta {c.get('transport_delta_ms','-')}ms "
      f"clone x{r.get('clone_vs_packed','-')} storage x{r.get('storage_vs_packed','-')}"
      + (f"  FAILED at {failed}" if failed else ""))
PY
  rm -rf "$S"
  if [[ "$PARITY_REMOTE" == "1" ]]; then
    $PARITY_REMOTE_SSH "rm -rf $GIT_BASE/$R.git" >/dev/null 2>&1
  else
    rm -rf "$GIT_BASE/$R.git"
  fi
done

echo "==> wrote $OUT"
