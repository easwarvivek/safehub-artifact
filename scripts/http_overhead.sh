#!/usr/bin/env bash
# What does HTTP actually cost SafeHub, relative to git's native protocol?
#
# The parity sweep serves git over `git daemon` (git://) and SafeHub over HTTP,
# because those are the transports each system actually has. To compare the
# constructions rather than the transports, we need the transport difference as
# a measured number -- and it has to be stable, or every corrected figure
# inherits its noise.
#
# A whole-client timing (`sit fetch` vs `git fetch`) does not isolate transport:
# it also contains process spawn, config load, MLS epoch material load, and ref
# negotiation, which differ between the systems for reasons unrelated to HTTP.
# So each cost is measured separately and the transport term is derived:
#
#   per-request HTTP round trip   one curl process issuing N requests, so the
#                                 curl spawn is amortised to nearly zero
#   client spawn floor            `sit --version` / `git --version`
#   no-op operation               `sit fetch` / `git ls-remote` with nothing to do
#
#   sit transport  ~= (sit no-op)      - (sit spawn)
#   git transport  ~= (git ls-remote)  - (git spawn)
#   delta          =  sit transport    -  git transport
#
# Stability is demonstrated rather than asserted: every quantity is measured in
# BATCHES independent batches and the between-batch spread is reported. A number
# whose batches disagree is not fit to correct anything with.
#
# Env: OV_REQS (default 200), OV_BATCHES (default 5), OV_REPS (default 30)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODE="$ROOT/code"; [[ -d "$CODE/crates" ]] || CODE="$ROOT"
REQS="${OV_REQS:-200}"      # HTTP requests per curl invocation
BATCHES="${OV_BATCHES:-5}"  # independent batches, for the stability check
REPS="${OV_REPS:-30}"       # repetitions of each per-process measurement
OUT="${OV_OUT:-$CODE/eval/published/http-overhead.json}"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CODE/target}"
BIN="$CODE/target/release"

free_port() { python3 -c "
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"; }

WORK="$(mktemp -d /tmp/ovh.XXXXXX)"
REAL_HOME="$HOME"
SH_PID=""; GIT_PID=""
cleanup() {
  [[ -n "$SH_PID"  ]] && kill -9 "$SH_PID"  2>/dev/null
  [[ -n "$GIT_PID" ]] && kill -9 "$GIT_PID" 2>/dev/null
  pkill -9 -P $$ 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

export HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config"
mkdir -p "$HOME" "$XDG_CONFIG_HOME"
export PATH="$BIN:/usr/bin:/bin:/usr/local/bin"

ms() { python3 -c 'import time;print(int(time.time()*1000))'; }
# us_of <n> <cmd...> : run cmd n times, print mean microseconds per run
us_of() {
  local n="$1"; shift
  local a b; a=$(python3 -c 'import time;print(time.time())')
  for ((k=0;k<n;k++)); do "$@" >/dev/null 2>&1; done
  b=$(python3 -c 'import time;print(time.time())')
  python3 -c "print(round((($b)-($a))*1e6/$n,1))"
}

SH_PORT="$(free_port)"; GIT_PORT="$(free_port)"
SH_DATA="$WORK/shdata"; GIT_BASE="$WORK/gitbase"
mkdir -p "$SH_DATA" "$GIT_BASE"

safehub-server --listen "127.0.0.1:$SH_PORT" --data "$SH_DATA" >"$WORK/sh.log" 2>&1 &
SH_PID=$!
git daemon --base-path="$GIT_BASE" --export-all --enable=receive-pack \
  --listen=127.0.0.1 --port="$GIT_PORT" --reuseaddr >"$WORK/git.log" 2>&1 &
GIT_PID=$!
export SAFEHUB_HOST="http://127.0.0.1:$SH_PORT"
for _ in $(seq 1 80); do curl -sf "$SAFEHUB_HOST/v1/health" >/dev/null 2>&1 && break; sleep 0.2; done
for _ in $(seq 1 80); do
  (exec 3<>"/dev/tcp/127.0.0.1/$GIT_PORT") 2>/dev/null && { exec 3<&- 3>&-; break; }
  sleep 0.2
done

# A repository on each side, with one commit, so the no-op operations are real.
sh auth register --user ovh --password ovh-pw-12345 --hostname "$SAFEHUB_HOST" >/dev/null 2>&1
sh device publish-key-package --device default >/dev/null 2>&1
( cd "$WORK" && sh repo create ovh --clone >/dev/null 2>&1 )
( cd "$WORK/ovh" && git config user.email ovh@safehub.local && git config user.name Ovh \
   && echo x > a.txt && sit add . >/dev/null 2>&1 && sit commit -qm c1 >/dev/null 2>&1 \
   && sit push >/dev/null 2>&1 )
git init --bare -q "$GIT_BASE/ovh.git"
GURL="git://127.0.0.1:$GIT_PORT/ovh.git"
( cd "$WORK" && rm -rf g && git init -q --template= g && cd g \
   && git config user.email ovh@safehub.local && git config user.name Ovh \
   && echo x > a.txt && git add -A && git commit -qm c1 >/dev/null 2>&1 \
   && git push -q "$GURL" HEAD >/dev/null 2>&1 )

# Warm both paths so the first batch is not measuring cold caches.
for _ in 1 2 3; do
  curl -s -o /dev/null "$SAFEHUB_HOST/v1/health"
  ( cd "$WORK/ovh" && sit fetch ) >/dev/null 2>&1
  git ls-remote "$GURL" >/dev/null 2>&1
done

echo "==> $BATCHES batches: $REQS HTTP requests, $REPS reps of each process measure"
HTTP_B=(); SITSPAWN_B=(); SITNOOP_B=(); GITSPAWN_B=(); GITLS_B=()
for ((b=1;b<=BATCHES;b++)); do
  # Per-request HTTP cost: ONE curl process issues $REQS requests, so the curl
  # spawn is divided by $REQS and what remains is connection + request + server
  # dispatch. This is the quantity the whole correction rests on.
  # -o applies per URL, so give curl one sink per request rather than letting
  # the remaining responses fall to stdout.
  urls=""; for ((k=0;k<REQS;k++)); do urls="$urls -o /dev/null $SAFEHUB_HOST/v1/health"; done
  a=$(python3 -c 'import time;print(time.time())')
  curl -s $urls >/dev/null 2>&1
  bb=$(python3 -c 'import time;print(time.time())')
  HTTP_B+=("$(python3 -c "print(round((($bb)-($a))*1e6/$REQS,1))")")

  SITSPAWN_B+=("$(us_of "$REPS" sit --version)")
  SITNOOP_B+=("$(us_of "$REPS" bash -c "cd '$WORK/ovh' && sit fetch")")
  GITSPAWN_B+=("$(us_of "$REPS" git --version)")
  GITLS_B+=("$(us_of "$REPS" git ls-remote "$GURL")")
  echo "    batch $b/$BATCHES"
done

mkdir -p "$(dirname "$OUT")"
python3 - "$OUT" "$REQS" "$BATCHES" "$REPS" \
    "${HTTP_B[*]}" "|" "${SITSPAWN_B[*]}" "|" "${SITNOOP_B[*]}" "|" \
    "${GITSPAWN_B[*]}" "|" "${GITLS_B[*]}" <<'PY'
import json,sys,statistics as st
out,reqs,batches,reps = sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4])
parts=[[],[],[],[],[]]; k=0
for tok in sys.argv[5:]:
    if tok=="|": k+=1; continue
    parts[k].extend(float(x) for x in tok.split())
http,sitspawn,sitnoop,gitspawn,gitls = parts

def summarise(v, label):
    m=st.mean(v); sd=st.stdev(v) if len(v)>1 else 0.0
    return {"label":label,"batches":len(v),"mean_us":round(m,1),
            "sd_us":round(sd,1),"spread_pct":round(100*sd/m,2) if m else None,
            "min_us":round(min(v),1),"max_us":round(max(v),1),
            "samples_us":[round(x,1) for x in v]}

rec={"requests_per_batch":reqs,"batches":batches,"reps_per_batch":reps,
     "http_request_us":summarise(http,"one HTTP round trip to safehub-server"),
     "sit_spawn_us":summarise(sitspawn,"sit process spawn"),
     "sit_noop_fetch_us":summarise(sitnoop,"sit fetch, nothing to transfer"),
     "git_spawn_us":summarise(gitspawn,"git process spawn"),
     "git_lsremote_us":summarise(gitls,"git ls-remote over git://")}

sit_tx = st.mean(sitnoop)-st.mean(sitspawn)
git_tx = st.mean(gitls)-st.mean(gitspawn)
rec["derived"]={
  "note":"transport = no-op operation minus that client's process spawn",
  "sit_transport_us":round(sit_tx,1),
  "git_transport_us":round(git_tx,1),
  "delta_us":round(sit_tx-git_tx,1),
  "delta_ms":round((sit_tx-git_tx)/1000,2),
  "interpretation":("positive: SafeHub's transport is dearer and should be "
                    "discounted; negative: SafeHub's is already the cheaper")}
json.dump(rec,open(out,"w"),indent=2)
for key in ("http_request_us","sit_spawn_us","sit_noop_fetch_us","git_spawn_us","git_lsremote_us"):
    s=rec[key]
    print(f"  {s['label']:<42} {s['mean_us']/1000:8.2f} ms  +/- {s['sd_us']/1000:5.2f} "
          f"({s['spread_pct']}% spread)")
d=rec["derived"]
print(f"\n  sit transport   {d['sit_transport_us']/1000:.2f} ms")
print(f"  git transport   {d['git_transport_us']/1000:.2f} ms")
print(f"  delta           {d['delta_ms']:+.2f} ms  (positive = SafeHub dearer)")
PY
echo "==> wrote $OUT"
