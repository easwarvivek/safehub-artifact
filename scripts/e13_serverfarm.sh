#!/usr/bin/env bash
# Server side of a split-host E13 sweep. Run on the benchmark host.
#
# One smart-HTTP git server carries every arm's git traffic; repository names are
# namespaced per lane so lanes cannot collide. Each lane additionally gets its
# own SafeHub server and control service, because /safehub/size reports a whole
# data directory: lanes sharing one would each read the other's growth as their
# own.
#
# Ports, per lane N (1-based):  safehub 18190+2N, control 18191+2N
# Shared:                       git-http 18191
set -uo pipefail
T="${SAFEHUB_TREE:-$HOME/safehub}"
BASE="${SAFEHUB_E13_SRV:-$HOME/e13srv}"
LANES="${SAFEHUB_E13_LANES:-4}"
IP=$(hostname -I | awk '{print $1}')

pkill -f "git_http_server.py"     2>/dev/null || true
pkill -f "e13_remote_service.py"  2>/dev/null || true
pkill -f "safehub-server --listen 0.0.0.0" 2>/dev/null || true
sleep 1
rm -rf "$BASE"; mkdir -p "$BASE/repos"

nohup python3 "$T/scripts/git_http_server.py" "$BASE/repos" 18191 0.0.0.0 \
  >"$BASE/githttp.log" 2>&1 &

for n in $(seq 1 "$LANES"); do
  sh_port=$((18190 + 2*n)); svc_port=$((18191 + 2*n))
  mkdir -p "$BASE/data-l$n"
  nohup "$T/code/target/release/safehub-server" --listen "0.0.0.0:$sh_port" \
    --data "$BASE/data-l$n" >"$BASE/sh-l$n.log" 2>&1 &
  nohup python3 "$T/scripts/e13_remote_service.py" "$BASE/repos" "$BASE/data-l$n" \
    "$svc_port" 0.0.0.0 >"$BASE/svc-l$n.log" 2>&1 &
done
sleep 3

echo "server host $IP, $LANES lane(s)"
printf "  git-http  :18191  %s\n" \
  "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:18191/none.git/info/refs?service=git-upload-pack")"
for n in $(seq 1 "$LANES"); do
  sh_port=$((18190 + 2*n)); svc_port=$((18191 + 2*n))
  printf "  lane %s: safehub :%s %s   control :%s %s\n" "$n" \
    "$sh_port" "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$sh_port/v1/health)" \
    "$svc_port" "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$svc_port/health)"
done
