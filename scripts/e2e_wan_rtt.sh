#!/usr/bin/env bash
# Eval E06 — WAN / RTT validation of push_round_trips = 2 + ceil(n/P).
# Publishes: code/eval/published/wan-fullstack-latest.json
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/gen_wan_fullstack_latest.py"
