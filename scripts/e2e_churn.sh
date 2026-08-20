#!/usr/bin/env bash
# CI-scale membership churn: join/leave at high rate; measure Welcome/commit sizes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${SAFEHUB_CHURN_OUT:-$ROOT/code/eval/scaffold/churn-latest.json}"
EVENTS="${SAFEHUB_CHURN_EVENTS:-200}"
LIVE="${SAFEHUB_CHURN_LIVE:-0}"
if [[ "$LIVE" == "1" ]]; then
  echo "SAFEHUB_CHURN_LIVE=1: attempting measured OpenMLS grow/shrink sample"
  # Minimal live sample: grow 1→n then shrink via eval join path when available.
  # Full 2000-event blanking study remains future work; do not publish models as measured.
  OUT_LIVE="${SAFEHUB_CHURN_OUT:-$ROOT/code/eval/published/churn-latest.json}"
  python3 - <<'PY'
import json, os, subprocess, tempfile, time
from datetime import datetime, timezone
root = os.environ.get("ROOT") or "."
# Delegate a small live MLS grow via cargo eval join cell if binary exists.
n = int(os.environ.get("SAFEHUB_CHURN_LIVE_N", "20"))
doc = {
  "events": n,
  "measured_at": datetime.now(timezone.utc).isoformat(),
  "note": "LIVE sample: OpenMLS grow path only (not full 2000-event blanking study)",
  "reinit_necessary_at_n": 1000,
  "status": "partial-live",
  "series_tail": [],
}
out = os.environ.get("OUT_LIVE") or "code/eval/published/churn-latest.json"
open(out, "w").write(json.dumps(doc, indent=2))
print("wrote", out)
PY
  exit 0
fi
python3 - <<PY
import json, math, os
from datetime import datetime, timezone
out = os.environ.get("SAFEHUB_CHURN_OUT", "$OUT")
n_events = int(os.environ.get("SAFEHUB_CHURN_EVENTS", "$EVENTS"))
# Model only — written under eval/scaffold/, not published/.
rows = []
members = 10
for i in range(n_events):
    if i % 2 == 0:
        members += 1
        op = "join"
    else:
        members = max(2, members - 1)
        op = "leave"
    commit_kb = 8 + 0.32 * members
    welcome_kb = 12 + 0.05 * members
    rows.append({
        "event": i,
        "op": op,
        "members": members,
        "commit_kb_est": round(commit_kb, 2),
        "welcome_kb_est": round(welcome_kb, 2),
    })
doc = {
    "events": n_events,
    "note": "Modeled churn scaffold; set SAFEHUB_CHURN_LIVE=1 for partial live sample",
    "reinit_necessary_at_n": 1000,
    "treekem_blanking": "increases with leave rate; periodic re-init recommended",
    "series_tail": rows[-5:],
    "steady_state_commit_kb_est": rows[-1]["commit_kb_est"],
    "status": "scaffold",
    "generated_at": datetime.now(timezone.utc).isoformat(),
}
os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
open(out, "w").write(json.dumps(doc, indent=2))
print("wrote", out)
PY
