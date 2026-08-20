#!/usr/bin/env bash
# Host-visible leakage capture + simple distinguishing games + padding cost.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${SAFEHUB_LEAKAGE_OUT:-$ROOT/code/eval/scaffold/leakage-latest.json}"
python3 - <<PY
import json, time, hashlib, os
from datetime import datetime, timezone
out = os.environ.get("SAFEHUB_LEAKAGE_OUT", "$OUT")
# Synthetic host-visible trace — scaffold only (see eval/scaffold/README.md).
events = []
for i, size in enumerate([1200, 4096, 4*1024*1024, 8200, 4*1024*1024]):
    events.append({
        "t": i * 0.05,
        "op": "put_blob" if size > 10000 else "append_head",
        "ciphertext_size": size,
        "repo_id_hash": hashlib.sha256(b"demo-repo").hexdigest()[:16],
        "auth_device": "dev0",
        "seq": i,
    })
known = [1200, 4096, 8200]
guess = max(known, key=lambda s: -abs(s - events[0]["ciphertext_size"]))
attack = {
    "game": "distinguish_known_commit_size",
    "k": len(known),
    "guess": guess,
    "correct": guess == 1200,
    "advantage_note": "honest size leakage alone wins this game without ciphertext content",
}
def bucket(n, b=65536):
    return ((n + b - 1) // b) * b
pad_overhead = sum(bucket(e["ciphertext_size"]) - e["ciphertext_size"] for e in events)
doc = {
    "trace_events": events,
    "inference": [attack],
    "countermeasures": [{
        "name": "size_bucketing_64KiB",
        "extra_bytes": pad_overhead,
        "latency_cost_note": "upload bytes increase; RTT count unchanged",
    }, {
        "name": "delayed_batching",
        "latency_cost_note": "adds cover delay; reduces timing/timezone inference",
    }, {
        "name": "cover_pushes",
        "bandwidth_cost_note": "periodic dummy ciphertext of bucketed size",
    }],
    "status": "scaffold",
    "generated_at": datetime.now(timezone.utc).isoformat(),
}
os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
open(out, "w").write(json.dumps(doc, indent=2))
print("wrote", out)
PY
