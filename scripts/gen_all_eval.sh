#!/usr/bin/env bash
# Master runner: regenerate all published JSON artifacts under code/eval/published/ (fast path).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Ensure smoke microtimings exist for AEAD anchors.
if [[ ! -f code/eval/published/smoke-latest.json ]]; then
  echo "==> refreshing smoke-latest.json for AEAD micro anchor"
  (cd code && cargo run -p safehub-eval --release -- --mode smoke --out eval/results/tmp-smoke-eval)
fi

SCRIPTS=(
  gen_depth_delta_latest.py
  gen_depth_clone_latest.py
  gen_realrepo_scale_latest.py
  gen_wan_fullstack_latest.py
  gen_encrypted_git_baseline_latest.py
  gen_design_costs_latest.py
  gen_per_invite_latest.py
  gen_vcs_workload_latest.py
  gen_attack_scenarios_latest.py
  gen_collab_slice_latest.py
  gen_import_timing_latest.py
)

for s in "${SCRIPTS[@]}"; do
  echo "==> $s"
  python3 "scripts/$s"
done

echo "==> all published JSON artifacts refreshed"
ls -1 code/eval/published/*-latest.json
