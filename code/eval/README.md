# SafeHub eval harness

Integration timing driver and fixture generator. Published JSON used by the
paper lives in [`published/`](./published/). Schema: [`schema.json`](./schema.json).

## Machine / transport note

Publish timed cells with a `meta` block (machine, date, reps, method).

| Field | Typical value |
|-------|---------------|
| CPU | Apple Silicon (`arm64`; pin with `SAFEHUB_EVAL_CPU`) |
| RAM | from `sysctl hw.memsize` (`meta.machine_detail.ram_gib`) |
| Storage | local SSD; override with `SAFEHUB_EVAL_STORAGE` |
| Transport AEAD | `hkdf-sha512-pad+HMAC-SHA-512-256` (`CommittingAead`) |
| Hardware AES | unused on the application transport hot path |

MLS still uses its own ciphersuite AEAD independently.

## Locked axes

| Axis | Values |
|------|--------|
| Size sweep | 8, 10, 12 MiB (full-stack `sit://` + plain-git baseline) |
| Join sweep | n ∈ {10,20,…,100} |
| Security scenarios | S1–S11 (`attack-scenarios-latest.json`) |

Smoke mode uses a reduced fixture (~20 files / 1 MiB) for CI.

Additive large-repo axis (does not replace locked sweeps): 100 / 200 MiB,
~1000 files, 8 sequential pushes — `SAFEHUB_SKIP_RTT=1 ./scripts/e2e_additive_scale.sh`.

## Published JSON regeneration

Prefer fast generators; optional `SAFEHUB_*_MODE=e2e` paths start a local server.

| Artifact | Regeneration |
|----------|----------------|
| `published/smoke-latest.json` | `cd code && cargo run -p safehub-eval --release -- --mode smoke` |
| `published/fullstack-latest.json` / `full-latest.json` | `./scripts/e2e_eval.sh` |
| `published/additive-scale-latest.json` | `SAFEHUB_SKIP_RTT=1 ./scripts/e2e_additive_scale.sh` |
| `published/concurrency-latest.json` | `./scripts/e2e_concurrency.sh` |
| `published/parity-latest.json` | `./scripts/parity_sweep.sh` |
| `published/realrepo-scale-latest.json` | `python3 scripts/gen_realrepo_scale_latest.py` or `./scripts/e2e_realrepo_scale.sh` |
| `published/depth-delta-latest.json` | `python3 scripts/gen_depth_delta_latest.py` or `SAFEHUB_DD_MODE=e2e ./scripts/e2e_depth_delta_sweep.sh` |
| `published/depth-clone-latest.json` | `python3 scripts/gen_depth_clone_latest.py` |
| `published/wan-fullstack-latest.json` | `python3 scripts/gen_wan_fullstack_latest.py` or `./scripts/e2e_wan_rtt.sh` |
| `published/encrypted-git-baseline-latest.json` | `python3 scripts/gen_encrypted_git_baseline_latest.py` |
| `published/design-costs-latest.json` | `python3 scripts/gen_design_costs_latest.py` |
| `published/per-invite-latest.json` | `python3 scripts/gen_per_invite_latest.py` |
| `published/vcs-workload-latest.json` | `python3 scripts/gen_vcs_workload_latest.py` |
| `published/attack-scenarios-latest.json` | `python3 scripts/gen_attack_scenarios_latest.py` |
| `published/collab-slice-latest.json` | `python3 scripts/gen_collab_slice_latest.py` |
| `published/import-timing-latest.json` | `python3 scripts/gen_import_timing_latest.py` |

Refresh fast generators in one shot:

```bash
./scripts/gen_all_eval.sh
```

Helpers: `scripts/lib/eval_common.sh`, `scripts/lib/eval_publish.py`.

## Run

```bash
./scripts/e2e_eval.sh
# or:
cd code && cargo run -p safehub-eval --release -- --mode full-stack
```

Environment: `RUSTUP_TOOLCHAIN=stable`, `CARGO_TARGET_DIR=$PWD/target`,
`SAFEHUB_EVAL_PROFILE=release`, `SAFEHUB_EVAL_REPS=5` (dispersion; no unlabeled N=1 cells).

## Result labels

| Label | Meaning |
|-------|---------|
| `measured` | Wall-clock or calibrated microbench on this machine |
| `model` | Analytical model anchored to measured rates/constants |
| `extrapolated` | Model beyond the measured regime (e.g. depth 10⁴) |
| `design-enforced` | Protocol/design outcome; timing optional |
| `analytic` | Threat/deployment analysis without an E2E cell |

Every timed cell carries median+IQR (or mean+95% CI) over `reps ≥ 2`.

## Quiet-host hygiene

Before timed generators / e2e sweeps, confirm no leftover `safehub-server`,
`safehub-browse`, or `safehub-local-ui` listeners and no competing harness
builds. Generators set `meta.quiet_host=true` by default
(`SAFEHUB_EVAL_QUIET_HOST` in `scripts/lib/eval_publish.py`).

## Tests

```bash
cargo test -p safehub-eval
```
