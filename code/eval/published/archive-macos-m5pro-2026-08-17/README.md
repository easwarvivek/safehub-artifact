# Archived published artifacts — macOS / Apple M5 Pro run

Snapshot of `code/eval/published/*.json` as they stood before the AWS
re-measurement, taken 2026-08-18. These are the numbers the paper text was
written against.

Provenance: macOS aarch64, Apple M5 Pro, localhost (client and server on one
machine), rustc 1.97.1.

Kept for comparison against the AWS Graviton4 split-host re-run. Do not edit;
regenerate nothing into this directory.

Note on the SafeHub CLI: `parity_sweep.sh` invoked a binary named `sh`, which no
cargo target produces. The copy in `code/target/release/sh` at the time of these
runs was built 2026-08-16 (md5 e73810d33acfc853d9ef048806cb88a4) while `shub`
was rebuilt 2026-08-17, so these parity numbers were produced with a stale CLI.
The release copy was replaced by a symlink to `shub` on 2026-08-18; the
corresponding debug build survives at `code/target/debug/sh`.
