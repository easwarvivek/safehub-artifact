# E13 — results that are complete and verified

Collected 2026-08-19 from the split client/server sweep. **Only experiments that
ran to completion with zero failed cells are here.** What is missing is missing
on purpose; see "Not included" below.

## Provenance

| | |
|---|---|
| architecture | clients and remotes on **separate machines** |
| server | bench-1 (`c8g.8xlarge`, 32 vCPU): `git-http-backend` for git/git-crypt/gcrypt/sgit, `safehub-server` for SafeHub, one control service per client for repo creation and sizing |
| clients | bench-2 (A3, D) and bench-3 (A1, A2), same instance type and AZ |
| RTT client→server | 0.088 ms (bench-2), 0.166 ms (bench-3) |
| transport | **every arm over HTTP.** No arm uses `file://` |
| repetitions | 5 per cell; gcrypt 3 (recorded per cell, never averaged across) |
| source parity | all 190 source files byte-identical across local, bench-2, bench-3 |

Arms: `git`, `git-crypt`, `git-remote-gcrypt`, `SafeHub`, `SGitChar`, `SGitLine`.
The last two are our reimplementation — no artifact was published for that
system — built as a real Git add-on pushing a ciphertext mirror to an ordinary
remote.

## Included

| file | experiment | points | cells | metric |
|---|---|---|---|---|
| `e13-A1-delta.json` | update vs size of new content | 5 KiB … 3 MiB | 36 | time, wire bytes, storage growth |
| `e13-A2-filesz.json` | update vs file size, fixed 1 KiB edit | 10 KiB … 8 MiB | 30 | time, wire bytes, storage growth |
| `e13-A3-nfiles.json` | update vs number of files touched | 1 … 100 | 30 | time, wire bytes, storage growth |
| `e13-D-updates.json` | storage vs number of versions | 10 … 100 | 24 | storage growth per version |

`*-rows.jsonl` holds the raw per-cell rows behind each artifact, including
retained samples, so a cell can be topped up later without re-running the rest.

## How to read the byte columns

Three different quantities, not interchangeable:

- **`wire_bytes_per_update`** — the thin pack a push actually put on the wire,
  computed against the remote tip *before* the push. Defined only where the
  transport is an ordinary Git push; `null` for gcrypt and SafeHub, which do not
  expose a readable ref map. Do not read `null` as zero.
- **`remote_growth_per_update`** — what the remote's storage gained, repacked at
  both ends. Defined for every arm.
- **`bytes_changed`** — the plaintext payload the edit actually altered.

## Caveats that matter

**D's `stored_bytes` is unusable for SafeHub; use `stored_growth_per_version`.**
SafeHub's server keeps one store shared by every repository — `blobs/`, `heads/`
and `blobmeta/` are global, not per repository — so a directory measurement is a
running total for the whole run, while every git-family arm gets a fresh bare
repository per point. D's growth column is a difference taken within a point, so
the accumulation cancels; it is flat across all four points (git 4.6→4.7 kB,
SGitChar 52.8→52.8 kB), which is what a correct per-version measure looks like.
The absolute column for SafeHub climbs 6.1→10.3 MB and means nothing per point.
The harness now records growth for every arm; D predates that change.

**A3's 100-file point is anomalous and should not be used until explained.**
Going 50→100 files should roughly double the cost. Instead git's wire bytes go
16 kB→106 kB, SGitChar's 44 kB→1.08 MB, and SafeHub's storage growth
22 kB→391 kB. Several arms jump together, which points at something in the
harness or in Git's packing at that size rather than at any one design. Every
other point in A3 scales as expected.

**Cells do not share an n.** gcrypt runs at 3 repetitions, the rest at 5. Each
cell records its own `n`, so any ratio spans two.

## Not included, and why

- **B (repository size), C (history depth), E (revisions of one file)** — the
  runs were stopped part way. B has points 5 and 25 measured, C has 10 and a
  partial 100. Fragments are not published.
- **The bench-1 validation run** (all seven experiments, one point each) — it
  ran single-box, where every arm used `file://` except SafeHub, which spoke
  HTTP to a server sharing its CPU. That penalised SafeHub twice, so its timings
  are not comparable across arms. It did its job as a validation and is
  superseded.
- **Anything measured before the SGitChar serialiser fix.** A bare character LCS
  without `diff_match_patch`'s cleanup, plus JSON-encoded delta blocks, inflated
  SGitChar's transmitted bytes 6.6× — an artefact of our reimplementation, not a
  property of their design. Everything here postdates that fix.
