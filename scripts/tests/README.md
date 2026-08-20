# Evaluation-harness correctness suite

Run before any sweep whose numbers will be published:

```bash
bash scripts/tests/run_tests.sh
```

## Why this exists

Ten defects reached published numbers during the AWS re-measurement. Every one
had the same shape: **an operation failed or never happened, and a plausible
number was recorded anyway.** A crash is cheap. A wrong number that looks
measured is expensive, because nothing downstream can tell the difference.

| Defect | What it produced |
|---|---|
| `shasum` absent | tree signatures were empty strings; postconditions compared `''` to `''` and passed vacuously |
| `git gc` run locally against a server-side path | failed in 14 ms, still returned a timing; the git arm was then cloned from 100 unconsolidated packfiles, making SafeHub look 2x faster |
| `aead_ms_per_byte` converted ns with `1e9` | seconds per byte from a helper named and used as milliseconds; every model 1000x too small |
| corrected ratio guarded with `max(den, 1e-9)` | published `4.17e10` as though measured |
| `time_cmd_ms` status dropped by command substitution | failed operations recorded as very fast ones |
| stale `sh` binary in `target/release` | harnesses silently ran a CLI built a day earlier; on a clean build they fell through to `/bin/sh` and did nothing |
| `auth register` returning 409 | client left logged out, every later operation failed quietly |
| `dir_bytes` walking local paths in split mode | server-side storage measured as zero |
| S2 asserted on `/git/tree` | the untrusted host serves no plaintext tree route, so every caller got 404 and the check could never pass |
| SendCommand 24 KB output cap | artifacts silently truncated into corrupt JSON |

## The four checks

**`preflight.sh`** — the environment is *working*, not merely present. It builds
a real multi-pack repository and requires `git gc` to consolidate it; it checks
`shasum` produces 64 hex characters; it requires `gpg-agent`, without which
GnuPG 2.x cannot generate a key and the gcrypt arm is silently dropped; and it
fails if `target/release/sh` is older than `shub`.

**`test_eval_publish.py`** — units, dispersion, quantiles, slopes, and ratio
guards. Asserts a 1 MiB AEAD costs single-digit milliseconds, that
`analytic_point` has no `median`, that an empty sample is flagged rather than
reported as zero, and that an undefined ratio is `None` rather than `1e10`.

**`test_eval_common.sh`** — that `time_cmd_ms` propagates a failed command's
status, that `dir_bytes` returns 0 for a missing path (so callers must not read
0 as measured), that `stats_json` labels a single shot, and that the machine
block is populated on this platform.

**`audit_harness.py`** — static scan for the patterns themselves: server-side
paths operated on locally, epsilon division guards, `['median']` reads on
analytic points, timed commands whose status is never inspected in scripts
without `errexit`, and assertions against routes the untrusted host does not
serve.

## Known open findings

`e2e_mvp.sh` asserts plaintext browse against `/v1/repos/{owner}/{name}/git/tree`
on the untrusted host. `router_host` registers no plaintext tree routes; they
exist only in `router_local_ui`. Those five assertions cannot pass as written
and need to target `safehub-local-ui` instead. Left unfixed deliberately:
repointing them would change what the test asserts, which is a decision about
the demo's intent rather than a mechanical repair.
