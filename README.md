# SafeHub — artifact

End-to-end encrypted Git hosting. The untrusted server stores and sequences
ciphertext and never holds repository keys; members hold the keys, and
unmodified `git` drives the system through a remote helper.

Everything below was run from a clean copy of this directory. Where a command
prints a count, the count observed on our machine is given so a deviation is
visible immediately.

---

## 1. Layout

| Path | What it is |
|---|---|
| `code/crates/safehub-crypto` | AEAD transport, dual key regression, RefHead, ML-DSA/ML-KEM binding |
| `code/crates/safehub-client` | Client protocol: seal, push, fetch, verify, windows |
| `code/crates/safehub-server` | Untrusted server: blob store, compare-and-swap head log, MLS delivery |
| `code/crates/safehub-cli` | `safehub`, `shub` (administration), `sit` (remote helper) |
| `code/crates/safehub-browse` | **Member-side plaintext browse UI**, runs on the member machine |
| `code/crates/sit-remote-safehub` | `git-remote-sit`, the transport `git` invokes |
| `code/crates/sgit-rs` | `sgit`, our reimplementation of the closest prior design (comparison only) |
| `code/crates/{safehub-api,safehub-storage,safehub-types}` | Wire types, storage, shared types |
| `code/vendor/openmls` | Vendored OpenMLS fork at NIST PQ Category 5. **Required to build** |
| `code/eval` | Evaluation harness and `published/`, the measurements the paper cites |
| `code/vectors` | Cross-implementation test vectors |
| `scripts` | Measurement harnesses (`e2e_*.sh`), figure generators, test suites |
| `safehub-paper.pdf` | The paper, for mapping each claim to a measurement |

---

## 2. Prerequisites

- **Rust** 1.97 or later (`cargo`, `rustc`). Tested with 1.97.1.
- **git** 2.40 or later.
- **python3** 3.10 or later, for the figure generators and harness guards.

Only for the six-system comparison (§2 of the evaluation), not for building or
testing SafeHub itself:

- `git-crypt`, `git-remote-gcrypt`, `gpg`

Check the environment is *working*, not merely installed:

```sh
bash scripts/tests/preflight.sh
```

---

## 3. Compile

```sh
cd code
cargo build --release
```

This builds the whole workspace, the vendored OpenMLS fork included. It
produces six executables in `code/target/release`:

| Binary | Role |
|---|---|
| `safehub` | end-user entry point |
| `shub` | administration: repositories, membership, rotation, consolidation |
| `sit` | remote helper commands (`sit push`, `sit fetch`, `sit clone`) |
| `git-remote-sit` | what `git` invokes for a `sit://` remote |
| `safehub-server` | the untrusted server |
| `safehub-browse` | the member-side plaintext browse UI |

To build only the cryptographic core against the PQ MLS suite:

```sh
cargo build --release -p safehub-crypto --features openmls
```

---

## 4. Test each part

Run from `code/` unless stated otherwise. Each command is independent.

### 4.1 Unit and integration tests (Rust)

```sh
cd code && cargo test --release
```

Expected: **285 tests, 0 failures.**

### 4.2 Paper properties — the claims, executable

Each of these corresponds to a property the proof depends on, so a broken
property fails here rather than silently changing a number.

```sh
cd code
cargo test --release -p safehub-crypto --features openmls --test paper_properties
cargo test --release -p safehub-crypto            --test paper_properties
cargo test --release -p safehub-crypto            --test negative_crypto
cargo test --release -p safehub-client            --test verification_path
cargo test --release -p safehub-client            --test read_path_verification
```

The suite is run in **both** crypto configurations on purpose: the default
build links a development stub, and every non-MLS property must hold there
too; the `openmls` build is what the shipped binaries use.

### 4.3 End-to-end protocol behaviour

```sh
bash scripts/tests/test_crypto_endtoend.sh   # push encrypts, pull decrypts, server compare-and-swaps
bash scripts/tests/test_safehub_ops.sh       # tamper, rollback, authorization, history windows, consolidation
bash scripts/tests/test_history_ops.sh       # history-window operations
bash scripts/tests/test_sgit_wrapper.sh      # the comparison reimplementation
```

### 4.4 Measurement-harness correctness

The harness is tested separately from the system, because a measurement bug is
as damaging as a protocol bug. This suite is hermetic: no server, no network.

```sh
bash scripts/tests/run_tests.sh
```

Expected: **18 passed, 0 failed**, ending in `=== suite: PASS ===`.

It checks, among other things, that an operation is corrected only by its own
zero-payload floor, that a clone is compared on content rather than merely
being non-empty, that an absent tool is reported absent rather than as zero,
and that thin-pack bytes measure the delta rather than the repository.

### 4.5 Guards on the guards

```sh
bash scripts/tests/mutate_e13_ops.sh   # removes each guard in turn; every removal must be caught
python3 scripts/tests/lint_unbound.py  # no function reads another function's local
python3 scripts/tests/audit_harness.py # static scan for silent-failure patterns
```

---

## 5. Run the whole set of tests

One command, both crypto configurations, every suite above:

```sh
bash scripts/run_property_suite.sh
```

It exits non-zero if anything fails. Run this before trusting any measurement.

---

## 6. Reproduce the measurements

The published measurements the paper cites are in `code/eval/published/`. The
figures are generated from them, so regenerating the figures reproduces the
paper's numbers without re-running a sweep:

```sh
python3 scripts/make_sweep_figures.py     # six-system comparison, storage, clone-vs-depth
python3 scripts/make_parity_figures.py    # SafeHub against plain Git over 5-500 MB
python3 scripts/make_review_figures.py    # head-log contention
python3 scripts/make_baseline_figures.py  # source-tree and additive corpora
```

To re-run a sweep end to end, on one host:

```sh
bash scripts/e2e_eval.sh          # microbenchmarks and the core end-to-end cells
bash scripts/e2e_e13_matrix.sh    # the six-system comparison
bash scripts/e2e_e13_ops.sh       # pull, fetch, merge, rebase, force-push, rotate, consolidation
bash scripts/e2e_depth_clone.sh   # clone against history depth
```

Output lands in `code/eval/results/`, which the harnesses create. Sweeps take
hours and are sensitive to the machine; the paper's numbers were taken with
clients and servers on separate hosts, so single-host runs will differ in
absolute terms while preserving the orderings the paper reports.

---

## 7. Try it by hand

```sh
export PATH="$PWD/code/target/release:$PATH"

safehub-server --listen 127.0.0.1:8080 --data /tmp/safehub-data &   # untrusted server
shub auth register --user alice --password pw --hostname http://127.0.0.1:8080
shub device publish-key-package --device default
shub repo create alice/demo

git init demo && cd demo
git remote add origin sit://alice/demo
echo hello > a.txt && git add a.txt && git commit -m first
git push origin main          # ciphertext leaves the client; the server never sees a.txt

safehub-browse                # plaintext browse UI, on the member machine only
```

`shub repo invite` grants a history window; `shub repo remove` revokes
membership and advances the epoch in one operation. `shub repo verify` checks
the head chain for forks.

---

## 8. What this artifact does not contain

- Raw sweep output and working notes. `code/eval/published/` retains
  everything the paper cites.
- The scripts that drove our multi-host runs, which carry infrastructure
  identifiers specific to one account and cannot run elsewhere. The
  single-host harnesses in `scripts/` are complete and reproduce the same
  measurements, differing in absolute latency because they do not cross a
  network.
- Build output. `cargo build --release` creates `code/target/` on first run.

The figure generators write LaTeX into `paper/figures/`, creating that
directory on first use.
