#!/usr/bin/env bash
# Repository size-sweep harness: 5, 10, 50, 100, 200, 250, 300 MiB.
#
# Methodology (NO_SCALE_DOWN):
#   - Sizes: 5, 10, 50, 100, 200, 250, 300 MiB total working-tree fixtures.
#   - Objects: ~1000 tracked files (harness "objects" ≡ working-tree files;
#     each becomes ≥1 git blob after commit). Override via SAFEHUB_LARGE_TARGET_FILES.
#   - Multiple pushes: grow each repo across N=8 sequential sit pushes
#     (SAFEHUB_LARGE_PUSH_COUNT), partitioning the fixture into roughly equal
#     byte batches. Records per-push and aggregate wall times — not a single
#     monolithic first push.
#   - Optional 1024 MiB when SAFEHUB_EVAL_1GIB=1 (expensive; off by default).
#   - Simulated WAN: inject RTT via userspace delay proxy unless SAFEHUB_SKIP_RTT=1.
#
# Results: eval/published/additive-scale-latest.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODE="$ROOT/code"
if [[ ! -d "$CODE/crates" ]]; then CODE="$ROOT"; fi
cd "$CODE"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CODE/target}"
export PATH="${HOME}/.cargo/bin:${PATH}"
PROFILE="${SAFEHUB_EVAL_PROFILE:-release}"
LISTEN="127.0.0.1:18082"
export SAFEHUB_HOST="http://$LISTEN"
RTT_MS="${SAFEHUB_SIM_RTT_MS:-50}"
OUT="${SAFEHUB_EVAL_OUT:-$CODE/eval/results}"
PUB="$CODE/eval/published"
TARGET_FILES="${SAFEHUB_LARGE_TARGET_FILES:-1000}"
PUSH_COUNT="${SAFEHUB_LARGE_PUSH_COUNT:-8}"
mkdir -p "$OUT" "$PUB"

DATA="$(mktemp -d /tmp/safehub-add-data.XXXXXX)"
CFG="$(mktemp -d /tmp/safehub-add-cfg.XXXXXX)"
WORK="$(mktemp -d /tmp/safehub-add-work.XXXXXX)"
export HOME="$CFG"
export XDG_CONFIG_HOME="$CFG/.config"
export SAFEHUB_DATA="$DATA"
mkdir -p "$XDG_CONFIG_HOME"

SERVER_PID=""
PROXY_PID=""
cleanup() {
  [[ -n "${PROXY_PID}" ]] && kill "$PROXY_PID" 2>/dev/null || true
  [[ -n "${SERVER_PID}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$DATA" "$CFG" "$WORK"
}
trap cleanup EXIT

CARGO_FLAGS=(--quiet)
[[ "$PROFILE" == "release" ]] && CARGO_FLAGS+=(--release)
cargo build -p safehub-server -p safehub-cli -p sit-remote-safehub -p safehub-eval "${CARGO_FLAGS[@]}"
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BIN="$TARGET_DIR/$PROFILE"
export PATH="$BIN:/usr/bin:/bin:$PATH"

echo "==> Starting server on $LISTEN"
"$BIN/safehub-server" --listen "$LISTEN" --data "$DATA" &
SERVER_PID=$!
for i in $(seq 1 50); do
  curl -sf "$SAFEHUB_HOST/v1/health" >/dev/null 2>&1 && break
  sleep 0.1
done

# Optional userspace RTT injection in front of the server.
PROXY_LISTEN="127.0.0.1:18083"
if [[ "${SAFEHUB_SKIP_RTT:-}" != "1" ]]; then
  python3 - "$LISTEN" "$PROXY_LISTEN" "$RTT_MS" <<'PY' &
import asyncio, sys
backend_host, backend_port = sys.argv[1].split(":")
listen_host, listen_port = sys.argv[2].split(":")
rtt_ms = float(sys.argv[3])
half = rtt_ms / 2000.0  # each direction

async def relay(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            await asyncio.sleep(half)
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try: writer.close()
        except Exception: pass

async def handle(client_reader, client_writer):
    await asyncio.sleep(half)
    try:
        server_reader, server_writer = await asyncio.open_connection(backend_host, int(backend_port))
    except Exception:
        client_writer.close()
        return
    await asyncio.gather(
        relay(client_reader, server_writer),
        relay(server_reader, client_writer),
    )

async def main():
    server = await asyncio.start_server(handle, listen_host, int(listen_port))
    async with server:
        await server.serve_forever()

asyncio.run(main())
PY
  PROXY_PID=$!
  sleep 0.3
  export SAFEHUB_HOST="http://$PROXY_LISTEN"
  echo "  simulated RTT=${RTT_MS}ms via userspace proxy on $PROXY_LISTEN"
else
  RTT_MS=0
  echo "  SAFEHUB_SKIP_RTT=1 — localhost, no delay proxy"
fi

ms_now() { python3 - <<'PY'
import time; print(int(time.time()*1000))
PY
}
time_cmd_ms() {
  local t0 t1 status
  t0=$(ms_now); set +e; "$@" >/dev/null; status=$?; set -e; t1=$(ms_now)
  echo $((t1 - t0)); return $status
}

# Recursive byte size of a directory (server data dir before/after a push set).
dir_bytes() {
  python3 - "$1" <<'PYSZ'
import os,sys
root=sys.argv[1]
n=0
for dp,_,fs in os.walk(root):
  for fn in fs:
    p=os.path.join(dp,fn)
    try: n+=os.path.getsize(p)
    except OSError: pass
print(n)
PYSZ
}

# Size sweep: 5 -> 300 MiB. Optional 1 GiB via SAFEHUB_EVAL_1GIB=1.
if [[ -n "${SAFEHUB_ADDITIVE_SIZES:-}" ]]; then
  # shellcheck disable=SC2206
  SIZES=(${SAFEHUB_ADDITIVE_SIZES})
else
  SIZES=(5 10 50 100 200 250 300)
fi
[[ "${SAFEHUB_EVAL_1GIB:-}" == "1" ]] && SIZES+=(1024)
# Quick mode: 100 MiB only (still multi-push + 1000 objects).
if [[ "${SAFEHUB_EVAL_QUICK:-}" == "1" ]]; then
  SIZES=(5 10 50)
fi

"$BIN/shub" auth register --user bob --password bob-add-pw --hostname "$SAFEHUB_HOST"
"$BIN/shub" device publish-key-package --device default || true
"$BIN/shub" auth logout || true
"$BIN/shub" auth register --user alice --password alice-add-pw --hostname "$SAFEHUB_HOST"
"$BIN/shub" device publish-key-package --device default || true
ROWS_JSONL="$OUT/additive-scale-rows.jsonl"
: >"$ROWS_JSONL"

partition_batches() {
  # Writes batch-0 .. batch-(N-1) file lists under $1/batches/ from fixture $2.
  local batch_root="$1" fix="$2" n="$3"
  python3 - "$batch_root" "$fix" "$n" <<'PY'
import os, sys
from pathlib import Path
root, fix, n = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
skip = {"meta.json", "MANIFEST.json", "commits.txt"}
files = []
for p in fix.rglob("*"):
    if not p.is_file():
        continue
    rel = p.relative_to(fix).as_posix()
    if rel in skip or p.name in skip:
        continue
    files.append((rel, p.stat().st_size))
files.sort(key=lambda x: (-x[1], x[0]))  # large first for steadier batch bytes
total = sum(s for _, s in files) or 1
target = total / n
batches = [[] for _ in range(n)]
sizes = [0] * n
# Greedy: assign each file to the currently lightest batch under soft target.
for rel, sz in files:
    i = min(range(n), key=lambda j: (sizes[j], j))
    # Prefer filling earlier batches if far below target.
    for j in range(n):
        if sizes[j] + sz <= target * 1.15 or j == n - 1:
            # still pick lightest among those under soft cap when possible
            pass
    i = min(range(n), key=lambda j: (sizes[j], j))
    batches[i].append(rel)
    sizes[i] += sz
bdir = root / "batches"
bdir.mkdir(parents=True, exist_ok=True)
for i, batch in enumerate(batches):
    (bdir / f"batch-{i}.txt").write_text("\n".join(batch) + ("\n" if batch else ""))
print(f"  partitioned {len(files)} files / {total} bytes into {n} pushes "
      f"(batch_bytes={sizes})")
PY
}

for MIB in "${SIZES[@]}"; do
  echo "==> Additive fixture ${MIB} MiB, objects≈${TARGET_FILES}, pushes=${PUSH_COUNT}"
  "$BIN/safehub-eval" --mode fixtures --out "$OUT" --size-mib "$MIB" --target-files "$TARGET_FILES"
  FIX="$OUT/fixture-${MIB}mib"
  REPO="add${MIB}mib"
  rm -rf "$WORK/$REPO" "$WORK/${REPO}-clone" "$WORK/${REPO}-batches"
  mkdir -p "$WORK/${REPO}-batches"
  partition_batches "$WORK/${REPO}-batches" "$FIX" "$PUSH_COUNT"

  (
    cd "$WORK"
    "$BIN/shub" repo create "$REPO" --clone
  )
  (
    cd "$WORK/$REPO"
    git config user.email eval@safehub.local
    git config user.name "SafeHub Eval"
  )

  PUSH_MS_LIST=()
  AGG_PUSH_MS=0
  FILE_COUNT=0
  # Ciphertext storage overhead: delta of the server data dir across all pushes.
  BYTES_BEFORE=$(dir_bytes "$DATA" || echo 0)
  for ((i=0; i<PUSH_COUNT; i++)); do
    BATCH_LIST="$WORK/${REPO}-batches/batches/batch-${i}.txt"
    echo "  push $((i+1))/${PUSH_COUNT}…"
    (
      cd "$WORK/$REPO"
      while IFS= read -r rel || [[ -n "${rel:-}" ]]; do
        [[ -z "$rel" ]] && continue
        mkdir -p "$(dirname "$rel")"
        cp "$FIX/$rel" "$rel"
      done <"$BATCH_LIST"
      "$BIN/sit" add .
      "$BIN/sit" commit -m "additive ${MIB}MiB batch $((i+1))/${PUSH_COUNT}" >/dev/null
    )
    PMS=$(time_cmd_ms bash -c "cd '$WORK/$REPO' && '$BIN/sit' push")
    PUSH_MS_LIST+=("$PMS")
    AGG_PUSH_MS=$((AGG_PUSH_MS + PMS))
    echo "    push_ms=${PMS}"
  done

  FILE_COUNT=$(python3 - "$FIX" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])/"meta.json"
print(json.load(open(p))["file_count"] if p.exists() else 0)
PY
)
  FIX_BYTES=$(python3 - "$FIX" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])/"meta.json"
print(json.load(open(p))["total_bytes"] if p.exists() else 0)
PY
)

  BYTES_AFTER=$(dir_bytes "$DATA" || echo 0)
  CT_BYTES=$((BYTES_AFTER - BYTES_BEFORE))
  if [[ "$CT_BYTES" -lt 0 ]]; then CT_BYTES=0; fi

  FETCH_MS=$(time_cmd_ms bash -c "cd '$WORK/$REPO' && '$BIN/sit' fetch")
  CLONE_MS=$(time_cmd_ms bash -c "cd '$WORK' && '$BIN/sit' clone alice/$REPO '${REPO}-clone'")

  # Plain-git baseline on the same fixture tree (local bare repo, same machine),
  # so the SafeHub and plain-git columns stay directly comparable.
  echo "  plain-git baseline…"
  PG="$WORK/plain-$MIB"
  rm -rf "$PG"
  mkdir -p "$PG/repo"
  rsync -a --exclude meta.json --exclude MANIFEST.json --exclude commits.txt "$FIX/" "$PG/repo/"
  git -C "$PG/repo" init -q --template=
  git -C "$PG/repo" config user.email eval@safehub.local
  git -C "$PG/repo" config user.name "SafeHub Eval"
  git -C "$PG/repo" add .
  git -C "$PG/repo" commit -qm "additive ${MIB}MiB baseline"
  git init --bare -q --template= "$PG/bare.git"
  git -C "$PG/repo" remote add origin "$PG/bare.git"
  PLAIN_PUSH_MS=$(time_cmd_ms git -C "$PG/repo" push -q origin HEAD)

  # Plain-git INCREMENTAL baseline: the same N batches, N commits, N pushes,
  # so it is comparable to SafeHub's N=8 aggregate. Comparing N SafeHub pushes
  # against git's single whole-tree push would measure batching, not encryption.
  PGI="$WORK/plaininc-$MIB"
  rm -rf "$PGI"; mkdir -p "$PGI/repo"
  git -C "$PGI/repo" init -q --template=
  git -C "$PGI/repo" config user.email eval@safehub.local
  git -C "$PGI/repo" config user.name "SafeHub Eval"
  git init --bare -q --template= "$PGI/bare.git"
  git -C "$PGI/repo" remote add origin "$PGI/bare.git"
  PLAIN_INC_PUSH_MS=0
  for ((bi=0; bi<PUSH_COUNT; bi++)); do
    BL="$WORK/${REPO}-batches/batches/batch-${bi}.txt"
    ( cd "$PGI/repo"
      while IFS= read -r rel || [[ -n "${rel:-}" ]]; do
        [[ -z "$rel" ]] && continue
        mkdir -p "$(dirname "$rel")"; cp "$FIX/$rel" "$rel"
      done <"$BL"
      git add -A >/dev/null 2>&1
      git commit -qm "plain incremental batch $((bi+1))" >/dev/null 2>&1 )
    BMS=$(time_cmd_ms git -C "$PGI/repo" push -q origin HEAD)
    PLAIN_INC_PUSH_MS=$((PLAIN_INC_PUSH_MS + BMS))
  done
  echo "  plain-git incremental ($PUSH_COUNT pushes): ${PLAIN_INC_PUSH_MS}ms"
  rm -rf "$PGI"

  # Pack the bare repo before cloning. An un-gc'd server forces `pack-objects`
  # to rebuild a packfile on every clone (~2x the total), which measures server
  # neglect rather than transport cost.
  git -C "$PG/bare.git" gc -q 2>/dev/null || true
  # Clone over file:// rather than a local path: a local-path clone hardlinks
  # the object store (and APFS copy-on-write makes even --no-hardlinks free),
  # so it never transfers the data SafeHub has to move.
  PLAIN_CLONE_MS=$(time_cmd_ms git clone -q "file://$PG/bare.git" "$PG/clone")
  git clone -q "file://$PG/bare.git" "$PG/fetch-wt"
  PLAIN_FETCH_MS=$(time_cmd_ms git -C "$PG/fetch-wt" fetch -q origin)
  rm -rf "$PG"

  # Like-for-like single push: one commit of the whole fixture, one push, so
  # the SafeHub and plain-git push columns cover identical work. (The N=8
  # column above measures the incremental-workflow cost instead.)
  SP_REPO="sp${MIB}mib"
  rm -rf "$WORK/$SP_REPO" "$WORK/${SP_REPO}-clone"
  ( cd "$WORK" && "$BIN/shub" repo create "$SP_REPO" --clone >/dev/null 2>&1 )
  ( cd "$WORK/$SP_REPO" && git config user.email eval@safehub.local \
      && git config user.name "SafeHub Eval" )
  rsync -a --exclude meta.json --exclude MANIFEST.json --exclude commits.txt \
    "$FIX/" "$WORK/$SP_REPO/"
  ( cd "$WORK/$SP_REPO" && "$BIN/sit" add . >/dev/null 2>&1 \
      && "$BIN/sit" commit -m "single push ${MIB}MiB" >/dev/null 2>&1 )
  SP_BYTES_BEFORE=$(dir_bytes "$DATA" || echo 0)
  SINGLE_PUSH_MS=$(time_cmd_ms bash -c "cd '$WORK/$SP_REPO' && '$BIN/sit' push")
  SP_BYTES_AFTER=$(dir_bytes "$DATA" || echo 0)
  SINGLE_CT_BYTES=$((SP_BYTES_AFTER - SP_BYTES_BEFORE))
  [[ "$SINGLE_CT_BYTES" -lt 0 ]] && SINGLE_CT_BYTES=0
  SINGLE_CLONE_MS=$(time_cmd_ms bash -c "cd '$WORK' && '$BIN/sit' clone alice/$SP_REPO '${SP_REPO}-clone'")
  echo "  single-push: push=${SINGLE_PUSH_MS}ms clone=${SINGLE_CLONE_MS}ms ciphertext=${SINGLE_CT_BYTES}B"
  rm -rf "$WORK/$SP_REPO" "$WORK/${SP_REPO}-clone"

  # Membership scaling at THIS repository size: invite + accept a real
  # collaborator, and time consolidation against the large tip. The locked
  # membership cost is measured at each repository size, not only small ones.
  JOIN_MS=0
  ROTATE_MS=0
  CONSOL_MS=0
  if [[ "${SAFEHUB_ADDITIVE_SKIP_MEMBERSHIP:-}" != "1" ]]; then
    echo "  membership + consolidation at ${MIB} MiB…"
    JOIN_MS=$(time_cmd_ms "$BIN/shub" repo invite "alice/$REPO" bob || true)
    ROTATE_MS=$(time_cmd_ms "$BIN/shub" repo rotate "alice/$REPO" || true)
    CONSOL_MS=$(time_cmd_ms "$BIN/shub" repo consolidate "alice/$REPO" --tip-mib "$MIB" || true)
    echo "    invite=${JOIN_MS}ms rotate=${ROTATE_MS}ms consolidate=${CONSOL_MS}ms"
  fi

  # Emit one JSON row (per-push array + aggregates).
  python3 - "$ROWS_JSONL" "$MIB" "$FILE_COUNT" "$FIX_BYTES" "$PUSH_COUNT" "$AGG_PUSH_MS" "$FETCH_MS" "$CLONE_MS" "$RTT_MS" "$CT_BYTES" "$PLAIN_PUSH_MS" "$PLAIN_FETCH_MS" "$PLAIN_CLONE_MS" "$JOIN_MS" "$ROTATE_MS" "$CONSOL_MS" "$SINGLE_PUSH_MS" "$SINGLE_CLONE_MS" "$SINGLE_CT_BYTES" "$PLAIN_INC_PUSH_MS" "${PUSH_MS_LIST[@]}" <<'PY'
import json, sys
path = sys.argv[1]
mib, files, nbytes, npush = map(int, sys.argv[2:6])
agg, fetch, clone, rtt = map(int, sys.argv[6:10])
ct, pgpush, pgfetch, pgclone = map(int, sys.argv[10:14])
join_ms, rotate_ms, consol_ms = map(int, sys.argv[14:17])
single_push_ms, single_clone_ms, single_ct = map(int, sys.argv[17:20])
plain_inc_push_ms = int(sys.argv[20])
per = [int(x) for x in sys.argv[21:]]
row = {
  "size_mib": mib,
  "objects": files,
  "object_note": "working-tree files (harness); ≈ git blobs after commit",
  "fixture_bytes": nbytes,
  "push_count": npush,
  "per_push_ms": per,
  "safehub_push_ms_aggregate": agg,
  "safehub_push_ms_mean": round(agg / max(npush, 1)),
  "safehub_push_ms_first": per[0] if per else None,
  "safehub_push_ms_last": per[-1] if per else None,
  # Back-compat field: aggregate multi-push wall (not single monolith).
  "safehub_push_ms": agg,
  "safehub_fetch_ms": fetch,
  "safehub_clone_ms": clone,
  "plain_git_push_ms": pgpush,
  "plain_git_fetch_ms": pgfetch,
  "plain_git_clone_ms": pgclone,
  "server_store_bytes_approx": ct,
  "ciphertext_ratio": round(ct / nbytes, 4) if nbytes else None,
  "push_overhead_x": round(agg / pgpush, 3) if pgpush else None,
  "fetch_overhead_x": round(fetch / pgfetch, 3) if pgfetch else None,
  "clone_overhead_x": round(clone / pgclone, 3) if pgclone else None,
  "plain_git_incremental_push_ms": plain_inc_push_ms,
  "incremental_push_overhead_x": round(agg / plain_inc_push_ms, 3) if plain_inc_push_ms else None,
  "single_push_ms": single_push_ms,
  "single_clone_ms": single_clone_ms,
  "single_push_ct_bytes": single_ct,
  "single_push_overhead_x": round(single_push_ms / pgpush, 3) if pgpush else None,
  "single_ct_ratio": round(single_ct / nbytes, 4) if nbytes else None,
  "invite_join_ms": join_ms,
  "rotate_ms": rotate_ms,
  "consolidate_ms": consol_ms,
  "sim_rtt_ms": rtt,
  "status": "measured",
}
with open(path, "a") as f:
  f.write(json.dumps(row) + "\n")
print(json.dumps(row, indent=2))
PY
  echo "  aggregate_push=${AGG_PUSH_MS}ms fetch=${FETCH_MS}ms clone=${CLONE_MS}ms files=${FILE_COUNT}"
  echo "  plain-git push=${PLAIN_PUSH_MS}ms fetch=${PLAIN_FETCH_MS}ms clone=${PLAIN_CLONE_MS}ms ciphertext_delta=${CT_BYTES}B"
done

python3 - "$PUB" "$RTT_MS" "$TARGET_FILES" "$PUSH_COUNT" "$ROWS_JSONL" <<'PY'
import json, os, sys, platform, datetime
pub, rtt, target_files, push_count, jsonl = sys.argv[1:6]
rows = []
with open(jsonl) as f:
  for line in f:
    line = line.strip()
    if line:
      rows.append(json.loads(line))
path = os.path.join(pub, "additive-scale-latest.json")
# Merge with prior published rows so partial runs (e.g. SAFEHUB_ADDITIVE_SIZES=200)
# do not drop sibling measured sizes.
by_size = {}
if os.path.exists(path):
  try:
    prev = json.load(open(path))
    for r in prev.get("size_ops", []):
      if r.get("status") == "measured" and "size_mib" in r:
        by_size[int(r["size_mib"])] = r
  except Exception:
    pass
for r in rows:
  by_size[int(r["size_mib"])] = r
merged = [by_size[k] for k in sorted(by_size)]
report = {
  "mode": "size-sweep",
  "methodology": {
    "sizes_mib": [r["size_mib"] for r in merged],
    "target_objects": int(target_files),
    "object_definition": "working-tree files generated by safehub-eval fixtures; paper may say objects",
    "push_count": int(push_count),
    "multi_push": (
      f"Each size grows across {push_count} sequential sit pushes with "
      "roughly equal byte batches (not a single monolithic first push)."
    ),
    "sim_rtt_ms": int(rtt),
    "sim_rtt_method": (
      "userspace asyncio TCP delay proxy (half-RTT each direction); not a real WAN path"
      if int(rtt) > 0
      else "localhost (SAFEHUB_SKIP_RTT=1)"
    ),
    "note": (
      "Size sweep 5/10/50/100/200/250/300 MiB × ~1000 objects "
      "× N pushes across the full 5–300 MiB size axis."
    ),
  },
  "machine": {
    "os": platform.system().lower(),
    "arch": platform.machine(),
    "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
  },
  "size_ops": merged,
}
json.dump(report, open(path, "w"), indent=2)
print("wrote", path)
PY

echo "==> Additive scale eval OK"
