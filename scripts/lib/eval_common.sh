#!/usr/bin/env bash
# Shared helpers for the SafeHub evaluation harnesses.
#
# Sourced by scripts/e2e_*.sh. Provides build + server bring-up, the userspace
# RTT proxy, millisecond timing, and the N-repetition dispersion reporting
# (median / IQR / mean / 95% CI) that every published cell is required to carry.
#
# Usage:
#   source "$(dirname "$0")/lib/eval_common.sh"
#   eval_build safehub-server safehub-cli sit-remote-safehub
#   eval_start_server 127.0.0.1:18100 "$DATA"

set -euo pipefail

EVAL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVAL_ROOT="$(cd "$EVAL_ROOT/.." && pwd)"
EVAL_CODE="$EVAL_ROOT/code"
EVAL_PUB="$EVAL_CODE/eval/published"
mkdir -p "$EVAL_PUB"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$EVAL_CODE/target}"
export PATH="${HOME}/.cargo/bin:${PATH}"

EVAL_PROFILE="${SAFEHUB_EVAL_PROFILE:-release}"

# Repetitions for every timed cell. N=1 cells are not publishable (need dispersion).
EVAL_REPS="${SAFEHUB_EVAL_REPS:-3}"

# Build the requested workspace binaries and export BIN / SH / SIT / SGIT / SERVER_BIN.
eval_build() {
  local pkgs=()
  local p
  for p in "$@"; do pkgs+=(-p "$p"); done
  local flags=(--quiet)
  [[ "$EVAL_PROFILE" == "release" ]] && flags+=(--release)
  (cd "$EVAL_CODE" && cargo build "${pkgs[@]}" "${flags[@]}")
  local target_dir
  target_dir="$(cd "$EVAL_CODE" && cargo metadata --format-version 1 --no-deps |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
  BIN="$target_dir/$EVAL_PROFILE"
  SH="$BIN/shub"
  SIT="$BIN/sit"
  SERVER_BIN="$BIN/safehub-server"
  EVAL_BIN="$BIN/safehub-eval"
  SGIT="$BIN/sgit"
  export PATH="$BIN:$PATH"
}

# Start safehub-server on $1 with data dir $2; block until /v1/health answers.
eval_start_server() {
  local listen="$1" data="$2"
  "$SERVER_BIN" --listen "$listen" --data "$data" &
  SERVER_PID=$!
  local i
  for i in $(seq 1 100); do
    curl -sf "http://$listen/v1/health" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "server on $listen did not become healthy" >&2
  return 1
}

# Userspace TCP delay proxy: $1 backend host:port, $2 listen host:port, $3 RTT ms.
# Half the RTT is applied in each direction, matching a symmetric path.
eval_start_rtt_proxy() {
  local backend="$1" listen="$2" rtt_ms="$3"
  python3 - "$backend" "$listen" "$rtt_ms" <<'PY' &
import asyncio, sys
backend_host, backend_port = sys.argv[1].split(":")
listen_host, listen_port = sys.argv[2].split(":")
half = float(sys.argv[3]) / 2000.0

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
        try:
            writer.close()
        except Exception:
            pass

async def handle(client_reader, client_writer):
    await asyncio.sleep(half)
    try:
        server_reader, server_writer = await asyncio.open_connection(
            backend_host, int(backend_port)
        )
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
  sleep 0.4
}

ms_now() {
  python3 -c 'import time; print(int(time.time()*1000))'
}

# Time a command, echoing elapsed milliseconds; propagates the command status.
time_cmd_ms() {
  local t0 t1 status
  t0=$(ms_now)
  set +e
  "$@" >/dev/null 2>&1
  status=$?
  set -e
  t1=$(ms_now)
  echo $((t1 - t0))
  return $status
}

# Recursive byte size of a directory.
dir_bytes() {
  python3 - "$1" <<'PY'
import os, sys
root = sys.argv[1]
n = 0
for dirpath, _, files in os.walk(root):
    for name in files:
        try:
            n += os.path.getsize(os.path.join(dirpath, name))
        except OSError:
            pass
print(n)
PY
}

# Dispersion summary for a whitespace-separated sample. Emits a JSON object with
# n / median / p25 / p75 / iqr / mean / stdev / ci95_half_width / samples so no
# published cell is an unlabelled single shot.
stats_json() {
  SAMPLES="$*" python3 - <<'PY'
import json, math, os, statistics
raw = [float(x) for x in os.environ["SAMPLES"].split() if x.strip()]
if not raw:
    print(json.dumps({"n": 0, "status": "no-samples"}))
    raise SystemExit(0)
raw_sorted = sorted(raw)
n = len(raw_sorted)


def quantile(data, q):
    if len(data) == 1:
        return data[0]
    pos = (len(data) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return data[int(pos)]
    return data[lo] + (data[hi] - data[lo]) * (pos - lo)


median = statistics.median(raw_sorted)
p25 = quantile(raw_sorted, 0.25)
p75 = quantile(raw_sorted, 0.75)
mean = statistics.fmean(raw_sorted)
stdev = statistics.stdev(raw_sorted) if n > 1 else 0.0
# Normal approximation; for n<=2 the interval is reported but flagged thin.
ci = 1.96 * stdev / math.sqrt(n) if n > 1 else None
print(json.dumps({
    "n": n,
    "median": round(median, 3),
    "p25": round(p25, 3),
    "p75": round(p75, 3),
    "iqr": round(p75 - p25, 3),
    "mean": round(mean, 3),
    "stdev": round(stdev, 3),
    "ci95_half_width": round(ci, 3) if ci is not None else None,
    "min": round(raw_sorted[0], 3),
    "max": round(raw_sorted[-1], 3),
    "samples": [round(x, 3) for x in raw],
    "dispersion": "median+IQR over n reps" if n > 1 else "single shot (label microbench-only)",
}))
PY
}

# Machine / AEAD provenance pinned into every published artifact.
eval_machine_json() {
  EVAL_PROFILE="$EVAL_PROFILE" python3 - <<'PY'
import json, os, platform, subprocess, datetime


def sysctl(key):
    try:
        out = subprocess.run(
            ["sysctl", "-n", key], capture_output=True, text=True, timeout=5
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except Exception:
        pass
    return None


arch = platform.machine()
mem = sysctl("hw.memsize")
model = sysctl("hw.model")
ncpu = sysctl("hw.ncpu")
cpu = sysctl("machdep.cpu.brand_string")
# Transport AEAD is HKDF-SHA-512 RO-pad + HMAC-SHA-512-256 — hardware AES is
# unused on the application transport hot path (MLS suite AEAD is separate).
aes_note = (
    "Transport AEAD is hkdf-sha512-pad+HMAC-SHA-512-256; hardware AES unused "
    "on application transport hot path"
)
print(json.dumps({
    "os": platform.system().lower(),
    "os_release": platform.release(),
    "arch": arch,
    "cpu_hint": os.environ.get("SAFEHUB_EVAL_CPU") or cpu or model or "unspecified",
    "cpu_count": int(ncpu) if ncpu and ncpu.isdigit() else None,
    "ram_bytes": int(mem) if mem and mem.isdigit() else None,
    "storage_hint": os.environ.get("SAFEHUB_EVAL_STORAGE", "local SSD (APFS/ext4)"),
    "hardware_aes_on_transport": False,
    "hardware_aes": "n/a for transport (see aes_note)",
    "aes_note": aes_note,
    "aead_backend": "hkdf-sha512-pad+HMAC-SHA-512-256",
    "build_profile": os.environ.get("EVAL_PROFILE", "release"),
    "python": platform.python_version(),
    "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}))
PY
}

# Standard identity so commits in generated fixtures do not depend on user config.
eval_git_identity() {
  git -C "$1" config user.email eval@safehub.local
  git -C "$1" config user.name "SafeHub Eval"
}
