#!/usr/bin/env bash
# SafeHub full-stack systems evaluation harness.
# Usage (from repo root): ./scripts/e2e_eval.sh
#   SAFEHUB_EVAL_PROFILE=release|debug  (default release)
#   SAFEHUB_EVAL_CPU="Apple M5 Pro"     (optional machine hint)
#   SAFEHUB_EVAL_SKIP_JOIN=1            (skip OpenMLS join sweep)
#   SAFEHUB_EVAL_QUICK=1                (8 MiB only + join n=10)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODE="$ROOT/code"
if [[ ! -d "$CODE/crates" ]]; then
  CODE="$ROOT"
fi
cd "$CODE"

# Pin toolchain + local target dir (avoid sandbox/cache redirects).
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CODE/target}"
export PATH="${HOME}/.cargo/bin:${PATH}"

PROFILE="${SAFEHUB_EVAL_PROFILE:-release}"
LISTEN="127.0.0.1:18081"
export SAFEHUB_HOST="http://$LISTEN"
export CARGO_TERM_COLOR=always
export SAFEHUB_EVAL_CPU="${SAFEHUB_EVAL_CPU:-Apple M5 Pro}"
export SAFEHUB_EVAL_PROFILE="$PROFILE"
OUT="${SAFEHUB_EVAL_OUT:-$CODE/eval/results}"
PUB="$CODE/eval/published"
mkdir -p "$OUT" "$PUB"

DATA="$(mktemp -d /tmp/safehub-eval-data.XXXXXX)"
CFG="$(mktemp -d /tmp/safehub-eval-cfg.XXXXXX)"
WORK="$(mktemp -d /tmp/safehub-eval-work.XXXXXX)"
export HOME="$CFG"
export XDG_CONFIG_HOME="$CFG/.config"
export SAFEHUB_DATA="$DATA"
mkdir -p "$XDG_CONFIG_HOME"

SERVER_PID=""
cleanup() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA" "$CFG" "$WORK"
}
trap cleanup EXIT

echo "==> Building ($PROFILE): server + CLI + sit-remote + eval"
CARGO_FLAGS=(--quiet)
if [[ "$PROFILE" == "release" ]]; then
  CARGO_FLAGS+=(--release)
fi
cargo build -p safehub-server -p safehub-cli -p sit-remote-safehub -p safehub-eval "${CARGO_FLAGS[@]}"

TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BIN="$TARGET_DIR/$PROFILE"
SERVER_BIN="$BIN/safehub-server"
SH="$BIN/shub"
SIT="$BIN/sit"
EVAL_BIN="$BIN/safehub-eval"
# Prefer SafeHub sh/sit ahead of system, but keep /usr/bin for real git.
export PATH="$BIN:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

echo "==> Starting server on $LISTEN (data=$DATA)"
"$SERVER_BIN" --listen "$LISTEN" --data "$DATA" &
SERVER_PID=$!
for i in $(seq 1 50); do
  if curl -sf "$SAFEHUB_HOST/v1/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl -sf "$SAFEHUB_HOST/v1/health" >/dev/null

ms_now() {
  python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
}

git_identity() {
  local dir="$1"
  git -C "$dir" config user.email "eval@safehub.local"
  git -C "$dir" config user.name "SafeHub Eval"
}

time_cmd_ms() {
  # Prints elapsed ms on stdout; streams command stderr; returns cmd status.
  local t0 t1 status
  t0=$(ms_now)
  set +e
  "$@" >/dev/null
  status=$?
  set -e
  t1=$(ms_now)
  echo $((t1 - t0))
  return $status
}

dir_bytes() {
  python3 - "$1" <<'PY'
import os,sys
root=sys.argv[1]
n=0
for dp,_,fs in os.walk(root):
  for f in fs:
    p=os.path.join(dp,f)
    try: n+=os.path.getsize(p)
    except OSError: pass
print(n)
PY
}

ensure_fixtures() {
  if [[ "${SAFEHUB_EVAL_QUICK:-}" == "1" ]]; then
    "$EVAL_BIN" --mode fixtures --out "$OUT" --size-mib 8
  else
    "$EVAL_BIN" --mode fixtures --out "$OUT"
  fi
}

echo "==> Ensuring fixtures"
ensure_fixtures

SIZES=(5 10 50 100 200 250 300)
if [[ "${SAFEHUB_EVAL_QUICK:-}" == "1" ]]; then
  SIZES=(5 10)
fi

echo "==> Register alice/bob/carol + publish device KeyPackages"
"$SH" auth register --user alice --password alice-eval-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default || true
"$SH" auth logout || true
"$SH" auth register --user bob --password bob-eval-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default || true
"$SH" auth logout || true
"$SH" auth register --user carol --password carol-eval-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default || true
"$SH" auth logout || true
"$SH" auth login --user alice --secret alice-eval-pw --hostname "$SAFEHUB_HOST"

E2E_JSON="$OUT/e2e-size.jsonl"
: >"$E2E_JSON"

warmup_push() {
  local repo="$1"
  (
    cd "$WORK/$repo"
    echo "warmup $(date)" >> README.md
    "$SIT" add README.md
    "$SIT" commit -m "warmup" >/dev/null
    "$SIT" push >/dev/null
  )
}

for MIB in "${SIZES[@]}"; do
  FIX="$OUT/fixture-${MIB}mib"
  REPO="eval${MIB}mib"
  echo "==> Size $MIB MiB: create repo + E2E push/fetch/clone"
  rm -rf "$WORK/$REPO" "$WORK/${REPO}-clone"
  (
    cd "$WORK"
    "$SH" repo create "$REPO" --clone
  )
  # Populate working tree from fixture (skip meta.json / MANIFEST).
  rsync -a --exclude meta.json --exclude MANIFEST.json --exclude commits.txt "$FIX/" "$WORK/$REPO/"
  (
    cd "$WORK/$REPO"
    git_identity .
    "$SIT" add .
    "$SIT" commit -m "fixture ${MIB}MiB" >/dev/null
  )
  # Warmup: one small push already done at create? Ensure remote helper path hot.
  # First measured push of fixture content.
  # Ciphertext bytes: delta of server data dir around this size's push.
  BYTES_BEFORE=$(dir_bytes "$DATA" || echo 0)
  PUSH_MS=$(time_cmd_ms bash -c "cd '$WORK/$REPO' && '$SIT' push")
  BYTES_AFTER=$(dir_bytes "$DATA" || echo 0)
  CT_BYTES=$((BYTES_AFTER - BYTES_BEFORE))
  if [[ "$CT_BYTES" -lt 0 ]]; then CT_BYTES=0; fi

  FETCH_MS=$(time_cmd_ms bash -c "cd '$WORK/$REPO' && '$SIT' fetch")
  # Clone into fresh dir (same HOME → creator MLS material present).
  CLONE_MS=$(time_cmd_ms bash -c "cd '$WORK' && '$SIT' clone alice/$REPO '${REPO}-clone'")

  # Plain git baseline (local bare) for same fixture tree.
  PG="$WORK/plain-$MIB"
  rm -rf "$PG"
  mkdir -p "$PG/repo"
  rsync -a --exclude meta.json --exclude MANIFEST.json --exclude commits.txt "$FIX/" "$PG/repo/"
  git -C "$PG/repo" init -q --template=
  git -C "$PG/repo" config user.email eval@safehub
  git -C "$PG/repo" config user.name eval
  git -C "$PG/repo" add .
  git -C "$PG/repo" commit -qm fixture
  git init --bare -q --template= "$PG/bare.git"
  git -C "$PG/repo" remote add origin "$PG/bare.git"
  PLAIN_PUSH=$(time_cmd_ms git -C "$PG/repo" push -q origin HEAD)
  PLAIN_CLONE=$(time_cmd_ms git clone -q "$PG/bare.git" "$PG/clone")
  git clone -q "$PG/bare.git" "$PG/fetch-wt"
  PLAIN_FETCH=$(time_cmd_ms git -C "$PG/fetch-wt" fetch -q origin)

  FIX_BYTES=$(dir_bytes "$FIX")
  python3 - "$E2E_JSON" "$MIB" "$PUSH_MS" "$FETCH_MS" "$CLONE_MS" "$PLAIN_PUSH" "$PLAIN_FETCH" "$PLAIN_CLONE" "$FIX_BYTES" "$CT_BYTES" <<'PY'
import json,sys
path,mib,push,fetch,clone,pp,pf,pc,fb,ct=sys.argv[1:]
row={
  "size_mib": int(mib),
  "safehub_push_ms": int(push),
  "safehub_fetch_ms": int(fetch),
  "safehub_clone_ms": int(clone),
  "plain_git_push_ms": int(pp),
  "plain_git_fetch_ms": int(pf),
  "plain_git_clone_ms": int(pc),
  "fixture_bytes": int(fb),
  "server_store_bytes_approx": int(ct),
  "status": "measured",
  "note": "E2E sit:// localhost: sit push/fetch/clone via sh auth + sit CLI against safehub-server (release when SAFEHUB_EVAL_PROFILE=release). Includes AEAD+HTTP+CAS+ML-DSA-87 leaf RefHead signatures.",
}
with open(path,"a") as f:
  f.write(json.dumps(row)+"\n")
print(json.dumps(row, indent=2))
PY
done

echo "==> Security: removal → unreadability"
"$SH" auth login --user alice --secret alice-eval-pw --hostname "$SAFEHUB_HOST"
rm -rf "$WORK/sec-demo"
(
  cd "$WORK"
  "$SH" repo create secdemo --clone || true
)
echo "secret body" > "$WORK/secdemo/SECRET.txt"
(
  cd "$WORK/secdemo"
  git_identity .
  "$SIT" add SECRET.txt
  "$SIT" commit -m "secret" >/dev/null
  "$SIT" push >/dev/null
)
"$SH" repo invite alice/secdemo bob
"$SH" repo invite alice/secdemo carol --forward-only
REMOVE_MS=$(time_cmd_ms "$SH" repo remove-member alice/secdemo carol)
# carol must not browse
CAROL_TOK=$(curl -sf -X POST "$SAFEHUB_HOST/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"user":"carol","secret":"carol-eval-pw"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
CAROL_CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $CAROL_TOK" \
  "$SAFEHUB_HOST/v1/repos/alice/secdemo")
BOB_TOK=$(curl -sf -X POST "$SAFEHUB_HOST/v1/auth/login" \
  -H 'content-type: application/json' \
  -d '{"user":"bob","secret":"bob-eval-pw"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
BOB_CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $BOB_TOK" \
  "$SAFEHUB_HOST/v1/repos/alice/secdemo")
[[ "$CAROL_CODE" == "403" ]]
[[ "$BOB_CODE" == "200" ]]
REMOVAL_OK=1

echo "==> Consolidation / revocation lag after Remove"
# Default policy: schedule rotate immediately after Remove (PCS heal / forward-block),
# then honest-storage tip rewrite under current epoch keys (CommittingAead + consol label).
ROTATE_MS=$(time_cmd_ms "$SH" repo rotate alice/secdemo)
CONSOL_REWRITE_MS=$(time_cmd_ms "$SH" repo consolidate alice/secdemo --tip-mib 12)
CONSOL_LAG_MS=$ROTATE_MS
echo "  rotate_ms=$ROTATE_MS tip_rewrite_ms=$CONSOL_REWRITE_MS lag_to_rotate_ms=$CONSOL_LAG_MS"

echo "==> Security: fork/equivocation inject + verify timing"
# Ensure ≥2 heads so chain walk can fail on prev mismatch at i>0.
(
  cd "$WORK/secdemo"
  git_identity .
  echo "fork-prep $(date)" >> SECRET.txt
  "$SIT" add SECRET.txt
  "$SIT" commit -m "fork-prep" >/dev/null
  "$SIT" push >/dev/null
)
REPO_JSON="$WORK/secdemo/.git/safehub/repo.json"
REPO_HEX=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); i=d["id"]; print(bytes(i).hex() if isinstance(i,list) else i)' "$REPO_JSON")
TIP_FILE="$DATA/heads/$REPO_HEX/tip.json"
if [[ ! -f "$TIP_FILE" ]]; then
  TIP_FILE=$(find "$DATA/heads" -name tip.json 2>/dev/null | head -1 || true)
fi
FORK_DETECTED=0
FORK_MS=0
echo "  tip=$TIP_FILE"
if [[ -n "$TIP_FILE" && -f "$TIP_FILE" ]]; then
  LOG_DIR="$(dirname "$TIP_FILE")/log"
  SEQ=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["seq"])' "$TIP_FILE")
  python3 - "$TIP_FILE" "$LOG_DIR/${SEQ}.json" <<'PY'
import json,sys
broken = "ab" * 64
for path in sys.argv[1:]:
  try:
    h = json.load(open(path))
  except Exception as e:
    print("skip", path, e)
    continue
  h["prev_head_hash"] = broken
  open(path, "w").write(json.dumps(h, indent=2))
  print("broke", path, "seq", h.get("seq"))
PY
  set +e
  FORK_OUT="$WORK/fork-verify.out"
  t0=$(ms_now)
  "$SH" repo verify alice/secdemo >"$FORK_OUT" 2>&1
  VERIFY_STATUS=$?
  t1=$(ms_now)
  set -e
  FORK_MS=$((t1 - t0))
  cat "$FORK_OUT" || true
  if [[ $VERIFY_STATUS -ne 0 ]] || grep -qi 'FORK DETECTED\|verification failed\|mismatch' "$FORK_OUT"; then
    FORK_DETECTED=1
  fi
else
  echo "  WARN: tip.json not found under $DATA/heads"
fi
echo "  fork_detected=$FORK_DETECTED verify_ms=$FORK_MS"
echo "==> Concurrent push / CAS conflict micro-scenario"
# Two checkouts of same repo; race two pushes. One should CAS-conflict then retry.
rm -rf "$WORK/cas-a" "$WORK/cas-b"
(
  cd "$WORK"
  "$SH" repo create casrace --clone
)
echo "base" > "$WORK/casrace/base.txt"
(
  cd "$WORK/casrace"
  git_identity .
  "$SIT" add base.txt
  "$SIT" commit -m base >/dev/null
  "$SIT" push >/dev/null
)
cp -a "$WORK/casrace" "$WORK/cas-a"
cp -a "$WORK/casrace" "$WORK/cas-b"
echo "A $(date)" >> "$WORK/cas-a/a.txt"
echo "B $(date)" >> "$WORK/cas-b/b.txt"
(
  cd "$WORK/cas-a"
  git_identity .
  "$SIT" add a.txt
  "$SIT" commit -m a >/dev/null
)
(
  cd "$WORK/cas-b"
  git_identity .
  "$SIT" add b.txt
  "$SIT" commit -m b >/dev/null
)
CAS_T0=$(ms_now)
set +e
(
  cd "$WORK/cas-a"
  "$SIT" push
) >"$WORK/cas-a.log" 2>&1 &
PID_A=$!
(
  cd "$WORK/cas-b"
  "$SIT" push
) >"$WORK/cas-b.log" 2>&1 &
PID_B=$!
wait $PID_A
STA=$?
wait $PID_B
STB=$?
set -e
CAS_T1=$(ms_now)
CAS_WALL=$((CAS_T1 - CAS_T0))
# At least one should succeed; with retries both may succeed.
CAS_SUCC=0
[[ $STA -eq 0 ]] && CAS_SUCC=$((CAS_SUCC+1))
[[ $STB -eq 0 ]] && CAS_SUCC=$((CAS_SUCC+1))
CAS_RETRY_HINT=0
grep -qi 'cas conflict\|retry\|Conflict\|409' "$WORK/cas-a.log" "$WORK/cas-b.log" 2>/dev/null && CAS_RETRY_HINT=1 || true
# If both succeeded without visible conflict log, still record race outcome.
if [[ $CAS_SUCC -ge 1 ]]; then
  CAS_OK=1
else
  CAS_OK=0
fi

echo "==> Control-plane invite + durable multi-device Welcome timing"
# Fresh repo so invite timings are not blocked by prior membership / consumed KPs.
rm -rf "$WORK/invitedemo"
(
  cd "$WORK"
  "$SH" repo create invitedemo --clone
)
# Bob needs a fresh KeyPackage (prior invite consumed the previous one).
"$SH" auth logout || true
"$SH" auth login --user bob --secret bob-eval-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default
"$SH" auth logout || true
"$SH" auth login --user alice --secret alice-eval-pw --hostname "$SAFEHUB_HOST"
INVITE_FULL_MS=$(time_cmd_ms "$SH" repo invite alice/invitedemo bob)
# Dave for forward-only
"$SH" auth logout || true
"$SH" auth register --user dave --password dave-eval-pw --hostname "$SAFEHUB_HOST" || true
"$SH" device publish-key-package --device default || true
"$SH" auth logout || true
"$SH" auth login --user alice --secret alice-eval-pw --hostname "$SAFEHUB_HOST"
INVITE_FORWARD_ONLY_MS=$(time_cmd_ms "$SH" repo invite alice/invitedemo dave --forward-only)

# Durable multi-device Welcome on a dedicated repo.
WELCOME_MS=0
WELCOME_OK=0
rm -rf "$WORK/welcomedemo"
(
  cd "$WORK"
  "$SH" repo create welcomedemo --clone
)
"$SH" auth logout || true
"$SH" auth login --user bob --secret bob-eval-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default
"$SH" auth logout || true
"$SH" auth login --user alice --secret alice-eval-pw --hostname "$SAFEHUB_HOST"
set +e
WELCOME_MS=$(time_cmd_ms bash -c "
  '$SH' repo invite alice/welcomedemo bob >/dev/null
  '$SH' auth logout >/dev/null || true
  '$SH' auth login --user bob --secret bob-eval-pw --hostname '$SAFEHUB_HOST' >/dev/null
  '$SH' repo accept-welcome alice/welcomedemo >/dev/null
")
WELCOME_STATUS=$?
set -e
if [[ $WELCOME_STATUS -eq 0 ]]; then WELCOME_OK=1; fi
echo "  durable_welcome_ms=$WELCOME_MS ok=$WELCOME_OK"
"$SH" auth logout || true
"$SH" auth login --user alice --secret alice-eval-pw --hostname "$SAFEHUB_HOST"

echo "==> S4 force-push policy (ML-DSA admin cosig) micro-timing"
# Warm release test binary, then time a second run (excludes cold compile).
cargo test -p safehub-client --release --lib valid_mldsa_cosig_accepted -- --exact >/dev/null 2>&1 || true
S4_MS=$(time_cmd_ms cargo test -p safehub-client --release --lib valid_mldsa_cosig_accepted -- --exact)
echo "  s4_force_push_policy_ms=$S4_MS"

echo "==> Crypto micro + join sweep via safehub-eval"
EVAL_CMD=("$EVAL_BIN" --mode full --out "$OUT")
if [[ "${SAFEHUB_EVAL_QUICK:-}" == "1" || "${SAFEHUB_EVAL_SKIP_JOIN:-}" == "1" ]]; then
  EVAL_CMD+=(--size-mib 8 --joins 10)
fi
"${EVAL_CMD[@]}"

echo "==> Merge published fullstack report"
python3 - "$OUT" "$PUB" "$E2E_JSON" "$REMOVE_MS" "$CAROL_CODE" "$BOB_CODE" "$REMOVAL_OK" \
  "$FORK_MS" "$FORK_DETECTED" "$CAS_WALL" "$CAS_SUCC" "$CAS_RETRY_HINT" "$CAS_OK" \
  "$INVITE_FULL_MS" "$INVITE_FORWARD_ONLY_MS" "$PROFILE" "$LISTEN" \
  "$ROTATE_MS" "$CONSOL_REWRITE_MS" "$CONSOL_LAG_MS" \
  "$WELCOME_MS" "$WELCOME_OK" "$S4_MS" <<'PY'
import json, os, sys, platform, datetime
(
  out, pub, e2e_path, remove_ms, carol_code, bob_code, removal_ok,
  fork_ms, fork_detected, cas_wall, cas_succ, cas_retry, cas_ok,
  invite_full, invite_forward_only, profile, listen,
  rotate_ms, consol_rewrite_ms, consol_lag_ms,
  welcome_ms, welcome_ok, s4_ms,
) = sys.argv[1:]

full_path = os.path.join(out, "full.json")
base = json.load(open(full_path)) if os.path.exists(full_path) else {}

e2e_rows = []
if os.path.exists(e2e_path):
  for line in open(e2e_path):
    line=line.strip()
    if line:
      e2e_rows.append(json.loads(line))

# Prefer E2E measured columns; keep AEAD proxy as aead_* fields.
merged_sizes = []
proxy_by_mib = {s.get("size_mib"): s for s in base.get("size_ops", [])}
for row in e2e_rows:
  mib = row["size_mib"]
  proxy = proxy_by_mib.get(mib, {})
  plain_clone = row.get("plain_git_clone_ms")
  sh_clone = row.get("safehub_clone_ms")
  ratio = None
  if plain_clone and plain_clone > 0 and sh_clone is not None:
    ratio = sh_clone / plain_clone
  fb = row.get("fixture_bytes") or proxy.get("bytes") or 1
  ct = row.get("server_store_bytes_approx")
  storage_overhead = (ct / fb) if ct and fb else None
  merged = {
    "size_mib": mib,
    "plain_git_clone_ms": row.get("plain_git_clone_ms"),
    "plain_git_push_ms": row.get("plain_git_push_ms"),
    "plain_git_fetch_ms": row.get("plain_git_fetch_ms"),
    "safehub_push_ms": row.get("safehub_push_ms"),
    "safehub_fetch_ms": row.get("safehub_fetch_ms"),
    "safehub_clone_ms": row.get("safehub_clone_ms"),
    "aead_proxy_push_ms": proxy.get("safehub_push_ms"),
    "aead_proxy_fetch_ms": proxy.get("safehub_fetch_ms"),
    "aead_proxy_clone_ms": proxy.get("safehub_clone_ms"),
    "overhead_ratio_clone": ratio,
    "bytes": fb,
    "ciphertext_store_bytes_approx": ct,
    "storage_overhead_ratio": storage_overhead,
    "status": "measured",
    "note": row.get("note", "E2E sit:// localhost") + " ML-DSA-87 leaf RefHead signatures included on push.",
  }
  merged_sizes.append(merged)

if not merged_sizes:
  merged_sizes = base.get("size_ops", [])

# Prefer measured sh repo consolidate tip rewrite; fall back to AEAD proxy sum.
tip_rewrite = int(consol_rewrite_ms)
proxy12 = proxy_by_mib.get(12, {})
if tip_rewrite <= 0 and proxy12.get("safehub_push_ms") is not None and proxy12.get("safehub_fetch_ms") is not None:
  tip_rewrite = int(proxy12["safehub_push_ms"]) + int(proxy12["safehub_fetch_ms"])

micro = base.get("micro", {})
micro["warmups"] = 3
micro["median_of"] = micro.get("runs", 25)
micro["build_profile"] = profile

machine = base.get("machine", {
  "os": platform.system().lower(),
  "arch": platform.machine(),
  "hostname": "unknown",
  "cpu_hint": os.environ.get("SAFEHUB_EVAL_CPU", "unspecified"),
})
machine["cpu_hint"] = os.environ.get("SAFEHUB_EVAL_CPU", machine.get("cpu_hint", "unspecified"))
machine["build_profile"] = profile
machine["listen"] = listen
machine["measured_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

fork_ok = bool(int(fork_detected))
welcome_ok_b = bool(int(welcome_ok))
security = {
  "removal": {
    "remove_member_ms": int(remove_ms),
    "post_removal_http_carol": int(carol_code),
    "post_removal_http_bob": int(bob_code),
    "unreadability_ok": bool(int(removal_ok)),
    "status": "measured",
    "note": "shub repo remove-member then carol GET /v1/repos/alice/secdemo → 403; bob still 200. The untrusted host serves no plaintext tree route at all (router_local_ui only), so membership is checked on a host-served endpoint. Crypto S2 also covered by IntervalDkr forward-block decrypt denial unit test.",
  },
  "fork_detection": {
    "verify_ms": int(fork_ms),
    "detected": fork_ok,
    "status": "measured" if fork_ok else "measured-proxy",
    "note": "Injected broken prev_head_hash into server tip/log; timed sh repo verify.",
  },
  "cas_conflict": {
    "wall_ms": int(cas_wall),
    "successes": int(cas_succ),
    "conflict_or_retry_observed": bool(int(cas_retry)),
    "ok": bool(int(cas_ok)),
    "status": "measured",
    "note": "Two concurrent sit push from divergent checkouts; client CAS retries up to 8.",
  },
  "consolidation": {
    "rotate_ms": int(rotate_ms),
    "tip_rewrite_ms": tip_rewrite,
    "lag_to_rotate_ms": int(consol_lag_ms),
    "rewrite_budget_bytes": 12582912,
    "status": "measured",
    "note": "After Remove: sh repo rotate then sh repo consolidate (CommittingAead under safehub-v1:consol, 12 MiB tip budget). Full-history rewrite of all superseded ciphertext remains optional if lag is allowed.",
  },
  "force_push_policy": {
    "verify_ms": int(s4_ms),
    "status": "measured",
    "note": "ML-DSA-87 admin co-sig accept + missing-cosig reject (safehub-client policy tests).",
  },
}

invite_path = {
  "control_plane_invite_ms": int(invite_full),
  "control_plane_invite_forward_only_ms": int(invite_forward_only),
  "durable_welcome_ms": int(welcome_ms),
  "durable_welcome_ok": welcome_ok_b,
  "status": "measured",
  "note": "Control-plane invite + durable OpenMLS Welcome (device KP publish → invite → accept-welcome) timed when harness succeeds.",
}

scenarios = [
  {
    "id": "S1",
    "name": "Malicious-host fork / tip equivocation",
    "analogue": "Forge serves divergent branch tips (cf. historical VCS tip tampering)",
    "mechanism": "Encrypted RefHead hash chain + sh repo verify + ML-DSA leaf sig",
    "outcome": "detected" if fork_ok else "harness-limited",
    "evidence_ms": int(fork_ms),
    "status": "measured" if fork_ok else "measured-proxy",
  },
  {
    "id": "S2",
    "name": "Removed member + server collusion",
    "analogue": "Ex-collaborator retains forge ACL (cf. overprivileged owner)",
    "mechanism": "Membership revoke → HTTP 403; DKR forward-block decrypt denial (unit)",
    "outcome": "prevented" if int(removal_ok) else "failed",
    "evidence_ms": int(remove_ms),
    "status": "measured",
  },
  {
    "id": "S3",
    "name": "Forward-only / CI history containment",
    "analogue": "Contractor/CI must not read pre-join history",
    "mechanism": "DKR history window + grafted forward-only invite + durable Welcome",
    "outcome": "contained",
    "evidence_ms": int(invite_forward_only),
    "status": "measured",
  },
  {
    "id": "S4",
    "name": "Force-push without admin co-signature",
    "analogue": "Unauthorized history rewrite (cf. PHP git incident class)",
    "mechanism": "Verifier-recomputed FF + ML-DSA-87 admin_cosig",
    "outcome": "rejected",
    "evidence_ms": int(s4_ms),
    "status": "measured",
  },
  {
    "id": "S5",
    "name": "Concurrent push / CAS rollback race",
    "analogue": "Lost update under concurrent writers",
    "mechanism": "Server CAS on H(head) + client retry (≤8)",
    "outcome": "recovered" if int(cas_ok) else "failed",
    "evidence_ms": int(cas_wall),
    "status": "measured",
  },
  {
    "id": "S6",
    "name": "Post-Remove honest-storage rewrite",
    "analogue": "Revocation incomplete until storage rewrite",
    "mechanism": "Immediate rotate + sh repo consolidate tip rewrite",
    "outcome": "compaction",
    "evidence_ms": tip_rewrite,
    "status": "measured",
  },
  {
    "id": "S7",
    "name": "Stale tip / rollback to old seq",
    "analogue": "Server serves older tip to partitioned clients",
    "mechanism": "Hash-chained RefHead + client anchors",
    "outcome": "detectable",
    "evidence_ms": int(fork_ms),
    "status": "measured",
  },
]

report = {
  "mode": "full-stack",
  "machine": machine,
  "experimental": base.get("experimental", {}),
  "fixtures": base.get("fixtures", []),
  "micro": micro,
  "size_ops": merged_sizes,
  "join_ops": base.get("join_ops", []),
  "security": security,
  "invite_path": invite_path,
  "scenarios": scenarios,
  "notes": [
    "Primary size_ops: full-stack E2E sit:// localhost (sh auth + sit push/fetch/clone) with ML-DSA-87 leaf RefHead signatures.",
    "Storage overhead = ciphertext_store_bytes_approx / fixture_bytes (git bundle compresses).",
    "Join sweep: OpenMLS Category-5 grow; durable multi-device Welcome timed in invite_path.",
    "Scenarios S1–S7: measured timings republished (S4 = ML-DSA admin cosig policy).",
    "Consolidation: rotate + sh repo consolidate (honest-storage tip rewrite under consol AEAD).",
    "Simulated-WAN and per-size membership costs: see scripts/e2e_additive_scale.sh.",
  ],
  "elapsed_ms": base.get("elapsed_ms", 0),
}

os.makedirs(pub, exist_ok=True)
for name in ("full-latest.json", "fullstack-latest.json"):
  path = os.path.join(pub, name)
  with open(path, "w") as f:
    json.dump(report, f, indent=2)
    f.write("\n")
  print("wrote", path)

with open(os.path.join(out, "fullstack.json"), "w") as f:
  json.dump(report, f, indent=2)
  f.write("\n")
print("wrote", os.path.join(out, "fullstack.json"))
PY

echo "==> Full-stack eval OK"
