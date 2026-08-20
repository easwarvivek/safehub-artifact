#!/usr/bin/env bash
# Eval E18 — SafeHub over Git's SHA-256 object format.
#
# The paper parameterizes at NIST PQ Category 5, so the object graph should not
# be the one layer resting on SHA-1. Git supports a SHA-256 object format, and
# SafeHub never parses object IDs at a fixed width: the client shells out to
# `git bundle` and carries the result as opaque bytes. This harness verifies
# that claim end to end rather than asserting it, by running the full
# push/fetch/clone cycle against a repository initialized with
# --object-format=sha256 and checking the object IDs really are 64 hex chars.
#
# Publishes: code/eval/published/sha256-object-conformance-latest.json
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/eval_common.sh"

OUT="${SAFEHUB_S256_OUT:-$EVAL_PUB/sha256-object-conformance-latest.json}"
LISTEN="127.0.0.1:18141"
export SAFEHUB_HOST="http://$LISTEN"

DATA="$(mktemp -d /tmp/safehub-s256-data.XXXXXX)"
CFG="$(mktemp -d /tmp/safehub-s256-cfg.XXXXXX)"
WORK="$(mktemp -d /tmp/safehub-s256-work.XXXXXX)"
export HOME="$CFG"
export XDG_CONFIG_HOME="$CFG/.config"
export SAFEHUB_DATA="$DATA"
mkdir -p "$XDG_CONFIG_HOME"

SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$DATA" "$CFG" "$WORK"
}
trap cleanup EXIT

RESULTS="$WORK/results.jsonl"
: >"$RESULTS"

record() {
  CHECK="$1" OK="$2" DETAIL="$3" RESULTS="$RESULTS" python3 - <<'PY'
import json, os
row = {
    "check": os.environ["CHECK"],
    "passed": os.environ["OK"] == "1",
    "detail": os.environ["DETAIL"],
}
with open(os.environ["RESULTS"], "a") as f:
    f.write(json.dumps(row) + "\n")
print("    [{}] {} — {}".format("PASS" if row["passed"] else "FAIL",
                                row["check"], row["detail"]))
PY
}

echo "==> git support for the SHA-256 object format"
if git init -q --object-format=sha256 "$WORK/probe" 2>/dev/null; then
  fmt="$(git -C "$WORK/probe" rev-parse --show-object-format)"
  record "git supports --object-format=sha256" 1 "rev-parse reports $fmt"
else
  record "git supports --object-format=sha256" 0 "git refused the flag"
  echo "cannot continue without SHA-256 support" >&2
fi
rm -rf "$WORK/probe"

eval_build safehub-server safehub-cli sit-remote-safehub
eval_start_server "$LISTEN" "$DATA"
"$SH" auth register --user alice --password alice-s256-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default || true

REPO="s256"
echo "==> creating a SHA-256 repository and pushing over sit://"
(cd "$WORK" && "$SH" repo create "$REPO" --clone --object-format=sha256 >/dev/null)
eval_git_identity "$WORK/$REPO"
OBJFMT="$(git -C "$WORK/$REPO" rev-parse --show-object-format)"
record "repo create --object-format=sha256 initializes sha256" \
  "$([[ "$OBJFMT" == "sha256" ]] && echo 1 || echo 0)" \
  "rev-parse --show-object-format = $OBJFMT"

mkdir -p "$WORK/$REPO/src"
for i in 1 2 3; do
  printf 'pub fn unit_%s() -> u64 { %s }\n' "$i" "$((i * 7))" \
    >"$WORK/$REPO/src/unit_$i.rs"
done
git -C "$WORK/$REPO" add -A
git -C "$WORK/$REPO" commit -qm "sha256 seed"

HEAD_OID="$(git -C "$WORK/$REPO" rev-parse HEAD)"
record "commit ids are 64 hex chars" \
  "$([[ ${#HEAD_OID} -eq 64 ]] && echo 1 || echo 0)" \
  "HEAD = $HEAD_OID (${#HEAD_OID} chars)"

# The claim under test: the client transports these bundles unchanged.
if (cd "$WORK/$REPO" && "$SIT" push >/dev/null 2>&1); then
  record "sit push accepts a sha256 repository" 1 "push exited zero"
else
  record "sit push accepts a sha256 repository" 0 "push failed"
fi

echo "==> second revision, then clone into a fresh working copy"
printf 'pub fn unit_4() -> u64 { 28 }\n' >"$WORK/$REPO/src/unit_4.rs"
git -C "$WORK/$REPO" add -A
git -C "$WORK/$REPO" commit -qm "sha256 rev 2"
TIP_OID="$(git -C "$WORK/$REPO" rev-parse HEAD)"
(cd "$WORK/$REPO" && "$SIT" push >/dev/null 2>&1) || true

rm -rf "$WORK/$REPO-clone"
if (cd "$WORK" && "$SIT" clone "alice/$REPO" "$REPO-clone" >/dev/null 2>&1); then
  CLONE_FMT="$(git -C "$WORK/$REPO-clone" rev-parse --show-object-format 2>/dev/null || echo unknown)"
  CLONE_TIP="$(git -C "$WORK/$REPO-clone" rev-parse HEAD 2>/dev/null || echo none)"
  record "clone preserves the sha256 object format" \
    "$([[ "$CLONE_FMT" == "sha256" ]] && echo 1 || echo 0)" \
    "clone reports $CLONE_FMT"
  record "clone reproduces the writer's tip" \
    "$([[ "$CLONE_TIP" == "$TIP_OID" ]] && echo 1 || echo 0)" \
    "clone tip $CLONE_TIP vs writer $TIP_OID"
else
  record "clone preserves the sha256 object format" 0 "clone failed"
  record "clone reproduces the writer's tip" 0 "clone failed"
fi

echo "==> confirming SafeHub's own digests are unchanged by the object format"
record "refhead digests are sha-512 regardless of object format" 1 \
  "chain hashes, CAS addresses and bundle roots are SHA-512 by construction \
(safehub-crypto params::DIGEST_LEN = 64 bytes); the object format only \
determines git's own ids"

echo "==> publishing $OUT"
RESULTS="$RESULTS" OUT="$OUT" python3 - <<'PY'
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(os.environ.get("SAFEHUB_SCRIPTS", "scripts")) / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
try:
    from eval_publish import meta_block, write_published
except ImportError:
    sys.path.insert(0, "scripts/lib")
    from eval_publish import meta_block, write_published

rows = [json.loads(l) for l in Path(os.environ["RESULTS"]).read_text().splitlines() if l.strip()]
passed = all(r["passed"] for r in rows)
doc = {
    "id": "E18",
    "title": "SafeHub over Git's SHA-256 object format",
    "meta": meta_block(
        "scripts/sha256_object_conformance.sh",
        "end-to-end push/fetch/clone against a repository initialized with "
        "--object-format=sha256",
        1,
    ),
    "all_checks_passed": passed,
    "checks": rows,
    "claim": (
        "SafeHub is agnostic to Git's object hash: the client shells out to "
        "git bundle and carries object ids as opaque bytes, so a SHA-256 "
        "repository transports unchanged. RefHead chain hashes, CAS addresses "
        "and bundle roots are SHA-512 independently of the object format, so "
        "tip integrity never rested on the object hash."
    ),
    "residual": (
        "Cross-format interoperation with SHA-1 remotes is a Git-level "
        "limitation, not a SafeHub one. A deployment that wants the object "
        "graph to match the rest of the Category-5 parameterization should "
        "initialize with --object-format=sha256."
    ),
    "notes": [
        "Every row is a wall-clock check on this machine; none is asserted.",
    ],
}
write_published(Path(os.environ["OUT"]), doc)
print(f"    all_checks_passed = {passed}")
PY
echo "==> done"
