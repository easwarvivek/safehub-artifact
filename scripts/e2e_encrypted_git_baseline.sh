#!/usr/bin/env bash
# Eval E08 — measured encrypted-Git baselines: sit vs plain git vs git-crypt
# vs git-remote-gcrypt.
#
# The previous generator produced analytic bars for git-crypt and
# git-remote-gcrypt on the grounds that the binaries were unavailable. They are
# installable (`brew install git-crypt git-remote-gcrypt`), so this harness
# measures them instead. A tool that is genuinely absent is reported absent --
# never as a modelled bar.
#
# All four arms carry a byte-identical working tree and run against a local
# remote, so the comparison is transport+crypto, not network.
#
# Env:
#   SAFEHUB_EGB_TREE_MIB=16     working-tree size
#   SAFEHUB_EGB_PUSHES=8        incremental pushes per arm
#   SAFEHUB_EVAL_REPS=3         clone repetitions
#
# Publishes: code/eval/published/encrypted-git-baseline-latest.json
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/eval_common.sh"

OUT="${SAFEHUB_EGB_OUT:-$EVAL_PUB/encrypted-git-baseline-latest.json}"
TREE_MIB="${SAFEHUB_EGB_TREE_MIB:-16}"
PUSHES="${SAFEHUB_EGB_PUSHES:-8}"
LISTEN="127.0.0.1:18131"
export SAFEHUB_HOST="http://$LISTEN"

DATA="$(mktemp -d /tmp/safehub-egb-data.XXXXXX)"
CFG="$(mktemp -d /tmp/safehub-egb-cfg.XXXXXX)"
WORK="$(mktemp -d /tmp/safehub-egb-work.XXXXXX)"
GNUPGHOME="$WORK/gnupg"
ROWS="$WORK/rows.jsonl"
: >"$ROWS"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
export HOME="$CFG"
export XDG_CONFIG_HOME="$CFG/.config"
export SAFEHUB_DATA="$DATA"
export GNUPGHOME
mkdir -p "$XDG_CONFIG_HOME"

SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$DATA" "$CFG" "$WORK"
}
trap cleanup EXIT

have() { command -v "$1" >/dev/null 2>&1; }

GIT_CRYPT_OK=0
GCRYPT_OK=0
have git-crypt && GIT_CRYPT_OK=1
have git-remote-gcrypt && GCRYPT_OK=1
have gpg || GCRYPT_OK=0
echo "==> tools: git-crypt=$GIT_CRYPT_OK git-remote-gcrypt=$GCRYPT_OK"

eval_build safehub-server safehub-cli sit-remote-safehub
eval_start_server "$LISTEN" "$DATA"
"$SH" auth register --user alice --password alice-egb-pw --hostname "$SAFEHUB_HOST"
"$SH" device publish-key-package --device default || true

# The working tree every arm receives. Either a real checkout (so the storage
# comparison is not driven by the compressibility of generated filler) or a
# synthetic source-shaped tree. Generated once and copied into every arm so all
# four transfer identical bytes.
SRC="$WORK/src-master"
mkdir -p "$SRC"
if [[ -n "${SAFEHUB_EGB_REAL_TREE:-}" ]]; then
  echo "==> using real working tree: $SAFEHUB_EGB_REAL_TREE"
  # Copy tracked content only; a .git directory inside the fixture would be
  # committed as data and make the arms incomparable.
  (cd "$SAFEHUB_EGB_REAL_TREE" && tar cf - --exclude=.git .) | (cd "$SRC" && tar xf -)
  REAL_BYTES=$(dir_bytes "$SRC")
  REAL_FILES=$(find "$SRC" -type f | wc -l | tr -d ' ')
  echo "    $REAL_FILES files, $REAL_BYTES bytes"
  FIXTURE_KIND="real:$(basename "$SAFEHUB_EGB_REAL_TREE")"
else
FIXTURE_KIND="synthetic-compressible"
python3 - "$SRC" "$TREE_MIB" <<'PY'
import random, sys
from pathlib import Path
root, mib = Path(sys.argv[1]), int(sys.argv[2])
rng = random.Random(20260817)
idents = ["resolve", "encode", "verify", "merge", "index", "flush", "render"]
types = ["u64", "usize", "String", "Vec<u8>"]
target = mib * 1024 * 1024
written = 0
f = 0
while written < target:
    lines = ["// Copyright (c) 2026 The SafeHub Evaluation Authors.",
             "use std::collections::BTreeMap;", "use anyhow::Result;", ""]
    size = 0
    while size < 128 * 1024 and written + size < target:
        name = rng.choice(idents); ty = rng.choice(types)
        block = [f"/// Unit {f}.",
                 f"pub fn {name}_{f}(input: &{ty}) -> Result<{ty}> {{",
                 "    let mut out = input.clone();",
                 f"    for _ in 0..{rng.randint(1, 9)} {{",
                 "        out = out.clone();", "    }", "    Ok(out)", "}", ""]
        lines.extend(block)
        size += sum(len(x) + 1 for x in block)
    p = root / f"mod_{f // 32}" / f"unit_{f}.rs"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines))
    written += size
    f += 1
print(f"    generated {f} files, {written/1048576:.1f} MiB")
PY
fi
export FIXTURE_KIND

# One revision body, shared by every arm's i-th push.
mkdir -p "$WORK/revs"
python3 - "$WORK/revs" "$PUSHES" <<'PY'
import random, sys
from pathlib import Path
root, n = Path(sys.argv[1]), int(sys.argv[2])
for i in range(n):
    rng = random.Random(9000 + i)
    lines = [f"// revision {i}"]
    for j in range(700):
        lines.append(f"pub const K_{i}_{j}: u64 = {rng.randint(0, 1 << 40)};")
    (root / f"rev_{i}.rs").write_text("\n".join(lines))
PY

emit_row() {
  ARM="$1" AVAIL="$2" PUSH="$3" CLONE="$4" STORE="$5" NOTE="$6" ROWS="$ROWS" \
    python3 - <<'PY'
import json, os
row = {
    "arm": os.environ["ARM"],
    "available": os.environ["AVAIL"] == "1",
    "push_ms": json.loads(os.environ["PUSH"]) if os.environ["PUSH"] else None,
    "clone_ms": json.loads(os.environ["CLONE"]) if os.environ["CLONE"] else None,
    "remote_bytes": int(os.environ["STORE"]) if os.environ["STORE"] else None,
    "measured": os.environ["AVAIL"] == "1",
    "status": "measured" if os.environ["AVAIL"] == "1" else "tool-absent",
    "note": os.environ["NOTE"],
}
with open(os.environ["ROWS"], "a") as f:
    f.write(json.dumps(row) + "\n")
if row["push_ms"]:
    print("    {:22s} push={}ms clone={}ms remote={}B".format(
        row["arm"], row["push_ms"]["median"], row["clone_ms"]["median"],
        row["remote_bytes"]))
else:
    print("    {:22s} NOT MEASURED ({})".format(row["arm"], row["note"]))
PY
}

# ---------------------------------------------------------------- plain git
echo "==> arm: plain-git"
run_git_arm() {
  local name="$1" setup_hook="$2" remote_kind="$3"
  local wt="$WORK/$name" bare="$WORK/$name.git"
  rm -rf "$wt" "$bare"
  git init --bare -q --template= --initial-branch=main "$bare"
  mkdir -p "$wt"
  git -C "$wt" init -q --template= --initial-branch=main
  eval_git_identity "$wt"
  cp -R "$SRC/." "$wt/"
  ( cd "$wt" && $setup_hook )
  if [[ "$remote_kind" == "gcrypt" ]]; then
    git -C "$wt" remote add origin "gcrypt::file://$bare"
  else
    git -C "$wt" remote add origin "file://$bare"
  fi
  git -C "$wt" add -A
  git -C "$wt" commit -qm "seed"
  git -C "$wt" push -q origin HEAD 2>/dev/null || git -C "$wt" push -q origin main

  local samples=()
  local i
  for ((i = 0; i < PUSHES; i++)); do
    mkdir -p "$wt/src/rev"
    cp "$WORK/revs/rev_$i.rs" "$wt/src/rev/rev_$i.rs"
    git -C "$wt" add -A
    git -C "$wt" commit -qm "rev $i"
    samples+=("$(time_cmd_ms git -C "$wt" push -q origin HEAD)")
  done

  local clones=()
  local rep
  for ((rep = 0; rep < EVAL_REPS; rep++)); do
    rm -rf "$WORK/$name-clone"
    if [[ "$remote_kind" == "gcrypt" ]]; then
      clones+=("$(time_cmd_ms git clone -q "gcrypt::file://$bare" "$WORK/$name-clone")")
    else
      clones+=("$(time_cmd_ms git clone -q "file://$bare" "$WORK/$name-clone")")
    fi
  done
  rm -rf "$WORK/$name-clone"
  PUSH_STATS="$(stats_json "${samples[@]}")"
  CLONE_STATS="$(stats_json "${clones[@]}")"
  REMOTE_BYTES="$(dir_bytes "$bare")"
}

run_git_arm plain true plain
emit_row "plain-git" 1 "$PUSH_STATS" "$CLONE_STATS" "$REMOTE_BYTES" \
  "local bare remote over file://; no encryption"

# ---------------------------------------------------------------- git-crypt
if ((GIT_CRYPT_OK)); then
  echo "==> arm: git-crypt"
  setup_git_crypt() {
    git-crypt init -k default >/dev/null 2>&1 || git-crypt init >/dev/null 2>&1
    printf '*.rs filter=git-crypt diff=git-crypt\n' >.gitattributes
  }
  if run_git_arm gitcrypt setup_git_crypt plain; then
    emit_row "git-crypt" 1 "$PUSH_STATS" "$CLONE_STATS" "$REMOTE_BYTES" \
      "symmetric key, path filters on *.rs; graph and paths remain host-visible"
  else
    emit_row "git-crypt" 0 "" "" "" "arm failed to run"
  fi
else
  emit_row "git-crypt" 0 "" "" "" \
    "binary not installed on this host (brew install git-crypt)"
fi

# ------------------------------------------------------- git-remote-gcrypt
if ((GCRYPT_OK)); then
  echo "==> arm: git-remote-gcrypt"
  # Batch-mode throwaway key: gcrypt needs a usable signing/encryption key.
  cat >"$WORK/keyparams" <<'EOF'
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Name-Real: SafeHub Eval
Name-Email: eval@safehub.invalid
Expire-Date: 0
%commit
EOF
  if gpg --batch --generate-key "$WORK/keyparams" >/dev/null 2>&1; then
    KEYID="$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr:/{print $10; exit}')"
    setup_gcrypt() {
      git config gcrypt.participants "$KEYID"
      git config gcrypt.publish-participants true
    }
    if run_git_arm gcrypt setup_gcrypt gcrypt; then
      emit_row "git-remote-gcrypt" 1 "$PUSH_STATS" "$CLONE_STATS" "$REMOTE_BYTES" \
        "whole-remote PGP; no per-member epochs, no ref-rollback protection"
    else
      emit_row "git-remote-gcrypt" 0 "" "" "" "arm failed to run"
    fi
  else
    emit_row "git-remote-gcrypt" 0 "" "" "" "gpg key generation failed"
  fi
else
  emit_row "git-remote-gcrypt" 0 "" "" "" \
    "binary not installed on this host (brew install git-remote-gcrypt)"
fi

# ------------------------------------------------------------------- safehub
echo "==> arm: safehub (sit://)"
REPO="egb"
rm -rf "$WORK/$REPO"
(cd "$WORK" && "$SH" repo create "$REPO" --clone >/dev/null)
eval_git_identity "$WORK/$REPO"
cp -R "$SRC/." "$WORK/$REPO/"
(cd "$WORK/$REPO" && git add -A && git commit -qm "seed" && "$SIT" push >/dev/null 2>&1)
BASE_CT="$(dir_bytes "$DATA")"
sit_samples=()
for ((i = 0; i < PUSHES; i++)); do
  mkdir -p "$WORK/$REPO/src/rev"
  cp "$WORK/revs/rev_$i.rs" "$WORK/$REPO/src/rev/rev_$i.rs"
  (cd "$WORK/$REPO" && git add -A && git commit -qm "rev $i" >/dev/null)
  sit_samples+=("$(time_cmd_ms bash -c "cd '$WORK/$REPO' && '$SIT' push")")
done
sit_clones=()
for ((rep = 0; rep < EVAL_REPS; rep++)); do
  rm -rf "$WORK/$REPO-clone"
  sit_clones+=("$(time_cmd_ms bash -c "cd '$WORK' && '$SIT' clone alice/$REPO '$REPO-clone'")")
done
rm -rf "$WORK/$REPO-clone"
emit_row "safehub" 1 "$(stats_json "${sit_samples[@]}")" \
  "$(stats_json "${sit_clones[@]}")" "$(dir_bytes "$DATA")" \
  "sit:// against safehub-server; contents, paths, refs and graph all sealed"

echo "==> publishing $OUT"
ROWS="$ROWS" OUT="$OUT" TREE_MIB="$TREE_MIB" PUSHES="$PUSHES" \
  REPS="$EVAL_REPS" FIXTURE_KIND="$FIXTURE_KIND" \
  SRC_BYTES="$(dir_bytes "$SRC")" \
  python3 "$SCRIPT_DIR/lib/publish_encrypted_git_baseline.py"
echo "==> done"
