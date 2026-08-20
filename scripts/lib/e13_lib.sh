#!/usr/bin/env bash
# E13 shared library: arm drivers, per-operation floors, and postcondition
# guards for the full benchmark matrix.
#
# Design: code/eval/design-e13-full-matrix.md.
#
# Two rules are enforced here rather than left to each call site, because both
# have already cost a published result:
#
#   1. An operation's floor is the SAME operation at zero payload on the SAME
#      tool. The withdrawn corrected columns subtracted a no-op fetch from a
#      push; with nine operations and four tools there are 36 floors, so the
#      rule has to be mechanical rather than remembered.
#   2. Exit zero is not evidence of work. Every operation asserts a
#      postcondition on the resulting DAG or working tree before its timing is
#      kept, and a failed command contributes no sample.

# ---------------------------------------------------------------- timing ----

# Time a command, keep its status. E13_MS is set either way; the caller must
# consult the return value. Restores the caller's errexit rather than forcing
# it, so a helper cannot turn a reporting script into an aborting one.
e13_timed() {
  local t0 t1 rc had_e=0
  case "$-" in *e*) had_e=1 ;; esac
  t0=$(ms_now)
  set +e
  "$@" >/dev/null 2>&1
  rc=$?
  t1=$(ms_now)
  if [[ "$had_e" == "1" ]]; then set -e; fi
  E13_MS=$((t1 - t0))
  return $rc
}

# Append $E13_MS to an array only when the command succeeded.
e13_sample() {
  local arr="$1" rc="$2"
  if [[ "$rc" -eq 0 ]]; then eval "$arr+=($E13_MS)"; fi
  return "$rc"
}

# ------------------------------------------------------------ postconditions

# A clone must have produced a working tree. `git clone` of a gcrypt remote
# exits 0 having checked out nothing ("remote HEAD refers to nonexistent ref"),
# so timing it without this check compares a partial operation against complete
# ones -- which is what the existing published gcrypt clone number does.
e13_clone_nonempty() {
  local dir="$1" n
  [[ -d "$dir" ]] || return 1
  n=$(find "$dir" -mindepth 1 -maxdepth 1 ! -name .git | wc -l | tr -d ' ')
  [[ "$n" -gt 0 ]]
}

# A clone must carry the same tree as its source.
e13_tree_equal() {
  local a="$1" b="$2" ta tb
  ta=$(git -C "$a" rev-parse HEAD^{tree} 2>/dev/null) || return 1
  tb=$(git -C "$b" rev-parse HEAD^{tree} 2>/dev/null) || return 1
  [[ -n "$ta" && "$ta" == "$tb" ]]
}

# ---- corpus ----------------------------------------------------------------
# Shared by both harnesses so a point of a given nominal size is the same
# corpus in every experiment.

# Compressible, source-shaped text. Random bytes would defeat delta compression
# on every arm and turn this into an I/O measurement.
gen_file() {
  python3 - "$1" "$2" "$3" <<'PY'
import random, sys
from pathlib import Path
path, kib, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rng = random.Random(seed)
ids = ["resolve","encode","verify","merge","index","flush","render"]
tys = ["u64","usize","String","Vec<u8>"]
out, size, i = [], 0, 0
while size < kib*1024:
    b = (f"/// unit {seed}_{i}\n"
         f"pub fn {rng.choice(ids)}_{seed}_{i}(x: &{rng.choice(tys)}) -> u64 {{\n"
         f"    let mut o = 0u64; for _ in 0..{rng.randint(1,9)} {{ o += 1; }} o\n}}\n")
    out.append(b); size += len(b); i += 1
Path(path).parent.mkdir(parents=True, exist_ok=True)
Path(path).write_text("".join(out))
PY
}

# Replace roughly `kib` KiB in the MIDDLE of an existing file, leaving its size
# unchanged. This is the operation git-crypt cannot exploit: it re-encrypts the
# whole file regardless of how little changed.
edit_file() {
  python3 - "$1" "$2" "$3" <<'PY'
import random, sys
from pathlib import Path
path, kib, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
p = Path(path); text = p.read_text()
n = kib * 1024
rng = random.Random(seed)
repl = "".join(f"// edit {seed} {rng.randint(0,10**9)}\n" for _ in range(max(1, n // 32)))[:n]
mid = max(0, (len(text) - len(repl)) // 2)
p.write_text(text[:mid] + repl + text[mid + len(repl):])
PY
}

# ---- split client/server -----------------------------------------------------
# With SAFEHUB_E13_SERVER set, the remotes live on another machine: git arms
# push over smart HTTP to git-http-backend, SafeHub to safehub-server, and the
# bare repositories are created and measured through the control service
# (scripts/e13_remote_service.py). Unset, everything is local and the arms use
# file:// as before.
#
# This matters beyond realism. On one box the git arms used file://, which skips
# the network stack entirely, while SafeHub spoke HTTP -- so SafeHub was charged
# for a transport the others avoided. Over HTTP every arm speaks the same
# protocol, which is the methodology the parity benchmark already uses.
e13_remote_mode() { [[ -n "${SAFEHUB_E13_SERVER:-}" ]]; }

# Two client machines share one server, so every repository this client creates
# carries its namespace. Without it the boxes collide on names and, worse, read
# each other's storage growth as their own.
e13_remote_name() { echo "${SAFEHUB_E13_NS:-local}-$(basename "$1" .bare)"; }

e13_git_url()  { echo "http://${SAFEHUB_E13_SERVER:?remote mode needs SAFEHUB_E13_SERVER}:${SAFEHUB_E13_GIT_PORT:-18191}/$1.git"; }
e13_svc_url()  { echo "http://${SAFEHUB_E13_SERVER:?remote mode needs SAFEHUB_E13_SERVER}:${SAFEHUB_E13_SVC_PORT:-18192}"; }

# Create the bare repository that an arm pushes to, wherever it lives.
e13_make_remote() {   # local_bare_path -> echoes the URL to push to
  local bare="$1" name
  name="$(e13_remote_name "$bare")"
  if e13_remote_mode; then
    curl -sf -X POST "$(e13_svc_url)/repo/create?name=$name" >/dev/null || return 1
    e13_git_url "$name"
  else
    rm -rf "$bare"
    git init --bare -q --template= --initial-branch=main "$bare" || return 1
    echo "file://$bare"
  fi
}

# The URL of a remote that already exists, for clone paths.
e13_arm_url() {   # local_bare_path -> url
  if e13_remote_mode; then e13_git_url "$(e13_remote_name "$1")"; else echo "file://$1"; fi
}

# What the remote holds, in bytes, after packing. Packing matters: loose objects
# and packs are two representations of the same content, so an arm whose push
# leaves objects loose would look several times more expensive than one whose
# push packs. Call between points, never inside a timer.
#
# SafeHub's remote is the server's data directory rather than a bare repository,
# so it is passed explicitly instead of being read from a harness global.
e13_remote_size() {   # arm bare_or_name safehub_data -> bytes
  local arm="$1" bare="$2" data="${3:-}"
  if e13_remote_mode; then
    # The remote is on another machine, so its storage is read through the
    # control service, which repacks before measuring exactly as the local
    # path does.
    local url
    if [[ "$arm" == "safehub" ]]; then url="$(e13_svc_url)/safehub/size"
    else url="$(e13_svc_url)/repo/size?name=$(e13_remote_name "$bare")"; fi
    curl -sf "$url" 2>/dev/null | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("bytes",0))
except Exception: print(0)' || echo 0
    return
  fi
  if [[ "$arm" == "safehub" ]]; then dir_bytes "$data" 2>/dev/null || echo 0
  else
    git -C "$bare" gc --quiet --prune=now >/dev/null 2>&1 || true
    dir_bytes "$bare" 2>/dev/null || echo 0
  fi
}

# The repository whose pushes land on the remote: the ciphertext mirror for
# sgit, the working tree itself otherwise.
e13_pushing_repo() { if e13_is_sgit "$1"; then e13_sgit_ct "$2"; else echo "$2"; fi; }

# The remote tip before a push, for the thin-pack measurement. gcrypt keeps an
# encrypted manifest and SafeHub an encrypted RefHead, so neither exposes a
# readable ref map -- that opacity is the security property. Those arms are read
# on storage growth alone.
e13_remote_tip() {   # arm bare_or_name -> oid or empty
  case "$1" in
    git|gitcrypt|sgitchar|sgitline)
      if e13_remote_mode; then
        git ls-remote "$(e13_git_url "$(e13_remote_name "$2")")" refs/heads/main 2>/dev/null | awk '{print $1}'
      else
        git -C "$2" rev-parse --verify -q main 2>/dev/null || true
      fi ;;
    *) echo "" ;;
  esac
}

# A clone carries the same CONTENT as its source. e13_tree_equal compares Git
# tree oids, which sgit's clone has none of: it writes decrypted plaintext into
# an ordinary directory. Comparing content covers both, and for the encrypted
# arms it is the only thing that distinguishes a working clone from one that
# exits 0 having checked out nothing.
e13_clone_matches() {   # source_worktree clone_dir
  local a="$1" b="$2"
  [[ -d "$a" && -d "$b" ]] || return 1
  diff -r --exclude=.git --exclude=.gitattributes --exclude=.sgit \
       "$a" "$b" >/dev/null 2>&1
}

# The remote tip advanced to what we just pushed.
e13_remote_at() {
  local bare="$1" ref="$2" want="$3" got
  if e13_remote_mode; then
    got=$(git ls-remote "$(e13_git_url "$(e13_remote_name "$bare")")" "refs/heads/$ref" 2>/dev/null | awk '{print $1}')
  else
    got=$(git -C "$bare" rev-parse "refs/heads/$ref" 2>/dev/null) || return 1
  fi
  [[ -n "$got" && "$got" == "$want" ]]
}

# A merge commit has exactly two parents; `merge --no-ff` can still
# fast-forward when the branch is behind.
e13_is_merge() {
  local repo="$1" rev="${2:-HEAD}" fields
  fields=$(git -C "$repo" rev-list --parents -n1 "$rev" 2>/dev/null | wc -w | tr -d ' ')
  [[ "$fields" == "3" ]]
}

# A rebase rewrote ids onto the intended base. The last clause separates a
# rebase from appending commits, which would also move the tip.
e13_is_rebase() {
  local repo="$1" old="$2" new="$3" base="$4"
  [[ -n "$old" && -n "$new" && -n "$base" && "$old" != "$new" ]] || return 1
  git -C "$repo" merge-base --is-ancestor "$base" "$new" 2>/dev/null || return 1
  ! git -C "$repo" merge-base --is-ancestor "$old" "$new" 2>/dev/null
}

# A non-fast-forward update replaces a tip the old tip does not reach.
e13_is_non_ff() {
  local repo="$1" old="$2" new="$3"
  [[ -n "$old" && -n "$new" && "$old" != "$new" ]] || return 1
  ! git -C "$repo" merge-base --is-ancestor "$old" "$new" 2>/dev/null
}

# SafeHub records what the client actually sent. Selected by head sequence, not
# mtime: several pushes land inside one mtime second and `ls -t` then orders
# them arbitrarily, which reads the wrong file and reports a real force push as
# unforced.
e13_push_was_forced() {
  local repo="$1" meta
  meta=$(ls "$repo/.git/safehub"/push-*.json 2>/dev/null \
         | sed 's/.*\/push-\([0-9]*\)\.json/\1 &/' \
         | sort -n -k1,1 | tail -1 | cut -d' ' -f2-)
  [[ -n "$meta" ]] || return 1
  python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("force") else 1)' \
    "$meta" 2>/dev/null
}

# --------------------------------------------------------------- floors -----
#
# e13_floor_kind <operation> names the floor an operation is allowed to use.
# The corrected value is computed only when the floor was measured under this
# same name, so a floor from a different operation cannot be substituted.
e13_floor_kind() {
  case "$1" in
    push)        echo "push_noop" ;;
    # pull and fetch had one kind between them, which made a fetch floor
    # acceptable for a pull -- the defect the withdrawn columns had. A pull
    # transfers and applies content; a fetch moves a ref. Their zero-payload
    # floors are different operations and are not interchangeable.
    pull)        echo "pull_noop" ;;
    fetch)       echo "fetch_noop" ;;
    clone)       echo "clone_empty" ;;
    merge)       echo "merge_empty" ;;
    rebase)      echo "rebase_empty" ;;
    forcepush|force_push) echo "force_noop" ;;
    rotate)      echo "rotate_minimal" ;;
    consolidate) echo "consolidate_noop" ;;
    *)           echo "" ;;
  esac
}

# Refuse a corrected cell whose floor came from a different operation. This is
# the mechanical form of the rule the withdrawn columns broke.
e13_floor_matches() {
  local op="$1" floor_kind="$2" want
  want="$(e13_floor_kind "$op")"
  [[ -n "$want" && "$want" == "$floor_kind" ]]
}

# --------------------------------------------------------------- tooling ----

e13_have() { command -v "$1" >/dev/null 2>&1; }

# Which arms can run here. A tool that is absent is reported absent, never as a
# zero and never as a modelled bar.
e13_arm_available() {
  case "$1" in
    git|safehub)        return 0 ;;
    gitcrypt)           e13_have git-crypt ;;
    gcrypt)             e13_have git-remote-gcrypt && e13_have gpg ;;
    sgitchar|sgitline)  [[ -x "${SGIT:-}" ]] ;;
    *)                  return 1 ;;
  esac
}

# SGitChar and SGitLine differ only in the granularity of the diff, so one arm
# name carries the variant flag rather than duplicating the harness.
e13_sgit_variant() { case "$1" in sgitchar) echo char ;; sgitline) echo line ;; esac; }
e13_is_sgit()      { [[ "$1" == sgitchar || "$1" == sgitline ]]; }

# The ciphertext repository sits beside the plaintext one. sgit pushes the
# ciphertext repository to an ordinary bare Git remote with an ordinary push.
e13_sgit_ct()   { echo "$1.ct"; }
e13_sgit_keys() { echo "$(dirname "$1")/.sgit-$(basename "$1").ct.keys.json"; }

# Bytes a push actually puts on the wire: the thin pack built against what the
# remote already holds. Directory growth counts loose objects and a
# self-contained pack counts a delta base the remote is not missing; on an
# append-structured ciphertext file both overstate transmission by two orders
# of magnitude. `have` is the remote tip as it stood BEFORE the push.
e13_thin_bytes() {   # repo have_oid -> bytes
  local repo="$1" have="$2" tip
  tip="$(git -C "$repo" rev-parse HEAD 2>/dev/null)" || { echo 0; return; }
  if [[ -n "$have" ]]; then
    printf '%s\n^%s\n' "$tip" "$have"
  else
    printf '%s\n' "$tip"
  fi | git -C "$repo" pack-objects --thin --stdout --revs 2>/dev/null | wc -c | tr -d ' '
}

# git-remote-gcrypt needs a sign+encrypt keypair and the participant named by
# full fingerprint; a short key id or a sign-only key fails at push with a
# message that looks like a permissions problem.
e13_gcrypt_key() {
  local home="$1"
  local kp="$home/keyparams"
  cat >"$kp" <<'KP'
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
KP
  gpg --batch --generate-key "$kp" >/dev/null 2>&1 || return 1
  gpg --list-secret-keys --with-colons | awk -F: '/^fpr:/{print $10; exit}'
}
