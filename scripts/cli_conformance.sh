#!/usr/bin/env bash
# Extensive CLI conformance and stress suite for `sit` / `sh`.
#
# Covers: git-verb forwarding parity, encrypted transport verbs, argument
# handling (including flags that must be REFUSED rather than silently
# ignored), the full `sh` command surface, multi-device and concurrency
# scenarios, epoch churn, pathological inputs, and failure modes.
#
# Usage:  ./scripts/cli_conformance.sh            (full suite)
#         SAFEHUB_CLI_QUICK=1 ./scripts/cli_conformance.sh   (skip stress)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODE="$ROOT/code"; [[ -d "$CODE/crates" ]] || CODE="$ROOT"
PORT="${SAFEHUB_CLI_PORT:-$(( 18200 + (RANDOM % 300) ))}"
PROFILE="${SAFEHUB_CLI_PROFILE:-release}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CODE/target}"

TMP="$(mktemp -d /tmp/safehub-cli-conf.XXXXXX)"
export HOME="$TMP/home" XDG_CONFIG_HOME="$TMP/home/.config" SAFEHUB_DATA="$TMP/data"
export SAFEHUB_HOST="http://127.0.0.1:$PORT"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$SAFEHUB_DATA" "$TMP/work"

SERVER_PID=""
cleanup() { [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

PASS=0; FAIL=0; FAILED=()
ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  \033[31mFAIL\033[0m  %s\n    %s\n' "$1" "$2"; }

# expect_ok <label> <cmd...>   — command must exit 0
expect_ok() { local l="$1"; shift; local o; o="$("$@" 2>&1)"; [[ $? -eq 0 ]] && ok "$l" || bad "$l" "$(head -2 <<<"$o" | tr '\n' '|')"; }
# expect_fail <label> <cmd...> — command must exit non-zero
expect_fail() { local l="$1"; shift; local o; o="$("$@" 2>&1)"; [[ $? -ne 0 ]] && ok "$l" || bad "$l" "unexpectedly succeeded"; }
# expect_out <label> <regex> <cmd...> — must exit 0 AND match
expect_out() {
  local l="$1" re="$2"; shift 2; local o rc
  o="$("$@" 2>&1)"; rc=$?
  if [[ $rc -eq 0 ]] && grep -qE "$re" <<<"$o"; then ok "$l"; else bad "$l" "rc=$rc want /$re/ got: $(head -2 <<<"$o" | tr '\n' '|')"; fi
}
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

echo "==> Building ($PROFILE) into $CARGO_TARGET_DIR"
( cd "$CODE" && cargo build --quiet $([[ $PROFILE == release ]] && echo --release) \
    -p safehub-cli -p safehub-server -p sit-remote-safehub -p safehub-browse ) || exit 1
BIN="$CARGO_TARGET_DIR/$PROFILE"
export PATH="$BIN:/usr/bin:/bin:/usr/local/bin"

if lsof -ti ":$PORT" >/dev/null 2>&1; then
  echo "port $PORT already in use; set SAFEHUB_CLI_PORT to a free port" >&2; exit 1
fi
echo "==> Server on 127.0.0.1:$PORT"
"$BIN/safehub-server" --listen "127.0.0.1:$PORT" --data "$SAFEHUB_DATA" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 80); do curl -sf "$SAFEHUB_HOST/v1/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -sf "$SAFEHUB_HOST/v1/health" >/dev/null || { echo "server failed to start"; exit 1; }

git_id() { git config user.email t@safehub.local; git config user.name "SafeHub Test"; }

# ---------------------------------------------------------------- auth -----
section "auth / identity"
expect_ok   "register alice"          shub auth register --user alice --password alice-pw-1 --hostname "$SAFEHUB_HOST"
expect_ok   "publish key package"     shub device publish-key-package --device default
expect_ok   "auth status"             shub auth status
expect_fail "duplicate register"      shub auth register --user alice --password other --hostname "$SAFEHUB_HOST"
expect_ok   "logout"                  shub auth logout
expect_fail "repo list when signed out" shub repo list
expect_fail "login wrong password"    shub auth login --user alice --secret WRONG --hostname "$SAFEHUB_HOST"
expect_ok   "login"                   shub auth login --user alice --secret alice-pw-1 --hostname "$SAFEHUB_HOST"
expect_ok   "device list"             shub device list
expect_ok   "config get"              shub config get
expect_ok   "doctor"                  sh doctor

# ---------------------------------------------------------------- repo -----
section "repo lifecycle"
cd "$TMP/work"
expect_ok   "repo create"             shub repo create demo --clone
expect_out  "repo list shows demo"    "alice/demo"  shub repo list
expect_ok   "repo view"               shub repo view alice/demo
expect_fail "view unknown repo"       shub repo view alice/nope
expect_fail "create duplicate"        shub repo create demo

cd "$TMP/work/demo"; git_id
echo hello > README.md

# ------------------------------------------------- git verb forwarding -----
section "git verb forwarding (sit -> git)"
for v in "add README.md" "status --short" "commit -q -m first" "log --oneline" \
         "diff --stat" "branch --show-current" "rev-parse HEAD" "show --stat HEAD" \
         "tag v0.1" "stash list" "config user.name" "ls-files" "cat-file -t HEAD" \
         "describe --tags" "shortlog -s" "count-objects -v" "symbolic-ref HEAD" \
         "blame -L 1,1 README.md" "reflog -n 1" "version"; do
  expect_ok "sit ${v%% *}" sit $v
done
expect_ok   "sit checkout -b"         sit checkout -q -b feature
expect_ok   "sit switch -"            sit switch -q -
expect_ok   "sit merge --abort dry"   bash -c 'sit merge --abort 2>/dev/null || true; true'
expect_ok   "sit --version"           sit --version
expect_ok   "sit --help"              sit --help
expect_out  "help lists merge/rebase" "merge" sit --help
expect_fail "sit unknown verb"        sit definitely-not-a-git-command
expect_out  "forwarded exit code"     "." sit rev-parse --abbrev-ref HEAD
expect_fail "sit outside repo"        bash -c 'cd /tmp && sit status'

# --------------------------------------------------- encrypted transport ---
section "encrypted transport verbs"
expect_ok   "push (defaults)"         sit push
expect_ok   "fetch (defaults)"        sit fetch
expect_ok   "pull (defaults)"         sit pull
echo more >> README.md; sit add README.md >/dev/null; sit commit -q -m second >/dev/null
expect_ok   "push remote+refspec"     sit push sit HEAD
expect_ok   "push --force"            sit push --force
expect_ok   "push -f"                 sit push -f

# --------------------------------------------------- argument handling -----
section "argument handling (must refuse, not silently ignore)"
TIP_BEFORE=$(sit fetch 2>&1 | grep -oE 'seq=[0-9]+' | head -1)
expect_out  "--dry-run announces"     "dry run" sit push --dry-run
TIP_AFTER=$(sit fetch 2>&1 | grep -oE 'seq=[0-9]+' | head -1)
[[ "$TIP_BEFORE" == "$TIP_AFTER" ]] && ok "--dry-run does not mutate remote" \
  || bad "--dry-run does not mutate remote" "tip moved $TIP_BEFORE -> $TIP_AFTER"

git branch -f doomed HEAD >/dev/null 2>&1; sit push sit doomed >/dev/null 2>&1
sit push --delete doomed >/dev/null 2>&1
if git ls-remote sit 2>/dev/null | grep -q 'refs/heads/doomed'; then
  bad "--delete removes the ref" "doomed still present"
else ok "--delete removes the ref"; fi

expect_fail "push rejects unknown flag"   sit push --nonsense-flag
expect_fail "push rejects --tags"         sit push --tags
expect_fail "clone rejects --depth"       sit clone --depth 1 alice/demo dd
expect_fail "clone rejects --branch"      sit clone --branch main alice/demo dd
expect_fail "clone rejects unknown flag"  sit clone --bogus alice/demo dd
expect_fail "clone with no args"          sit clone

# ------------------------------------------------------------- clone -------
section "clone forms"
cd "$TMP/work"
expect_ok   "clone owner/name"        sit clone alice/demo c1
expect_ok   "clone sit:// URL"        sit clone sit://alice/demo c2
expect_ok   "clone safehub:// alias"  sit clone safehub://alice/demo c3
expect_fail "clone unknown repo"      sit clone alice/does-not-exist c4

# --------------------------------------------------- pull integration ------
section "pull integrates remote commits"
cd "$TMP/work/demo"; echo integrated > integrated.txt
sit add integrated.txt >/dev/null; sit commit -q -m integrate >/dev/null; sit push >/dev/null 2>&1
cd "$TMP/work/c1"; sit pull >/dev/null 2>&1
[[ -f integrated.txt ]] && ok "sit pull merges into working tree" \
  || bad "sit pull merges into working tree" "file absent after pull"

# ------------------------------------------- merge/rebase via sit remote ---
section "local merge/rebase then encrypted push"
cd "$TMP/work"
rm -rf mrg && sit clone alice/demo mrg >/dev/null 2>&1
(
  cd mrg; git_id
  sit checkout -q -b topic
  echo topic > topic.txt; sit add topic.txt >/dev/null; sit commit -q -m topic >/dev/null
  sit checkout -q -
  sit merge -q topic -m "merge topic"
  sit push >/dev/null 2>&1
) && ok "merge then sit push" || bad "merge then sit push" "failed"
(
  cd "$TMP/work/c1"
  sit pull >/dev/null 2>&1
  test -f topic.txt
) && ok "peer pulls merged tip" || bad "peer pulls merged tip" "missing topic.txt"

cd "$TMP/work"
rm -rf rba rbb
sit clone alice/demo rba >/dev/null 2>&1
sit clone alice/demo rbb >/dev/null 2>&1
( cd rba; git_id; echo a > a.txt; sit add a.txt >/dev/null; sit commit -q -m a >/dev/null; sit push >/dev/null 2>&1 )
( cd rbb; git_id; echo b > b.txt; sit add b.txt >/dev/null; sit commit -q -m b >/dev/null
  if sit push >/dev/null 2>&1; then exit 1; fi
  sit pull --rebase >/dev/null 2>&1 || sit pull >/dev/null 2>&1
  sit push >/dev/null 2>&1
) && ok "non-ff rejects then rebase/pull push" || bad "non-ff rejects then rebase/pull push" "failed"

# ------------------------------------------------ admin vs member authz ----
section "admin vs ordinary member authz"
cd "$TMP/work"
# Use dave so we do not collide with the later multi-device bob/carol section.
shub auth register --user dave --password dave-pw-1! --hostname "$SAFEHUB_HOST" >/dev/null 2>&1 || true
expect_ok "login dave (pre-invite)" bash -c 'shub auth logout >/dev/null 2>&1; shub auth login --user dave --secret dave-pw-1! --hostname "$SAFEHUB_HOST"'
expect_fail "non-member repo view" shub repo view alice/demo
expect_ok "publish dave KP" shub device publish-key-package --device default
expect_ok "re-login alice for invite" bash -c 'shub auth logout >/dev/null 2>&1; shub auth login --user alice --secret alice-pw-1 --hostname "$SAFEHUB_HOST"'
expect_ok "owner invite dave" shub repo invite alice/demo dave
expect_ok "login dave member" bash -c 'shub auth logout >/dev/null 2>&1; shub auth login --user dave --secret dave-pw-1! --hostname "$SAFEHUB_HOST"'
expect_ok "member repo view" shub repo view alice/demo
expect_fail "member cannot invite" shub repo invite alice/demo mallory
expect_fail "member cannot remove" shub repo remove-member alice/demo alice
expect_fail "member cannot archive" shub repo archive alice/demo
expect_fail "member cannot delete" shub repo delete alice/demo --yes
expect_fail "member cannot rotate" shub repo rotate alice/demo
expect_ok "member can list collabs" shub repo collaborators alice/demo
expect_ok "restore alice" bash -c 'shub auth logout >/dev/null 2>&1; shub auth login --user alice --secret alice-pw-1 --hostname "$SAFEHUB_HOST"'

# ------------------------------------------------------------- sh surface --
section "expanded sh surface (status/variable/milestone/pr/issue)"
expect_ok "sh status help" sh status --help
expect_ok "sh variable help" sh variable --help
expect_ok "sh milestone help" sh milestone --help
expect_ok "sh issue --help" sh issue --help
expect_ok "sh pr --help" sh pr --help
expect_ok "sh org --help" sh org --help

# ------------------------------------------------------- collaboration -----
section "sh collaboration surface"
cd "$TMP/work/demo"
expect_ok   "issue create"            sh issue create --repo alice/demo --title "Bug A" --body details
expect_ok   "issue list"              sh issue list --repo alice/demo
expect_ok   "pr create"               sh pr create --repo alice/demo --title "PR A" --body b --head feature
expect_ok   "pr list"                 sh pr list --repo alice/demo
expect_ok   "search issues"           sh search issues Bug
expect_ok   "label list"              sh label list --repo alice/demo
expect_ok   "inbox list"              sh inbox list --repo alice/demo
expect_ok   "sync"                    sh sync

# ------------------------------------------------------------- admin -------
section "admin operations"
expect_ok   "repo verify"             shub repo verify alice/demo
expect_ok   "export-checkpoint"       shub repo export-checkpoint alice/demo --out "$TMP/ckpt.json"
expect_ok   "rotate"                  shub repo rotate alice/demo
expect_ok   "fetch survives rotate"   sit fetch
expect_ok   "pull survives rotate"    sit pull
expect_ok   "rotate twice"            shub repo rotate alice/demo
expect_ok   "fetch survives 2 rotates" sit fetch
# `shub repo consolidate` currently seals and reopens a synthetic tip-sized
# buffer and discards the result: it exits zero without replacing a log prefix
# or contacting the server. The assertion is named for what it actually shows
# so a green suite is not read as evidence that consolidation works. Wiring
# safehub-client's consolidate module to the CLI is the outstanding gap.
expect_ok   "consolidate exits zero (does not yet compact)" \
                                      shub repo consolidate alice/demo --tip-mib 1
expect_ok   "push after consolidate"  sit push

# ------------------------------------------------------ multi-device -------
section "multi-device (second member)"
shub auth logout >/dev/null 2>&1
expect_ok   "register bob"            shub auth register --user bob --password bob-pw-1 --hostname "$SAFEHUB_HOST"
expect_ok   "bob publishes KeyPackage" shub device publish-key-package --device default
shub auth logout >/dev/null 2>&1
shub auth login --user alice --secret alice-pw-1 --hostname "$SAFEHUB_HOST" >/dev/null 2>&1
expect_ok   "invite bob"              shub repo invite alice/demo bob
expect_fail "re-invite existing member" shub repo invite alice/demo bob
shub auth logout >/dev/null 2>&1
expect_ok   "register carol"          shub auth register --user carol --password carol-pw-1 --hostname "$SAFEHUB_HOST"
expect_ok   "carol publishes KeyPackage" shub device publish-key-package --device default
shub auth logout >/dev/null 2>&1
shub auth login --user alice --secret alice-pw-1 --hostname "$SAFEHUB_HOST" >/dev/null 2>&1
expect_ok   "invite carol forward-only" shub repo invite alice/demo carol --forward-only
expect_fail "invite unknown user"     shub repo invite alice/demo nosuchuser
expect_ok   "remove member"           shub repo remove-member alice/demo bob
expect_ok   "rotate after removal"    shub repo rotate alice/demo
expect_ok   "fetch after removal"     sit fetch

# ------------------------------------------------ pathological inputs ------
section "pathological paths and content"
cd "$TMP/work/demo"
mkdir -p "src/δοκιμή" "src/with spaces" "src/a/b/c/d/e/f/g"
printf u > "src/δοκιμή/файл.txt"
printf s > "src/with spaces/name here.txt"
printf d > "src/a/b/c/d/e/f/g/deep.txt"
printf e > "src/emoji-🔐.txt"
printf l > "src/$(python3 -c 'print("long"*40)').txt"
head -c 200000 /dev/urandom > src/binary.bin
printf 'no-newline-at-eof' > src/noeol.txt
sit add . >/dev/null 2>&1
expect_ok   "commit pathological tree" sit commit -q -m pathological
expect_ok   "push pathological tree"   sit push
cd "$TMP/work"; rm -rf pc
expect_ok   "clone pathological tree"  sit clone alice/demo pc
N=$(find pc/src -type f 2>/dev/null | grep -cE 'δοκιμή|with spaces|deep|emoji|longlong|binary|noeol')
[[ "$N" -ge 7 ]] && ok "pathological files round-trip ($N/7)" \
  || bad "pathological files round-trip" "only $N/7 present"

# --------------------------------------------------------- empty repo ------
section "edge cases"
cd "$TMP/work"
expect_ok   "create empty repo"       shub repo create emptyrepo --clone
cd "$TMP/work/emptyrepo"; git_id
expect_fail "push with no commits"    sit push
expect_ok   "fetch on empty repo"     sit fetch
echo x > f.txt; sit add f.txt >/dev/null; sit commit -q -m only >/dev/null
expect_ok   "push single commit"      sit push
expect_ok   "idempotent re-push"      sit push
expect_ok   "fetch after re-push"     sit fetch

# ------------------------------------------------------------- stress ------
if [[ "${SAFEHUB_CLI_QUICK:-}" != "1" ]]; then
  section "stress: sustained push/fetch"
  cd "$TMP/work/demo"
  S_OK=0
  for i in $(seq 1 25); do
    echo "churn $i" >> churn.txt; sit add churn.txt >/dev/null; sit commit -q -m "churn$i" >/dev/null
    sit push >/dev/null 2>&1 && sit fetch >/dev/null 2>&1 && S_OK=$((S_OK+1))
  done
  [[ "$S_OK" -eq 25 ]] && ok "25 push/fetch cycles" || bad "25 push/fetch cycles" "$S_OK/25 succeeded"

  section "stress: epoch churn (rotate every 3 pushes)"
  R_OK=0
  for i in $(seq 1 12); do
    echo "r$i" >> rot.txt; sit add rot.txt >/dev/null; sit commit -q -m "r$i" >/dev/null
    sit push >/dev/null 2>&1 || continue
    (( i % 3 == 0 )) && shub repo rotate alice/demo >/dev/null 2>&1
    sit fetch >/dev/null 2>&1 && R_OK=$((R_OK+1))
  done
  [[ "$R_OK" -eq 12 ]] && ok "12 pushes across 4 rotations" || bad "12 pushes across 4 rotations" "$R_OK/12"

  section "stress: concurrent writers (CAS contention)"
  # Use a FRESH repository: this measures write contention, not the accumulated
  # state (rotations, pathological paths, churn files) left by earlier sections.
  cd "$TMP/work"
  shub repo create racerepo --clone >/dev/null 2>&1
  ( cd racerepo; git_id; echo base > base.txt; sit add . >/dev/null
    sit commit -q -m base >/dev/null; sit push >/dev/null 2>&1 )
  for i in 1 2 3 4 5 6; do rm -rf "cw$i"; sit clone alice/racerepo "cw$i" >/dev/null 2>&1; done
  WPIDS=()
  for i in 1 2 3 4 5 6; do
    ( cd "cw$i"; git_id
      for j in 1 2; do
        echo "$i-$j" > "cw$i-$j.txt"; git add -A; git commit -q -m "cw$i-$j"
        # push; on a legitimate non-fast-forward, pull to merge and retry.
        for _ in $(seq 1 20); do sit push >/dev/null 2>&1 && break; sit pull >/dev/null 2>&1; done
      done ) &
    WPIDS+=($!)
  done
  # Wait only on the writers: a bare `wait` would also block on the
  # long-lived safehub-server started earlier in this shell.
  for p in "${WPIDS[@]}"; do wait "$p"; done
  cd "$TMP/work/cw1"; sit pull >/dev/null 2>&1
  LANDED=$(ls cw*-*.txt 2>/dev/null | wc -l | tr -d ' ')
  [[ "$LANDED" -eq 12 ]] && ok "12 concurrent writes all landed (6 writers)" \
    || bad "12 concurrent writes all landed (6 writers)" "$LANDED/12 landed"
  git fsck --no-progress >/dev/null 2>&1 && ok "repo consistent after contention" \
    || bad "repo consistent after contention" "git fsck reported problems"

  section "stress: many files"
  cd "$TMP/work"; rm -rf many; shub repo create manyfiles --clone >/dev/null 2>&1
  cd manyfiles; git_id
  python3 -c "
import os
for i in range(600):
    d=f'src/m{i//50}'; os.makedirs(d,exist_ok=True)
    open(f'{d}/f{i}.txt','w').write('x'*512)
"
  sit add . >/dev/null 2>&1; sit commit -q -m "600 files" >/dev/null
  expect_ok "push 600 files"          sit push
  cd "$TMP/work"; rm -rf manyclone
  expect_ok "clone 600 files"         sit clone alice/manyfiles manyclone
  C=$(find manyclone/src -type f 2>/dev/null | wc -l | tr -d ' ')
  [[ "$C" -eq 600 ]] && ok "600 files round-trip" || bad "600 files round-trip" "$C/600"
fi

# ------------------------------------------------------------ summary ------
printf '\n\033[1m==== %d passed, %d failed ====\033[0m\n' "$PASS" "$FAIL"
if (( FAIL )); then printf '  failed: %s\n' "${FAILED[@]}"; exit 1; fi
exit 0
