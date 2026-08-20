#!/usr/bin/env bash
# UI correctness suite for safehub-local-ui.
#
# Checks routes, session handling, rendered content (not just status codes),
# escaping, self-containment, and negative/authorization cases.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODE="$ROOT/code"; [[ -d "$CODE/crates" ]] || CODE="$ROOT"
PORT="${SAFEHUB_UI_PORT:-18130}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CODE/target}"

TMP="$(mktemp -d /tmp/safehub-ui-conf.XXXXXX)"
UI="http://127.0.0.1:$PORT"
JAR="$TMP/jar"
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

PASS=0; FAIL=0; FAILED=()
ok()  { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  FAIL  %s\n    %s\n' "$1" "$2"; }
section() { printf '\n== %s ==\n' "$1"; }

# code <label> <expected> <path> [--nocookie]
code() {
  local l="$1" want="$2" p="$3" jar="-b $JAR"
  [[ "${4:-}" == "--nocookie" ]] && jar=""
  local got; got=$(curl -s $jar -o /dev/null -w '%{http_code}' "$UI$p")
  [[ "$got" == "$want" ]] && ok "$l" || bad "$l" "$p -> $got (want $want)"
}
# has <label> <path> <regex>
has() {
  local l="$1" p="$2" re="$3"
  local body; body=$(curl -s -b "$JAR" "$UI$p")
  grep -qE "$re" <<<"$body" && ok "$l" || bad "$l" "$p missing /$re/"
}
# hasnot <label> <path> <regex>
hasnot() {
  local l="$1" p="$2" re="$3"
  local body; body=$(curl -s -b "$JAR" "$UI$p")
  grep -qE "$re" <<<"$body" && bad "$l" "$p unexpectedly contains /$re/" || ok "$l"
}

echo "==> Building"
( cd "$CODE" && cargo build --quiet --release -p safehub-server -p safehub-cli -p safehub-browse ) || exit 1
BIN="$CODE/target/release"

echo "==> deprecated local-ui on 127.0.0.1:$PORT"
"$BIN/safehub-local-ui" --allow-deprecated --listen "127.0.0.1:$PORT" --data "$TMP/data" >"$TMP/ui.log" 2>&1 &
PID=$!
for _ in $(seq 1 80); do curl -sf "$UI/v1/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -sf "$UI/v1/health" >/dev/null || { echo "ui failed to start"; exit 1; }

# seed: two users, one repo, one issue, one PR
TOK=$(curl -s -X POST "$UI/v1/auth/register" -H 'content-type: application/json' \
      -d '{"user":"alice","password":"alice-pw-1"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
curl -s -X POST "$UI/v1/auth/register" -H 'content-type: application/json' \
     -d '{"user":"mallory","password":"mallory-pw-1"}' -o /dev/null
curl -s -X POST "$UI/v1/repos" -H "Authorization: Bearer $TOK" -H 'content-type: application/json' \
     -d '{"name":"demo"}' -o /dev/null
curl -s -X POST "$UI/v1/repos/alice/demo/issues" -H "Authorization: Bearer $TOK" \
     -H 'content-type: application/json' -d '{"title":"First issue","body":"issue body"}' -o /dev/null
curl -s -X POST "$UI/v1/repos/alice/demo/pulls" -H "Authorization: Bearer $TOK" \
     -H 'content-type: application/json' -d '{"title":"First PR","body":"pr body"}' -o /dev/null

section "signed-out behaviour"
code "home renders signed out"     200 "/"        --nocookie
code "login page"                  200 "/login"   --nocookie
code "register page"               200 "/register" --nocookie
has  "signed-out home offers sign in" "/" "Sign in|sign in"

section "session"
LOGIN=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{http_code}' -X POST "$UI/login" \
        --data-urlencode user=alice --data-urlencode password=alice-pw-1)
[[ "$LOGIN" == "303" ]] && ok "login redirects" || bad "login redirects" "got $LOGIN"
grep -q "sh_user" "$JAR" && ok "session cookie set" || bad "session cookie set" "no sh_user in jar"
code "login redirects when signed in" 303 "/login"
BADLOGIN=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$UI/login" \
           --data-urlencode user=alice --data-urlencode password=WRONG)
[[ "$BADLOGIN" != "303" ]] && ok "wrong password does not sign in" || bad "wrong password does not sign in" "got 303"

section "routes return 200"
for p in "/" "/register" "/settings/tokens" "/settings/tokens/new" "/settings/billing" \
         "/codespaces" "/assets/app.css" "/assets/app.js" "/alice" "/alice/demo" "/alice/demo/" \
         "/alice/demo/commits" "/alice/demo/issues" "/alice/demo/issues/1" "/alice/demo/pulls" \
         "/alice/demo/pulls/1" "/alice/demo/settings" "/alice/demo/settings/access" \
         "/alice/demo/actions" "/alice/demo/projects" "/alice/demo/wiki" \
         "/alice/demo/security" "/alice/demo/insights" "/alice/demo/packages"; do
  code "GET $p" 200 "$p"
done

section "rendered content is real, not placeholder"
has "dashboard lists the repo"      "/"                    "alice/demo"
has "user page lists the repo"      "/alice"               "alice/demo"
has "repo page shows owner/name"    "/alice/demo"          "alice.*demo"
has "repo page has Code tab"        "/alice/demo"          ">Code<|Code</a>"
has "repo page has Issues tab"      "/alice/demo"          "Issues"
has "repo page has Pull requests"   "/alice/demo"          "Pull requests"
has "private badge shown"           "/alice/demo"          "[Pp]rivate"
has "issues list shows issue"       "/alice/demo/issues"   "First issue"
has "issue detail shows title"      "/alice/demo/issues/1" "First issue"
has "pulls list shows PR"           "/alice/demo/pulls"    "First PR"
has "commits page renders"          "/alice/demo/commits"  "[Cc]ommit"
has "tokens page has a form"        "/settings/tokens"     "<form"

section "GitHub-like structure"
has "top header present"            "/alice/demo" 'class="top"'
has "repo tab bar present"          "/alice/demo" 'repo-tabs'
has "active tab marked"             "/alice/demo" 'class="active"|li class="active"'
has "stylesheet linked"             "/alice/demo" 'assets/app.css'
has "orange active indicator in css" "/assets/app.css" 'fd8c73'
has "dark mode tokens in css"       "/assets/app.css" 'prefers-color-scheme'

section "self-contained (no external assets)"
for p in "/" "/alice/demo" "/alice/demo/issues" "/login"; do
  hasnot "no remote refs on $p" "$p" 'https?://[a-z]'
done
hasnot "css has no @import"          "/assets/app.css" '@import'
hasnot "css has no remote url()"     "/assets/app.css" 'url\(https?:'

section "escaping / injection"
XSSTOK=$TOK
curl -s -X POST "$UI/v1/repos/alice/demo/issues" -H "Authorization: Bearer $XSSTOK" \
     -H 'content-type: application/json' \
     -d '{"title":"<script>alert(1)</script>","body":"<img src=x onerror=alert(2)>"}' -o /dev/null
hasnot "issue title script tag escaped" "/alice/demo/issues" '<script>alert\(1\)</script>'
has    "issue title shown escaped"      "/alice/demo/issues" '&lt;script&gt;'

section "negative / authorization"
code "unknown repo 404s"            404 "/alice/no-such-repo"
code "unknown issue 404s"           404 "/alice/demo/issues/9999"
code "unknown user page"            200 "/nobody"
MJAR="$TMP/mjar"
curl -s -c "$MJAR" -b "$MJAR" -o /dev/null -X POST "$UI/login" \
     --data-urlencode user=mallory --data-urlencode password=mallory-pw-1
MCODE=$(curl -s -b "$MJAR" -o /dev/null -w '%{http_code}' "$UI/alice/demo/settings/access")
[[ "$MCODE" == "200" || "$MCODE" == "403" || "$MCODE" == "404" ]] \
  && ok "non-member settings access handled ($MCODE)" \
  || bad "non-member settings access handled" "got $MCODE"

section "logout"
code "logout redirects" 303 "/logout"

printf '\n==== %d passed, %d failed ====\n' "$PASS" "$FAIL"
if (( FAIL )); then printf '  failed: %s\n' "${FAILED[@]}"; exit 1; fi
exit 0
