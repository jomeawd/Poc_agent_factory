#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2034  # checks are strings eval'd later; they read variables set afterwards
# Integration smoke suite: runs against a live stack started with `docker compose up --wait`.
#
#   tests/integration/smoke.sh <compose-project> <env-file>
#
# Exercises the real HTTP path (browser -> nginx -> API -> Postgres / broker -> Docker / Telegram)
# and asserts the brief's security invariants. Never prints secret values.
set -uo pipefail

PROJECT="${1:?compose project name}"
ENV_FILE="${2:?env file}"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
BASE="http://localhost:${WEB_PORT:-3999}"
EGRESS="${EGRESS_NAME:-af-egress}"
COMPOSE=(docker compose -p "$PROJECT" --env-file "$ENV_FILE")
JAR="$(mktemp)"; BODY="$(mktemp)"
trap 'rm -f "$JAR" "$BODY"' EXIT

pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "  PASS  $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
json() { python3 -c "import json,sys; d=json.load(open('$BODY')); print($1)"; }

# req METHOD PATH [JSON] [extra curl args...] -> sets $code, body in $BODY
req() {
  local m="$1" p="$2" data="${3:-}"; shift 3 2>/dev/null || shift $#
  local args=(-s -o "$BODY" -w '%{http_code}' -b "$JAR" -c "$JAR" -X "$m" -H 'content-type: application/json')
  [ -n "${CSRF:-}" ] && args+=(-H "X-CSRF-Token: $CSRF")
  [ -n "$data" ] && args+=(--data "$data")
  code=$(curl "${args[@]}" "$@" "$BASE$p")
}

echo "== Web and API reachability"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/login"); check "login page served (200)" '[ "$code" = 200 ]'
check "page is never served stale (Cache-Control: no-cache)" 'curl -sI "$BASE/app.js" | grep -qi "cache-control: no-cache"'
req GET /api/health; check "API health through nginx" '[ "$code" = 200 ]'

echo "== Authentication"
req GET /api/agents; check "anonymous request rejected (401)" '[ "$code" = 401 ]'
req POST /api/login '{"email":"'"$OWNER_EMAIL"'","password":"wrong-password"}'; check "wrong password rejected (401)" '[ "$code" = 401 ]'
req POST /api/login "$(python3 -c 'import json,os;print(json.dumps({"email":os.environ["OWNER_EMAIL"],"password":os.environ["OWNER_PASSWORD"]}))')"
check "owner can sign in" '[ "$code" = 200 ]'
TOKEN_FROM_LOGIN=$(json "d.get('csrf_token','')")

echo "== CSRF and CORS"
req POST /api/agentfather/sessions ''; check "state change without CSRF token rejected (403)" '[ "$code" = 403 ]'
req POST /api/logout ''; check "logout without CSRF token rejected (403)" '[ "$code" = 403 ]'
req GET /api/me; check "session survives a forged logout" '[ "$code" = 200 ]'
CSRF="$TOKEN_FROM_LOGIN"
req POST /api/agentfather/sessions '' -H 'Origin: https://evil.example'; check "cross-origin state change rejected (403)" '[ "$code" = 403 ]'

echo "== Model providers"
req GET /api/providers
check "providers listed without any key value" '[ "$code" = 200 ] && ! grep -q "sk-ant" "$BODY"'
check "Claude connected from env, Gemini/Groq not" '[ "$(json "\",\".join(p[\"id\"] for p in d if p[\"configured\"])")" = anthropic ]'
req PUT /api/providers/gemini '{"key":"not-a-key"}'; check "malformed provider key rejected (422)" '[ "$code" = 422 ]'

echo "== AgentFather guided flow"
req POST /api/agentfather/sessions ''; check "session opened" '[ "$code" = 200 ]'
SID=$(json "d['id']")
answer() { req POST "/api/agentfather/sessions/$SID/messages" "$1"; }
answer '{"choices":["Customer support"]}'; answer '{"text":"CI Company"}'; answer '{"choices":["Nova"]}'
answer '{"text":"We test the platform."}'; answer '{"choices":["Friendly and warm"]}'; answer '{"choices":["English only"]}'
answer '{"choices":[]}'; answer "{\"choices\":[\"Simply say it doesn't know\"]}"; answer '{"choices":["OpenClaw (recommended)"]}'
check "only models of connected providers are offered" '[ "$(json "any(\"Gemini\" in o or \"Groq\" in o for o in d[\"question\"][\"options\"])")" = False ]'
answer '{"choices":["Gemini 3.8 Flash"]}'; check "unconnected provider model refused" '[ -n "$(json "d.get(\"error\") or \"\"")" ]'
answer '{"choices":["Claude Haiku 5.5 (fastest)"]}'; answer '{"choices":["Telegram"]}'
answer '{"choices":["Only people I list"]}'; answer '{"text":"abc"}'
check "invalid Telegram user ids refused" '[ -n "$(json "d.get(\"error\") or \"\"")" ]'
answer '{"text":"123456789"}'
check "summary reached with validated config" '[ "$(json "d[\"complete\"]")" = True ] && [ "$(json "d[\"config\"][\"model\"]")" = claude-haiku-5-5 ]'

echo "== Confirm through the broker (live Telegram check)"
FAKE_BOT="123456789:AAci$(openssl rand -hex 16)"
req POST "/api/agentfather/sessions/$SID/confirm" "{\"telegram_token\":\"$FAKE_BOT\"}"
check "fake bot token rejected by Telegram via broker (422)" '[ "$code" = 422 ] && grep -qi telegram "$BODY"'
req GET /api/agents; check "no agent left behind after rejected confirm" '[ "$(json "len(d)")" = 0 ]'
check "no bot secret left in the broker store" '[ "$("${COMPOSE[@]}" exec -T broker sh -c "ls /secrets | grep -c ^sec_ || true")" = 0 ]'

echo "== Isolation invariants"
for svc in web api worker db egress; do
  cid=$("${COMPOSE[@]}" ps -q "$svc")
  check "$svc has no Docker socket" '! docker inspect "$cid" --format "{{range .Mounts}}{{.Source}} {{end}}" | grep -q docker.sock'
done
check "broker is the one with the Docker socket" 'docker inspect "$("${COMPOSE[@]}" ps -q broker)" --format "{{range .Mounts}}{{.Source}} {{end}}" | grep -q docker.sock'
check "broker /health reveals nothing but ok" '[ "$("${COMPOSE[@]}" exec -T broker php -r "echo file_get_contents(\"http://127.0.0.1:8100/health\");")" = "{\"ok\":true}" ]'
check "broker refuses requests without its token (401)" '[ "$("${COMPOSE[@]}" exec -T api php -r "\$c=curl_init(\"http://broker:8100/providers\");curl_setopt(\$c,CURLOPT_RETURNTRANSFER,1);curl_exec(\$c);echo curl_getinfo(\$c,CURLINFO_RESPONSE_CODE);")" = 401 ]'

echo "== Egress allowlist"
probe() { docker run --rm --network "${PROJECT}_egress" curlimages/curl:8.11.1 -s -o /dev/null -w '%{http_code}' --max-time 15 -x "http://$EGRESS:8888" "$1" 2>/dev/null || true; }
check "allowlisted host reachable (api.telegram.org)" '[ "$(probe https://api.telegram.org/bot1:x/getMe)" != 000 ]'
check "non-allowlisted host blocked (www.google.com)" '[ "$(probe https://www.google.com)" = 000 ] || [ "$(probe https://www.google.com)" = 403 ]'

echo "== No secret in logs or database"
LOGS=$("${COMPOSE[@]}" logs 2>&1); DUMP=$("${COMPOSE[@]}" exec -T db pg_dump -U agentfactory agentfactory 2>/dev/null)
for var in BROKER_TOKEN SESSION_SECRET POSTGRES_PASSWORD OWNER_PASSWORD ANTHROPIC_API_KEY; do
  val="${!var}"
  check "$var absent from logs and DB" '! grep -qF -- "$val" <<<"$LOGS$DUMP"'
done
check "fake bot token absent from logs and DB" '! grep -qF -- "$FAKE_BOT" <<<"$LOGS$DUMP"'

echo "== Worker"
check "worker is running" '[ "$(docker inspect "$("${COMPOSE[@]}" ps -q worker)" --format "{{.State.Running}}")" = true ]'

echo
echo "Integration: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
