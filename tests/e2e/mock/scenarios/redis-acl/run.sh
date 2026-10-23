#!/usr/bin/env bash
# Local disposable Redis; never reads a kubeconfig or external credentials.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/../../lib/common.sh"
command -v redis-server >/dev/null
command -v redis-cli >/dev/null
FIXTURE_DIR=$(mktemp -d)
ACL_REDIS_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
REDIS_PID=""
SCENARIO_LOG=/tmp/e2e-mock-redis-acl.log
cleanup() {
  local rc=$?
  if (( rc != 0 )); then dump_diagnostics > "$SCENARIO_LOG" 2>&1 || true; fi
  stop_stack
  [[ -z "$REDIS_PID" ]] || kill "$REDIS_PID" 2>/dev/null || true
  [[ -z "$REDIS_PID" ]] || wait "$REDIS_PID" 2>/dev/null || true
  rm -rf "$FIXTURE_DIR"
  exit "$rc"
}
trap cleanup EXIT
cat > "$FIXTURE_DIR/redis.conf" <<CONF
bind 127.0.0.1
port $ACL_REDIS_PORT
save ""
appendonly no
user default off
user admin on >fixture-admin ~* &* +@all
user crowdsec on ">fixture password%value" ~crowdsec:* +get +set +del +select
CONF
redis-server "$FIXTURE_DIR/redis.conf" > "$FIXTURE_DIR/redis.log" 2>&1 &
REDIS_PID=$!
admin() { REDISCLI_AUTH=fixture-admin redis-cli --no-auth-warning -p "$ACL_REDIS_PORT" --user admin -n 5 "$@"; }
for ((i=0; i<50; i++)); do
  if [[ $(admin PING 2>/dev/null) == PONG ]]; then break; fi
  sleep 0.1
done
[[ $(admin PING) == PONG ]]
admin SET crowdsec:1.2.3.4 f EX 300 >/dev/null
admin SET crowdsec:1.2.3.5 t EX 300 >/dev/null
admin SET other:sentinel unchanged >/dev/null
sed "s/@@ACL_REDIS_HOST@@/127.0.0.1:$ACL_REDIS_PORT/g" "$HERE/dynamic.yml" > "$FIXTURE_DIR/dynamic.yml"
start_stack "$FIXTURE_DIR"
for ((i=0; i<100; i++)); do
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.5"
done
assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.6"
[[ $(admin GET crowdsec:1.2.3.6) == f ]]
[[ $(admin EXISTS 1.2.3.6) == 0 ]]
admin ACL SETUSER crowdsec -set >/dev/null
assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 --max-time 3 -H "X-Forwarded-For: 1.2.3.7"
admin ACL SETUSER crowdsec -get >/dev/null
assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 --max-time 3 -H "X-Forwarded-For: 1.2.3.4"
[[ $(admin GET other:sentinel) == unchanged ]]
if ! REDISCLI_AUTH='fixture password%value' redis-cli --no-auth-warning -p "$ACL_REDIS_PORT" --user crowdsec -n 5 DEL other:sentinel | grep -q NOPERM; then
  echo 'cross-prefix DEL was not denied' >&2
  exit 1
fi
[[ $(admin GET other:sentinel) == unchanged ]]
echo '[redis-acl] PASS: 100 allow/ban pairs, namespaced write, denied GET/SET, cross-prefix denial'
