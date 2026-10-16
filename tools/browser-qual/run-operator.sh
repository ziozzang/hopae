#!/bin/bash
# Browser qualification of console operator assurance (ADR-0021), local only:
# a real Chrome with a WebAuthn virtual authenticator, Hopae (held by the
# ignored scenario test `g8_hold_operator_stack`) and the real Hangang
# authority and console (HANGANG_BIN_DIR: hangang and hangang-console from
# the Hangang feat/operator-aal branch). operator.cjs plays TLS and the
# gateway. Nothing is downloaded; artifacts stay in .work-operator/ (ignored).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work="$here/.work-operator"
mkdir -p "$work/shots"
: "${G8_CHROME_IMAGE:?image with /opt/google/chrome/chrome}"
: "${G8_NODE:?node binary}"
: "${PW_CORE:?playwright-core path}"
: "${HANGANG_BIN_DIR:?directory with hangang and hangang-console}"
port=${G8_PORT:-28444}
cdp=${G8_CDP_PORT:-9334}
if [ ! -s "$work/cert.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$work/key.pem" -out "$work/cert.pem" -days 2 -subj "/CN=auth.example.test" \
    -addext "subjectAltName=DNS:auth.example.test,DNS:app.example.test,DNS:console.example.test" 2>/dev/null
  openssl x509 -in "$work/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der |
    openssl dgst -sha256 -binary | base64 > "$work/spki.txt"
fi
name=hopae-g8-operator-chrome
cleanup() {
  touch "$work/stack.stop"
  docker rm -f "$name" >/dev/null 2>&1 || true
  wait 2>/dev/null || true
}
trap cleanup EXIT
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --rm --name "$name" --network host --shm-size=1g \
  --entrypoint /opt/google/chrome/chrome "$G8_CHROME_IMAGE" \
  --headless=new --no-sandbox --disable-gpu --remote-debugging-address=127.0.0.1 \
  --remote-debugging-port="$cdp" --user-data-dir=/tmp/g8-operator-profile \
  "--host-resolver-rules=MAP auth.example.test 127.0.0.1:$port, MAP app.example.test 127.0.0.1:$port, MAP console.example.test 127.0.0.1:$port" \
  "--ignore-certificate-errors-spki-list=$(cat "$work/spki.txt")" about:blank >/dev/null
for _ in $(seq 1 30); do curl -s "127.0.0.1:$cdp/json/version" >/dev/null && break; sleep 1; done
rm -f "$work/stack.json" "$work/stack.stop"
(cd "$root" && G8_STACK_FILE="$work/stack.json" CARGO_INCREMENTAL=0 \
  cargo test --locked --features test-hooks --test scenarios g8_hold_operator_stack -- --ignored --nocapture \
  > "$work/stack.log" 2>&1) &
until [ -s "$work/stack.json" ]; do sleep 1; done
G8_STACK_FILE="$work/stack.json" G8_WORK="$work" G8_SHOTS="${G8_SHOTS:-$work/shots}" \
  G8_PORT="$port" G8_CDP="http://127.0.0.1:$cdp" PW_CORE="$PW_CORE" HANGANG_BIN_DIR="$HANGANG_BIN_DIR" \
  timeout 900 "$G8_NODE" "$here/operator.cjs"
