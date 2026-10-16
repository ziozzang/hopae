#!/bin/bash
# G8 browser qualification for passkeys (ADR-0017), local only.
#
# Needs: Docker with an image that contains Google Chrome at
# /opt/google/chrome/chrome (G8_CHROME_IMAGE), Node.js (G8_NODE) and an
# existing playwright-core checkout (PW_CORE). Nothing is downloaded.
# Starts a throwaway Chrome container (host network, removed at the end),
# the Hopae stack holder (an ignored scenario test), and drive.cjs.
# Artifacts (certificate, results, screenshots) stay in .work/ (ignored).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work="$here/.work"
mkdir -p "$work/shots"
: "${G8_CHROME_IMAGE:?image with /opt/google/chrome/chrome}"
: "${G8_NODE:?node binary}"
: "${PW_CORE:?playwright-core path}"
port=${G8_PORT:-28443}
cdp=${G8_CDP_PORT:-9333}

if [ ! -s "$work/cert.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$work/key.pem" -out "$work/cert.pem" -days 2 -subj "/CN=auth.example.test" \
    -addext "subjectAltName=DNS:auth.example.test,DNS:app.example.test" 2>/dev/null
  openssl x509 -in "$work/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der |
    openssl dgst -sha256 -binary | base64 > "$work/spki.txt"
fi

name=hopae-g8-chrome
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
  --remote-debugging-port="$cdp" --user-data-dir=/tmp/g8-profile \
  "--host-resolver-rules=MAP auth.example.test 127.0.0.1:$port, MAP app.example.test 127.0.0.1:$port" \
  "--ignore-certificate-errors-spki-list=$(cat "$work/spki.txt")" about:blank >/dev/null
for _ in $(seq 1 30); do curl -s "127.0.0.1:$cdp/json/version" >/dev/null && break; sleep 1; done

rm -f "$work/stack.json" "$work/stack.stop"
(cd "$root" && G8_STACK_FILE="$work/stack.json" CARGO_INCREMENTAL=0 \
  cargo test --locked --test scenarios g8_hold_passkey_stack -- --ignored --nocapture \
  > "$work/stack.log" 2>&1) &
until [ -s "$work/stack.json" ]; do sleep 1; done

G8_STACK_FILE="$work/stack.json" G8_WORK="$work" G8_SHOTS="${G8_SHOTS:-$work/shots}" \
  G8_PORT="$port" G8_CDP="http://127.0.0.1:$cdp" PW_CORE="$PW_CORE" \
  timeout 600 "$G8_NODE" "$here/drive.cjs"
