#!/usr/bin/env bash
# Run the dual-backend store conformance suite (ADR-0020) against an
# ephemeral local PostgreSQL: a `postgres:17-alpine` container with its data
# on tmpfs, bound to loopback on a free port, removed on exit (also on
# failure or interrupt). Extra arguments are passed to `cargo test`.
#
#   make test-postgres
#   tools/test_postgres.sh -- --nocapture
#
# Environment: HOPAE_PG_IMAGE (default postgres:17-alpine), CARGO_JOBS (4).
set -euo pipefail
image="${HOPAE_PG_IMAGE:-postgres:17-alpine}"
name="hopae-pg-test-$$"
password="hopae-test-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
docker run -d --rm --name "$name" \
  --tmpfs /var/lib/postgresql/data:size=256m \
  -e POSTGRES_USER=hopae -e POSTGRES_DB=hopae -e POSTGRES_PASSWORD="$password" \
  -p "127.0.0.1:${port}:5432" "$image" >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$name" pg_isready -U hopae -d hopae -h 127.0.0.1 >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
docker exec "$name" pg_isready -U hopae -d hopae -h 127.0.0.1 >/dev/null
export HOPAE_TEST_POSTGRES_URL="host=127.0.0.1 port=${port} user=hopae password=${password} dbname=hopae"
cargo test -j "${CARGO_JOBS:-4}" --locked --lib --features postgres store::conformance "$@"
