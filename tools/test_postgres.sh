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
# Every case migrates a fresh schema: bound the WAL so tmpfs never fills.
docker run -d --rm --name "$name" \
  --tmpfs /var/lib/postgresql/data:size=512m \
  -e POSTGRES_USER=hopae -e POSTGRES_DB=hopae -e POSTGRES_PASSWORD="$password" \
  -p "127.0.0.1:${port}:5432" "$image" \
  -c max_wal_size=96MB -c min_wal_size=32MB -c checkpoint_timeout=30s >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$name" pg_isready -U hopae -d hopae -h 127.0.0.1 >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
docker exec "$name" pg_isready -U hopae -d hopae -h 127.0.0.1 >/dev/null
export HOPAE_TEST_POSTGRES_URL="host=127.0.0.1 port=${port} user=hopae password=${password} dbname=hopae"
cargo test -j "${CARGO_JOBS:-4}" --locked --lib --features postgres store::conformance "$@"
# Owner-level PostgreSQL races that live next to their owner code.
cargo test -j "${CARGO_JOBS:-4}" --locked --lib --features postgres s600_28_postgres_connections "$@"
# The native Human suite (snapshot, primary/TOTP/WebAuthn provenance, the
# Human ledger, Human receipts over gRPC) on PostgreSQL: the same tests the
# SQLite run executes, with the fixture on a fresh schema per case.
HOPAE_TEST_HUMAN_BACKEND=postgres RUST_TEST_THREADS=4 cargo test -j "${CARGO_JOBS:-4}" --locked --lib --features postgres verify::human_tests "$@"
