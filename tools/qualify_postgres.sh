#!/usr/bin/env bash
# Local two-replica qualification of the PostgreSQL store (ADR-0020 slice 4).
#
# One ephemeral `postgres:17-alpine` container, data on tmpfs, bound to
# loopback on a free port, removed on exit (also on failure or interrupt).
#
#   1. Migration: a SQLite store made by `hopae providers import` is copied
#      by `hopae store migrate-to-postgres`; a second run must be refused
#      (non-empty target) and the SQLite file must be unchanged.
#   2. Replicas: `qualify_postgres_replicas setup`, then replicas A and B run
#      the same shared workload concurrently; B is killed with SIGKILL
#      mid-traffic and replaced by C; `verify` checks that no effect
#      happened twice and that the user-ID ledger is unique.
#   3. Serving replicas (ADR-0020 slice 5): scenario S610 starts two real
#      `hopae serve` processes on one database behind a TCP round-robin and
#      drives logins, verify, handoffs, console writes and a SIGKILL over HTTP.
#
#   make qualify-postgres
#
# Environment: HOPAE_PG_IMAGE (default postgres:17-alpine), CARGO_JOBS (4).
set -euo pipefail
image="${HOPAE_PG_IMAGE:-postgres:17-alpine}"
name="hopae-pg-qualify-$$"
password="hopae-q-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
work="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/qualify-postgres.$$"
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill -9 "$p" 2>/dev/null || true; done
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/state" "$work/replicas"
chmod 700 "$work/state"

cargo build -j "${CARGO_JOBS:-4}" --locked --features postgres --bin hopae --example qualify_postgres_replicas
target_dir="$(dirname "$work")"
hopae="$target_dir/debug/hopae"
qualify="$target_dir/debug/examples/qualify_postgres_replicas"

docker run -d --rm --name "$name" \
  --tmpfs /var/lib/postgresql/data:size=512m \
  -e POSTGRES_USER=hopae -e POSTGRES_DB=hopae -e POSTGRES_PASSWORD="$password" \
  -p "127.0.0.1:${port}:5432" "$image" >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$name" pg_isready -U hopae -d hopae -h 127.0.0.1 >/dev/null 2>&1; then break; fi
  sleep 0.5
done
docker exec "$name" pg_isready -U hopae -d hopae -h 127.0.0.1 >/dev/null
docker exec -e PGPASSWORD="$password" "$name" timeout 20 psql -h 127.0.0.1 -U hopae -d hopae -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE qualify" </dev/null
url_for() { echo "host=127.0.0.1 port=${port} user=hopae password=${password} dbname=$1"; }

echo "== 1. SQLite -> PostgreSQL migration"
export HOPAE_QUALIFY_CALLER_KEY="qualify-caller-key-0123456789abcdef0123456789"
export HOPAE_QUALIFY_PG="$(url_for hopae)"
cat >"$work/sqlite.json" <<EOF
{"state_dir": "$work/state", "portal": {"public_url": "https://auth.example.test"},
 "gateway": {"kind": "hangang", "caller_key_env": "HOPAE_QUALIFY_CALLER_KEY"}}
EOF
cat >"$work/postgres.json" <<EOF
{"state_dir": "$work/state", "portal": {"public_url": "https://auth.example.test"},
 "gateway": {"kind": "hangang", "caller_key_env": "HOPAE_QUALIFY_CALLER_KEY"},
 "store": {"kind": "postgres", "postgres": {"url_env": "HOPAE_QUALIFY_PG"}}}
EOF
timeout 60 "$hopae" --config "$work/sqlite.json" providers import </dev/null >/dev/null
before="$(sha256sum "$work/state/hopae.db" | cut -d' ' -f1)"
timeout 120 "$hopae" --config "$work/postgres.json" store migrate-to-postgres </dev/null
if timeout 120 "$hopae" --config "$work/postgres.json" store migrate-to-postgres </dev/null 2>"$work/second.err"; then
  echo "FAIL a second migration into the non-empty target was accepted"; exit 1
fi
grep -q "not empty" "$work/second.err" && echo "PASS second migration refused: target not empty"
after="$(sha256sum "$work/state/hopae.db" | cut -d' ' -f1)"
[ "$before" = "$after" ] && echo "PASS the SQLite file is unchanged (rollback artefact)" || { echo "FAIL SQLite file changed"; exit 1; }

echo "== 2. Two replicas, one killed mid-traffic"
export HOPAE_QUALIFY_PG_URL="$(url_for qualify)" HOPAE_QUALIFY_DIR="$work/replicas"
timeout 300 "$qualify" setup </dev/null
# The workers run without a wrapper so the SIGKILL reaches the replica
# itself; the cleanup trap kills whatever is left.
HOPAE_QUALIFY_REPLICA=a "$qualify" work </dev/null & a=$!; pids+=("$a")
HOPAE_QUALIFY_REPLICA=b "$qualify" work </dev/null & b=$!; pids+=("$b")
sleep "${HOPAE_QUALIFY_KILL_AFTER:-3}"
if kill -9 "$b" 2>/dev/null; then
  echo "killed replica b (pid $b) mid-traffic after $(wc -l <"$HOPAE_QUALIFY_DIR/b.log") logged effects"
else
  echo "FAIL replica b finished before the kill (raise the workload)"; exit 1
fi
wait "$b" 2>/dev/null || true
HOPAE_QUALIFY_REPLICA=c "$qualify" work </dev/null & c=$!; pids+=("$c")
wait "$a"; wait "$c"
timeout 120 "$qualify" verify </dev/null

echo "== 3. Two serving replicas behind a round-robin balancer (S610)"
export HOPAE_TEST_POSTGRES_URL="$(url_for hopae)"
timeout 900 cargo test -j "${CARGO_JOBS:-4}" --locked --features postgres,test-hooks --test scenarios -- s610 </dev/null
echo "qualification passed"
