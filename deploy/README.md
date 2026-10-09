# Deployment template

Portable, public templates for running Hopae in production. Operator copies
(`hopae.env`, `hopae.local.json`, `state/`) stay local and are git-ignored. The
hostnames (`auth.example.test`, `app.example.test`) are placeholders.

| File | Purpose |
| --- | --- |
| `compose.yaml` | Hardened Docker Compose service: user 1000, read-only root, all capabilities dropped, `no-new-privileges`, memory and process limits, rotated JSON logs, host network namespace with loopback listeners |
| `hopae.example.json` | Configuration with one application and the Google provider; copy to `hopae.local.json`. The management console is off; add the `admin` block below to enable it |
| `env.example` | Environment variable names (values are `change-me` placeholders); copy to `hopae.env` |
| `hangang-routes.example.json` | The portal route, a protected application route and the `hopae-admin` console route, as Hangang route objects (the protected routes need gateway changes HC-3 for `static_request_headers` and HC-12 for the route-level `strip_request_cookies`, which also belongs on any public route of the same host; without HC-12 the session handle reaches the application in the `cookie` header. The console route deliberately has **no** `strip_request_cookies`: the console reads its own handle cookie) |

The image is built from the repository `Dockerfile` (static musl binary, empty
`scratch` base). Tag convention: `hopae:<version>-<shortsha>`.

## Steps

1. Build: `docker build --network=host -t hopae:0.1.0-abc1234 .` from the repository root (or let `docker compose build` do it), and set `HOPAE_TAG` to the tag.
2. Create the private files: `cp env.example hopae.env` and `cp hopae.example.json hopae.local.json`; edit both. Generate the caller key with a CSPRNG (for example `openssl rand -base64 32`); give the gateway the same value as `HANGANG_HOPAE_KEY`.
3. Create the state directory: `install -d -m 700 -o 1000 -g 1000 state`.
4. Validate: `docker compose run --rm hopae --check --config /etc/hopae/hopae.json`. It prints the route `auth` fragment and the provider redirect URI (`https://auth.example.test/callback/google`) to register at the provider.
5. Back up `state/` if it holds data, then `docker compose up -d`.
6. Register the two routes (portal and application; the console route only if you enable the console, below) of `hangang-routes.example.json` on the gateway (admin API for a live gateway), with your real hosts and backend for the application.
7. Smoke test: open the protected host in a browser, sign in, confirm the upstream sees the identity headers and a client-supplied `x-forwarded-user` does not reach it, sign out, and confirm the next request redirects to login.

## Management console (optional)

The console is an extra listener and an extra route. Everything below uses the
placeholder host `hopae-admin.example.test`; use your own.

1. Give the console host DNS and TLS on the gateway.
2. Add to `hopae.local.json` (a fragment; `listen.admin` defaults to `127.0.0.1:8702`, and the listener is bound only when `admin.public_url` is set):

```json
{
  "listen": {"portal": "127.0.0.1:8700", "gateway": "127.0.0.1:8701", "admin": "127.0.0.1:8702"},
  "admin": {
    "public_url": "https://hopae-admin.example.test",
    "max_auth_age": "12h"
  }
}
```

3. Register the `hopae-admin` route of `hangang-routes.example.json` with your host. It must have the `auth` block and must not strip Hopae's cookies. The gateway's address must be in `trusted_proxies` (the default `127.0.0.1/32` fits a gateway on the same host).
4. Validate and restart: `docker compose run --rm hopae --check --config /etc/hopae/hopae.json` lists the console as the implicit application `admin`, prints the route fragment and the freshness capability of each provider (for the Google preset: `reauth unsupported: console freshness is Hopae login age`). The start prints `admin listening on 127.0.0.1:8702`.
5. Sign in once at the console host (the page answers `403 not_admin` and shows your user id), then `docker compose run --rm hopae admin grant <user_id> --config /etc/hopae/hopae.json`, and reload the page. If you grant by email and the provider is not authoritative for that address, the command prints the resolved user and asks for `--confirm <user_id>`.

The first start after the upgrade applies migration 0003 and writes
`state/hopae.db.bak-v2` first; see [the operations guide](../docs/OPERATIONS.md#upgrade-and-migration-backups).
The administration guide is [../docs/ADMIN.md](../docs/ADMIN.md).

Operation, upgrades, backups and key rotation: see
[the operations guide](../docs/OPERATIONS.md). Every key: see
[the configuration reference](../docs/CONFIG.md).
