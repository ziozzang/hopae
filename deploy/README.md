# Deployment template

Portable, public templates for running Hopae in production. Operator copies
(`hopae.env`, `hopae.local.json`, `state/`) stay local and are git-ignored. The
hostnames (`auth.example.test`, `app.example.test`) are placeholders.

| File | Purpose |
| --- | --- |
| `compose.yaml` | Hardened Docker Compose service: user 1000, read-only root, all capabilities dropped, `no-new-privileges`, memory and process limits, rotated JSON logs, host network namespace with loopback listeners |
| `hopae.example.json` | Configuration with one application and the Google provider; copy to `hopae.local.json` |
| `env.example` | Environment variable names (values are `change-me` placeholders); copy to `hopae.env` |
| `hangang-routes.example.json` | The portal route and a protected application route, as Hangang route objects (the protected route needs gateway changes HC-3 for `static_request_headers` and HC-12 for the route-level `strip_request_cookies`, which also belongs on any public route of the same host; without HC-12 the session handle reaches the application in the `cookie` header) |

The image is built from the repository `Dockerfile` (static musl binary, empty
`scratch` base). Tag convention: `hopae:<version>-<shortsha>`.

## Steps

1. Build: `docker build --network=host -t hopae:0.1.0-abc1234 .` from the repository root (or let `docker compose build` do it), and set `HOPAE_TAG` to the tag.
2. Create the private files: `cp env.example hopae.env` and `cp hopae.example.json hopae.local.json`; edit both. Generate the caller key with a CSPRNG (for example `openssl rand -base64 32`); give the gateway the same value as `HANGANG_HOPAE_KEY`.
3. Create the state directory: `install -d -m 700 -o 1000 -g 1000 state`.
4. Validate: `docker compose run --rm hopae --check --config /etc/hopae/hopae.json`. It prints the route `auth` fragment and the provider redirect URI (`https://auth.example.test/callback/google`) to register at the provider.
5. Back up `state/` if it holds data, then `docker compose up -d`.
6. Register the two routes of `hangang-routes.example.json` on the gateway (admin API for a live gateway), with your real hosts and backend for the application.
7. Smoke test: open the protected host in a browser, sign in, confirm the upstream sees the identity headers and a client-supplied `x-forwarded-user` does not reach it, sign out, and confirm the next request redirects to login.

Operation, upgrades, backups and key rotation: see
[the operations guide](../docs/OPERATIONS.md). Every key: see
[the configuration reference](../docs/CONFIG.md).
