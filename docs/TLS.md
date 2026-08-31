# TLS

Chiron doesn't terminate TLS itself by default — the recommended path for
anything beyond `localhost` is a trusted reverse proxy or private access
layer in front of it (Cloudflare Access, Tailscale, a VPN, or Caddy/nginx/
Traefik terminating real HTTPS) — see [reverse-proxy.md](reverse-proxy.md)
for that setup, including automatic Let's Encrypt via Caddy.

This page covers the alternative: having the app terminate TLS itself,
for when you don't want to run a separate proxy — a LAN deployment, a
Tailscale-only box where a self-signed cert is enough, or a quick local
test of an HTTPS-dependent feature.

## Enable it

Set two env vars (paths are read **inside the container** — point them at
`/app/certs/...`, which `docker-compose.yml` mounts read-only from
`${APP_TLS_DIR:-./certs}` on the host):

```bash
# .env
SSL_KEYFILE=/app/certs/key.pem
SSL_CERTFILE=/app/certs/cert.pem
```

Both must be set together — either one alone is ignored (uvicorn needs
both). Leave both unset (the default) to keep serving plain HTTP for a
reverse proxy to front, unchanged from before.

Native (non-container) installs: `app.py`'s own `if __name__ ==
"__main__":` block reads the same two env vars directly — no separate
config.

## Generate a certificate

**Self-signed** (fastest — works for LAN/Tailscale access; browsers will
warn once until you accept/pin it):

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/key.pem -out certs/cert.pem -days 365 \
  -subj "/CN=chiron.local"
```

**A real, trusted certificate** without running a public-facing proxy:
[mkcert](https://github.com/FiloSottile/mkcert) issues locally-trusted
certs (no browser warning) for LAN/Tailscale hostnames —
`mkcert -install && mkcert -cert-file certs/cert.pem -key-file certs/key.pem chiron.local`.

## Restart

```bash
podman-compose -f docker-compose.yml -f docker-compose.security.yml --profile sidecars up -d --force-recreate odysseus
```

`podman logs -f chiron_odysseus_1` should show uvicorn serving on
`https://` once it's up. `SecurityHeadersMiddleware` (`core/middleware.py`)
already emits `Strict-Transport-Security` automatically whenever a request
arrives over `https://` (or with a trusted `X-Forwarded-Proto: https`) —
nothing else to configure for HSTS.

## Rotating or replacing a certificate

Overwrite the two files under your `APP_TLS_DIR` (`./certs` by default)
and force-recreate the container — uvicorn reads them at startup, not
per-request, so a running process won't pick up a swapped file without a
restart.
