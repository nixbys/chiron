# Reverse Proxy Setup

Odysseus-red's HTTP services should never be exposed to the network without TLS and rate limiting. This guide covers three common options: Caddy (recommended for simplicity), nginx, and Traefik.

All examples assume:
- Odysseus web UI runs at `http://localhost:8080` (internal)
- Your public domain is `odysseus.example.com`
- BentoPDF runs at `http://localhost:3000` (internal, optional to expose)

---

## Caddy (recommended)

Caddy handles TLS automatically via Let's Encrypt with zero configuration.

```
# /etc/caddy/Caddyfile

odysseus.example.com {
    # Automatic HTTPS via Let's Encrypt
    reverse_proxy localhost:8080

    # Rate limit: 30 requests/minute per client IP (Caddy 2.7+ with rate_limit plugin)
    # rate_limit {
    #     zone dynamic {
    #         key {remote_host}
    #         events 30
    #         window 1m
    #     }
    # }

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        -Server
    }

    # Block common scanners and bots
    @blocked path /wp-admin* /wp-login* /.env /phpinfo*
    respond @blocked 403
}
```

Start: `systemctl enable --now caddy`

---

## nginx

```nginx
# /etc/nginx/sites-available/odysseus

limit_req_zone $binary_remote_addr zone=odysseus_api:10m rate=30r/m;

server {
    listen 80;
    server_name odysseus.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name odysseus.example.com;

    # Certificates — use certbot or your own PKI:
    # certbot --nginx -d odysseus.example.com
    ssl_certificate     /etc/letsencrypt/live/odysseus.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/odysseus.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'";
    server_tokens off;

    location / {
        limit_req zone=odysseus_api burst=10 nodelay;
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (required for Odysseus live agent output)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # Block common scanner paths
    location ~* \.(env|git|sql|bak|log)$ { return 403; }
    location ~ /\.ht { return 403; }
}
```

Enable: `ln -s /etc/nginx/sites-available/odysseus /etc/nginx/sites-enabled/ && nginx -t && systemctl reload nginx`

---

## Traefik (Docker Compose)

Add to your `docker-compose.security.yml` if you prefer a container-native proxy:

```yaml
services:
  traefik:
    image: traefik:v3.2
    command:
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --certificatesresolvers.letsencrypt.acme.email=your@email.com
      - --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json
      - --certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - traefik-certs:/letsencrypt
    restart: unless-stopped

  odysseus:
    # (existing odysseus service)
    labels:
      - traefik.enable=true
      - traefik.http.routers.odysseus.rule=Host(`odysseus.example.com`)
      - traefik.http.routers.odysseus.entrypoints=websecure
      - traefik.http.routers.odysseus.tls.certresolver=letsencrypt
      - traefik.http.services.odysseus.loadbalancer.server.port=8080
      # Rate limiting middleware (50 req/s with burst of 100)
      - traefik.http.middlewares.odysseus-ratelimit.ratelimit.average=50
      - traefik.http.middlewares.odysseus-ratelimit.ratelimit.burst=100
      - traefik.http.routers.odysseus.middlewares=odysseus-ratelimit

volumes:
  traefik-certs:
```

---

## Internal-only deployment

If Odysseus is only accessible from a VPN or local network, binding to localhost is sufficient — no public TLS setup needed:

```yaml
# docker-compose.security.yml
services:
  odysseus:
    ports:
      - "127.0.0.1:8080:8080"  # loopback only — not 0.0.0.0
```

For remote team access, prefer a WireGuard VPN over exposing the port publicly.

---

## exec API protection

The toolchain exec API (`http://odysseus-toolchain:8088`) must **never** be reachable from outside the Docker network. It is internal-only by design — no ports are published. Always set `EXEC_API_TOKEN` in `.env` to a strong random value:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Add to `.env`:
```
EXEC_API_TOKEN=<output from above>
```
