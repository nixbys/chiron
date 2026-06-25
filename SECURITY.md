# Security Policy

Odysseus is a self-hosted AI workspace with privileged local capabilities. Please do not run it as a public, unauthenticated service.

## Supported Versions

Security fixes are handled on the default branch until formal releases are cut.

## Deployment Guidance

- Keep `AUTH_ENABLED=true` for any network-accessible deployment.
- Keep `LOCALHOST_BYPASS=false` outside local development.
- Set `SECURE_COOKIES=true` when Odysseus is served through HTTPS by a trusted reverse proxy or private access gateway.
- Use HTTPS when exposing the app beyond localhost.
- Put the authenticated Odysseus web/API entrypoint behind a trusted reverse proxy or private access layer such as Cloudflare Access, Tailscale, or a VPN.
- Keep ChromaDB, SearXNG, ntfy, Ollama, vLLM, llama.cpp, databases, and raw model/provider APIs internal-only.
- Protect `.env`, `data/`, `logs/`, uploads, generated media, backups, auth/session files, database files, API keys, and model/provider tokens.
- Disable open signup unless you intentionally want new accounts.
- Keep demo/test users non-admin, and remove them entirely on serious deployments.
- Give admin accounts strong passwords and enable 2FA where possible.
- Leave high-risk agent tools restricted to admins: shell, Python, file read/write, email send/read, MCP, app API, task/skill/memory management, settings, tokens, and model serving.
- Rotate API keys, webhook secrets, and Odysseus API tokens if they appear in logs, screenshots, demos, or shared chats.
- Treat shell, model-serving, MCP, email, calendar, and vault features as privileged admin functionality.
- Common internal-only ports are Odysseus `7000`, SearXNG `8080`, ntfy `8091`, ChromaDB `8100`, Ollama `11434`, and local model/provider APIs such as `8000-8020`.

## Publishing A Fork

Before pushing a public fork, run:

```bash
git status --short
git check-ignore -v .env data/auth.json data/app.db logs/compound.log odysseus.db
git grep -n -I -E "(sk-[A-Za-z0-9_-]{20,}|xox[baprs]-|AIza[0-9A-Za-z_-]{20,}|Bearer [A-Za-z0-9._~+/-]{20,})" -- . ':!static/lib/**' ':!package-lock.json'
```

Only `.env.example`, docs, source, tests, and static assets should be committed. Never commit live `.env` values, `data/` contents, local databases, uploaded files, generated media, logs, backups, auth/session files, API keys, model/provider tokens, password hashes, or personal documents.

## Reporting

Please report vulnerabilities privately via GitHub security advisories if available, or by opening a minimal issue that does not disclose exploit details.

---

## Odysseus Red — Additional Security Guidance

This fork adds a Kali Linux sidecar, OpenSearch, and 14 MCP servers that execute security tools. The following guidance applies in addition to everything above.

### Toolchain Authorization

**All active tools require explicit written authorization for any target.** The MCP servers will execute nmap, sqlmap, nuclei, hydra, john, and other tools precisely as instructed. This is intentional — but it means a compromised Odysseus session can harm external systems.

Before any active scan:

1. Confirm written authorization covers the target IP ranges, domains, and test types.
2. Prefer `passive` SpiderFoot use case for external targets unless active probing is authorized.
3. Lock down the toolchain container: do not publish port 8088 beyond the internal Docker network.
4. Set `EXEC_API_TOKEN` to a strong random value (`openssl rand -hex 32`) — the default placeholder is not safe for any deployment.

### Toolchain Container Hardening

- The exec API (`/exec_api.py`) accepts arbitrary command arrays over HTTP. Restrict access to the internal `odysseus-security` network only.
- Log rotation: `exec_api.jsonl` grows unbounded; rotate or cap it in production.
- The Kali image runs as root by default. For higher-assurance deployments, create a dedicated non-root user and restrict capabilities with `--security-opt no-new-privileges`.

### OpenSearch

- The bundled OpenSearch instance uses default credentials (`admin`/`admin`) — change `OPENSEARCH_USER`/`OPENSEARCH_PASSWORD` before any shared deployment.
- Do not expose port 9200 outside the internal network.

### Additional Secrets

In addition to `.env`, protect:
- `data/assets.db` — asset inventory and findings (SQLite)
- `data/attck_enterprise.json` — cached ATT&CK STIX data (no secrets, but large)
- `exec_api.jsonl` — exec API audit log (may contain command arguments with target data)

### Reporting Issues in Fork Additions

For vulnerabilities in MCP servers (`mcp_servers/`), the Dockerfile, or the exec API, open a GitHub security advisory on this repo (`nixbys/odysseus-red`). For vulnerabilities in upstream Odysseus code (`routes/`, `src/`, etc.), report to `pewdiepie-archdaemon/odysseus` upstream.
