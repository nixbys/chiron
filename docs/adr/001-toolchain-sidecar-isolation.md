# ADR 001: Toolchain Isolation via Sidecar Container

**Status:** Accepted
**Date:** 2026-06-20
**Corrected:** 2026-08-31 — the mechanism this ADR originally described
(`podman exec`) was never what the code actually does; see the Decision
section below for what's real. The core decision (a dedicated sidecar
container) is unchanged.

## Context

Odysseus-red needs to invoke Kali-class security tools (nmap, sqlmap, nuclei, etc.) from within MCP server Python code. There were two viable options:

1. Install tools directly into the main Odysseus container image.
2. Run tools in a separate sidecar container and exec into it.

## Decision

Use a dedicated sidecar container (`odysseus-toolchain`) based on `kalilinux/kali-rolling`, managed via a `docker-compose.security.yml` overlay.

MCP servers call it over HTTP, not `podman exec`: `docker/toolchain/exec_api.py` runs a minimal `POST /exec` API inside the sidecar (no ports published to the host — reachable only from other containers on the internal Compose network), and `mcp_servers/common.py`'s `exec_in_toolchain()` is the one chokepoint every toolchain-backed MCP server tool call goes through to reach it. Three layers gate what that API will actually run:
- **Auth**: a shared Bearer token (`EXEC_API_TOKEN`), compared with `secrets.compare_digest` (constant-time). The process refuses to start with the token unset or left as the shipped placeholder — no accidental unauthenticated deployment.
- **Allowlist**: `args[0]` (the binary) must be in a fixed `ALLOWED_BINARIES` set matching what the image actually installs; there is no general-purpose shell reachable through this API at all.
- **Rate limiting**: `mcp_servers/common.py` tracks recent invocations per binary in a shared SQLite audit trail and rejects calls over the configured limit, before they ever reach the sidecar.

Every invocation is logged to that same audit trail (`data/audit.db`) — see `mcp_servers/audit_server.py` — including, since this session, a tamper-evident hash chain over the whole table and (optionally encrypted) full raw output per call.

## Consequences

**Positive:**
- Odysseus core image stays unchanged — upstream merges remain clean.
- Security tools can be updated, rebuilt, or replaced without touching Odysseus.
- The sidecar can be omitted entirely on machines where only passive/API-based tools are needed.
- Clear blast radius: a compromised tool execution is contained to the sidecar.
- The exec API's own allowlist + rate limiting are enforced regardless of what an individual MCP server does or forgets to check — a second, server-independent boundary around arbitrary command execution.

**Negative:**
- Requires the sidecar to be running for active tools to work.
- The HTTP round-trip adds a small latency overhead per tool invocation.
- Sharing files between Odysseus and the sidecar requires a named volume (`toolchain-workspaces`).
- The exec API is unauthenticated-by-default risk if `EXEC_API_TOKEN` is ever weak (not unset — that case is refused at startup) — see `SECURITY.md`.

## Alternatives Considered

**Install into main container:** Rejected. Merging upstream Dockerfile changes would require manual reconciliation every release. Also bloats the main image significantly.
