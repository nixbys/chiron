# ADR 002: Podman as Primary Container Runtime

**Status:** Accepted
**Date:** 2026-06-20

## Context

The primary development host runs Bazzite (immutable Fedora Kinoite), which ships Podman 5.x by default. Docker Engine is not installed and is not trivially layerable on an ostree-based system.

## Decision

Use `podman` and `podman-compose` as the primary container runtime. MCP servers read `ODYSSEUS_CONTAINER_RUNTIME` from the environment (default: `podman`) to construct exec calls, making the runtime switchable without code changes.

## Consequences

**Positive:**
- No Docker daemon required — Podman is daemonless and rootless by default.
- Works natively on Bazzite without layering packages onto the immutable OS.
- Compose files are format-compatible; `podman-compose` consumes standard `docker-compose.yml` syntax.

**Negative:**
- Some Docker Compose v3 features have partial support in `podman-compose` — network configuration needs verification.
- CI jobs use Docker (standard GitHub Actions runners) — the `ODYSSEUS_CONTAINER_RUNTIME=docker` env var must be set in CI.

## Migration

Any contributor on a Docker-based host sets `ODYSSEUS_CONTAINER_RUNTIME=docker` in their `.env` — no code changes needed.
