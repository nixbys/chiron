# ADR 001: Toolchain Isolation via Sidecar Container

**Status:** Accepted
**Date:** 2026-06-20

## Context

Odysseus-red needs to invoke Kali-class security tools (nmap, sqlmap, nuclei, etc.) from within MCP server Python code. There were two viable options:

1. Install tools directly into the main Odysseus container image.
2. Run tools in a separate sidecar container and exec into it.

## Decision

Use a dedicated sidecar container (`odysseus-toolchain`) based on `kalilinux/kali-rolling`, managed via a `docker-compose.security.yml` overlay. MCP servers call `podman exec odysseus-toolchain <tool> ...` via subprocess.

## Consequences

**Positive:**
- Odysseus core image stays unchanged — upstream merges remain clean.
- Security tools can be updated, rebuilt, or replaced without touching Odysseus.
- The sidecar can be omitted entirely on machines where only passive/API-based tools are needed.
- Clear blast radius: a compromised tool execution is contained to the sidecar.

**Negative:**
- Requires the sidecar to be running for active tools to work.
- `podman exec` adds a small latency overhead per tool invocation (~50ms).
- Sharing files between Odysseus and the sidecar requires a named volume (`toolchain-workspaces`).

## Alternatives Considered

**Install into main container:** Rejected. Merging upstream Dockerfile changes would require manual reconciliation every release. Also bloats the main image significantly.
