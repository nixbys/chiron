# ADR 008: Project Rebrand — "Odysseus Red" to "Chiron"

**Status:** Accepted
**Date:** 2026-08-28

## Context

The fork shipped its first four minor releases (through v0.5.0) under the working name "Odysseus Red" — a direct "upstream name + team-color suffix" pattern. As the fork's own surface grew (20 MCP servers, a security dashboard, engagement/watchlist/continuous-scanning features, its own design system), that name started working against it in two concrete ways: it read as a variant/reskin of upstream rather than a project with its own identity, and "Red" specifically implied offense-only tooling for a fork that had already grown defensive/blue capability (host telemetry, remediation verification, NIST compliance mapping) alongside it.

A 4-phase rebrand-and-redesign plan was scoped and approved: Phase 0 (pick a new name), Phase 1 (8 backend red/blue additions, shipped as v0.6.0), Phase 2 (a from-scratch visual design system and its application across the whole site), Phase 3 (this ADR — apply the new name), Phase 4 (a fork-owned roadmap document).

## Decision

**Rename the fork to "Chiron."** In Greek myth, Chiron is the centaur who trained both healers and warriors — a name that reads correctly for a toolkit that does reconnaissance/exploitation *and* telemetry/verification/compliance, without defaulting to either half. It was checked against trademark/naming collisions with existing security tooling and open-source projects before being selected; no material conflict was found.

## Scope: What Actually Gets Renamed

The rename applies to **this fork's own added identity** — not to the underlying upstream platform it's built on. Concretely:

**Renamed:**
- User-facing UI text and chrome: page titles, sidebar header, welcome screen, chat placeholder, login page, favicon/wordmark/icon, `manifest.json`.
- The fork's own docs: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `ACKNOWLEDGMENTS.md`, this ADR series' non-historical prose.
- The fork's own config/CI: `.env.example`'s fork-specific section, `.github/CODEOWNERS`, CodeQL config, release-drafter config, `ci-security.yml`, `release.yml`.
- The fork's own code identifiers where safe: `ODYSSEUS_RED_VERSION` → `CHIRON_VERSION` in `src/constants.py` (confirmed unused elsewhere before renaming), docstrings/comments/User-Agent strings in `mcp_servers/common.py`, `exploit_server.py`, `spiderfoot_server.py`, `scripts/mcp_health_check.py`, `setup.py`, `src/host_capabilities.py`.
- The GitHub repository itself: `nixbys/odysseus-red` → `nixbys/chiron` (renamed via GitHub's own rename flow; GitHub transparently redirects the old URL, so existing clones and links keep working).

**Deliberately not renamed:**
- The upstream "Odysseus" platform itself — its own code (`routes/`, most of `src/`, `services/`), its own docs, and every place this fork's docs *reference* upstream by its real name (e.g. "the Odysseus core image is not modified").
- Docker/Compose container and service names already in production use (`odysseus-toolchain`, `odysseus-spiderfoot`, `odysseus-bentopdf`, `odysseus-opensearch`, `odysseus-ollama`) and the `ODYSSEUS_*` environment-variable prefix (`ODYSSEUS_DATA_DIR`, `ODYSSEUS_ADMIN_USER`, `ODYSSEUS_CONTAINER_RUNTIME`, etc.) — these are load-bearing for every existing self-hosted deployment; renaming them would silently break running installs for a purely cosmetic gain.
- Internal, non-user-facing implementation details such as the `odysseus-theme` `localStorage` key and `window.__odysseusLogin*` globals — renaming these forgets every existing user's saved preferences for no visible benefit.
- Upstream-owned files this fork must never diverge from, per [ADR 005](005-upstream-sync-strategy.md): `ROADMAP.md`, `docs/index.html`, `package.json`.
- Every historical ADR (001–007) and every dated `CHANGELOG.md` entry. These are records of what was true when they were written — "Odysseus Red" is the correct, accurate name for the fork *at those points in time*, and rewriting them to say "Chiron" would falsify the record. `CHANGELOG.md`'s non-dated intro paragraph is the one exception, since it describes the project as it exists today rather than a dated event.

## Consequences

**Positive:**
- The fork now reads as its own project with red/blue scope, rather than a "Red-team reskin of Odysseus."
- Zero breakage for existing self-hosted users: no environment variable, container name, or stored preference changed meaning.
- The GitHub rename's automatic redirect means old clone URLs, bookmarks, and CI badge links referencing `nixbys/odysseus-red` keep resolving.

**Negative:**
- Two names now legitimately appear side by side in the repo's own history and docs (dated changelog/ADR entries say "Odysseus Red," current docs say "Chiron"). This is intentional per the scope above, but it means a contributor skimming older entries needs the one-line pointer at the top of `CHANGELOG.md` ("formerly named Odysseus Red") to connect the two.
- The rename touches enough files (UI, docs, CI/config, one renamed constant) that it needed its own dedicated pass rather than riding along with a feature change — accepted as a one-time cost.
