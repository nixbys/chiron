# Changelog

All notable changes to **Odysseus Red** (this fork) are documented here. Changes to the upstream Odysseus platform appear in the [upstream repository](https://github.com/pewdiepie-archdaemon/odysseus).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Releases in progress may be tagged `vX.Y.Z-alpha.N` / `-beta.N` / `-rc.N` before the final `vX.Y.Z` — see [ADR 006](docs/adr/006-release-channel-strategy.md). Those prerelease tags don't get their own section here; their GitHub Release notes are generated from whatever's under `[Unreleased]` at tag time.

---

## [Unreleased]

### Fixed
- `src/agent_loop.py` — tool output, live progress tails, and displayed
  commands now get redacted for common secret shapes (cookies, URL
  credentials, `Authorization` headers, provider-shaped bare tokens,
  PEM private keys) before reaching the model or the SSE stream to the
  client. There was previously no redaction anywhere in this pipeline.
  Salvaged from an unlanded local branch discovered during a repo
  cleanup pass; see that commit for full detail.
- `README.md` — MCP tool tables had drifted from the actual server
  code: `intel_server` was missing `censys_host`/`censys_search`,
  `osint_server` was missing `subdomain_enum`, `web_vuln_server` was
  missing `ffuf_fuzz`, `pdf_server` was missing `generate_report`, and
  `asset_server` listed two tools (`asset_get`, `service_list`) that
  don't exist in the code while omitting two that do (`asset_summary`,
  `finding_update`). Also fixed a stale `docs/adr/` count (004 → 005)
  and the Quick Start's Podman/Docker command wording.
- `.env.example` / `README.md` — the Censys config comment referenced
  a `censys_server` module that was never created; Censys support
  actually lives in `intel_server.py`.
- `docs/develop-mcp-servers.md` — the "registering a new server" step
  referenced a `config.json` (or equivalent) file that doesn't exist;
  MCP servers are registered as rows in the app's own database via
  Settings → Integrations → MCP or `POST /api/mcp/servers`, not a
  static config file.

### Removed
- 9 stale/superseded branches on `origin` (all content already present
  on `dev`, confirmed individually rather than assumed from merge
  ancestry). One of them held real unlanded work (the redaction fix
  above) that was ported to `dev` first.

---

## [0.4.0] — 2026-08-26

Full upstream re-sync (dev fully converged with upstream `dev`) plus an
MCP-reliability and security-hardening pass, released as `main`'s first
promotion since `v0.3.1`.

### Upstream sync

`dev` had drifted a very long way behind `upstream/dev`
(pewdiepie-archdaemon/odysseus) since the last release. Merged upstream in
24 reviewed batches (each with full per-hunk provenance review — no blanket
"take theirs"/"take ours" — verified individually via compile checks, JS
syntax checks, an AST duplicate-definition scanner, and a full pytest run
compared against a passing baseline), bringing `dev` to zero commits behind
`upstream/dev` at merge time. See the individual
`merge: sync upstream pewdiepie-archdaemon/odysseus dev (batch N, ...)`
commits on `dev` for full per-batch detail (each documents exactly which
upstream commits landed and how every conflict was resolved). Notable
upstream features absorbed this cycle include: per-tool capability/
result-integrity gating for indirect prompt-injection defense
(`src/tool_capabilities.py`, `src/tool_approvals.py`), a model-capability
reader framework (`src/model_capability_readers/`), several route
domain-subpackage splits (document, mcp, webhook, task, note, search, vault,
cleanup, admin_wipe, compare), and the platform version advancing to
`1.0.3`.

### Added

- `scripts/mcp_health_check.py` — speaks the real MCP stdio protocol
  (spawn → initialize → list_tools) to each of the 14 security-focused MCP
  servers plus the 4 core-platform servers (email, memory, image_gen, rag),
  independent of the app's own MCP server registry. Confirms every server
  starts cleanly and correctly advertises its tools — upstream has open
  reports of MCP servers intermittently failing to register with tools
  "disappearing" silently rather than raising a visible error, and this
  fork's headline differentiator is its 14 cybersecurity MCP servers.
  Usable standalone (`--json` for CI, `--core-only`/`--security-only` to
  scope a run) and as a manual pre-release check.
- `GET /api/ready` now reports an `mcp_servers` check: configured/connected
  counts and any server currently in `error`/`timeout` status, sourced from
  the existing `McpManager` connection-status snapshot (no new connection
  attempts, so it stays fast). Informational only — never fails overall
  readiness — but a broken MCP server is now visible here instead of only
  discoverable by a user hitting a missing tool mid-session.
- `.github/workflows/ci.yml`: new `sensitive-paths` job. Runs
  `git ls-files` on every push/PR and fails if any tracked file matches
  `data/`, `logs/`, `backups/`, `.env` (excluding `.env.example`), or
  private-key filename patterns. Automates the "confirm no secrets/data
  ever get committed" checklist item as a real CI gate instead of relying
  on a human to remember it before every push.

### Fixed

- `mcp_servers/asset_server.py` — schema init ran unconditionally at
  *module import time*, before the MCP stdio handshake could even begin.
  Any unwritable or missing data directory (bad volume mount, full disk, a
  misconfigured read-only mount) crashed the whole server process before it
  could register a single tool, surfacing to the MCP client only as an
  opaque low-level transport exception — not an actionable message. Its
  sibling stateful servers (`risk_server`, `memory_server`, `rag_server`,
  `image_gen_server`) already use a safe lazy-init pattern that only
  touches the filesystem when a tool is actually invoked; `asset_server`
  was the sole outlier. Fixed to match: schema init now runs lazily on
  first real DB access. A genuinely broken data directory now surfaces as
  a normal per-call `[error:db_error] ...` MCP response instead of taking
  down the process.
- `.gitignore` / `.dockerignore` — `backups/` (full data-directory
  snapshots written by `scripts/odysseus-backup`: DB, uploads, personal
  docs — everything `data/` itself is gitignored for) was not covered by
  either file. A `git add -A` after running a backup would have staged a
  complete personal-data snapshot; a Docker build from a checkout with a
  stray `backups/` dir would have baked it into an image layer. Audited
  currently-tracked files first — confirmed clean, so this closes a latent
  gap rather than an active leak.
- `.gitleaksignore` — the allowlisted fingerprint for the known jwt.io
  demo-token false positive in `tests/mcp_servers/test_transform_server.py`
  pinned a commit SHA (`36edb229...`) reachable only via the `v0.3.1` tag.
  This fork's `dev` history reconstruction during the upstream-sync merges
  produced a *different* commit SHA (`6a7ce654...`) for the same
  byte-identical content, which was never allowlisted — so the Secret scan
  CI check had been failing on every push since the upstream-sync effort
  began, mischaracterized along the way as "confirmed pre-existing and
  unrelated" rather than actually run down. Added the correct fingerprint;
  verified locally with the exact pinned gitleaks binary before pushing.
- `.github/workflows/release.yml` — the release-notes template hardcoded
  "Upstream base: Odysseus `1.0.1`", stale since the upstream-sync batches
  above advanced the platform to `1.0.3`.

---

## [0.3.1] — 2026-06-25

SDLC hardening, CI consolidation, and release cycle.

### Added
- `CHANGELOG.md` — version history following Keep a Changelog
- `ODYSSEUS_RED_VERSION` in `src/constants.py` — fork version independent of upstream
- `.github/release-drafter.yml` + `workflows/release-drafter.yml` — auto-draft release notes from merged PRs
- `.github/workflows/release.yml` — creates GitHub Release from CHANGELOG on `v*` tag push
- `.github/codeql/codeql-config.yml` — restrict CodeQL analysis to fork paths only
- CODEOWNERS entries for all fork-specific paths (`@nixbys`)
- Fork-specific sections in `SECURITY.md` (toolchain, OpenSearch, exec API guidance) and `CONTRIBUTING.md` (setup, MCP dev, release process)
- `tests/mcp_servers/test_transform_server.py` — 13 tests (all in-process, no mocking)
- `tests/mcp_servers/test_yara_server.py` — 5 tests with path-traversal rejection
- `tests/mcp_servers/test_asset_server.py` — 5 SQLite lifecycle tests (77 total)
- CI: `python-syntax`, `hadolint`, `yaml-lint` jobs in `ci-security.yml`
- CI: `mcp_servers/ modules/` added to `compileall` in `ci.yml`
- CI: `dev` branch added to push triggers for `ci.yml`, `secret-scan.yml`, `workflow-security.yml`
- `findings_server.py` added to bandit CI job

### Fixed
- Missing env vars in `.env.example` (`EXEC_API_TOKEN`, `CENSYS_API_ID/SECRET`, `OPENSEARCH_*`)
- `*.jsonl` missing from `.gitignore` (exec API audit log)
- All 30 CodeQL `py/path-injection` alerts dismissed — all were in unmodified upstream files

---

## [0.3.0] — 2026-06-24

Tier 3 intelligence, risk management, and IR playbooks.

### Added
- `mcp_servers/asset_server.py` — SQLite-backed asset and findings inventory (WAL mode)
- `mcp_servers/attck_server.py` — MITRE ATT&CK STIX lookup with 7-day local cache
- `mcp_servers/risk_server.py` — CVSS-based risk scoring and prioritized remediation plans
- `mcp_servers/findings_server.py` — OpenSearch findings persistence and search
- `skills/incident_response/ransomware_response.yaml` — host triage → IOC → ATT&CK → remediation
- `skills/incident_response/network_compromise.yaml` — entry scan → C2 intel → lateral movement TTPs
- `skills/incident_response/credential_breach.yaml` — attacker intel → credential-focused TTPs
- `skills/incident_response/ioc_triage.yaml` — rapid IOC triage against threat intel
- `skills/incident_response/threat_actor_profile.yaml` — threat actor dossier from OSINT + ATT&CK
- `skills/threat_hunting/ioc_hunt.yaml` — IOC hunt across asset inventory
- `skills/threat_hunting/network_exposure_audit.yaml` — unexpected exposure on known assets
- `skills/malware_analysis/file_triage.yaml` — static file triage with YARA, exiftool, hashes
- OpenSearch service added to `docker-compose.security.yml`

---

## [0.2.0] — 2026-06-24

Tier 2 new servers, toolchain hardening, and shared library.

### Added
- `mcp_servers/common.py` — shared `exec_in_toolchain()`, `mcp_error()`, `validate_ip()`, `validate_url()`, `validate_domain()`
- `mcp_servers/yara_server.py` — YARA scan, rule write, rule list
- `mcp_servers/exploit_server.py` — searchsploit, Exploit-DB lookup, CVE-to-exploit
- `mcp_servers/transform_server.py` — encode/decode, hash, gzip, regex, JWT decode, XOR (in-process)
- Bearer token auth on exec API (`EXEC_API_TOKEN`)
- `GET /health` endpoint on exec API
- Structured JSON audit logging to `/var/log/exec_api.jsonl`
- `docker/toolchain/Dockerfile` — HEALTHCHECK, new tools (ffuf, exploitdb, yara, trivy, subfinder, amass, httpx), Go binary retry wrapper
- `docs/develop-mcp-servers.md` — MCP server development guide
- `docs/reverse-proxy.md` — Caddy, nginx, Traefik HTTPS setup with exec API protection

### Changed
- All 5 original MCP servers refactored to use `common.py`
- Error format standardized to `[error:code] message` across all servers
- Input validation added to recon, web_vuln, hashcrack servers
- Toolchain base image changed from `kalilinux/kali-rolling:2025.2` (non-existent) to `latest`

### Fixed
- `kalilinux/kali-rolling:2025.2` tag did not exist on Docker Hub

---

## [0.1.0] — 2026-06-24

Tier 1 initial fork with 7 security MCP servers and CI.

### Added
- `mcp_servers/recon_server.py` — nmap, masscan
- `mcp_servers/intel_server.py` — Shodan, VirusTotal, CVE/NVD, OTX
- `mcp_servers/osint_server.py` — theHarvester, Sherlock, DNS, WHOIS
- `mcp_servers/web_vuln_server.py` — nikto, gobuster, sqlmap, nuclei
- `mcp_servers/hashcrack_server.py` — hashid, john
- `mcp_servers/spiderfoot_server.py` — SpiderFoot REST API client
- `mcp_servers/pdf_server.py` — PDF intel and report assembly (pypdf)
- `docker/toolchain/Dockerfile` — Kali Rolling sidecar with exec API
- `docker/toolchain/exec_api.py` — HTTP exec API for MCP-to-Kali bridge
- `docker-compose.security.yml` — toolchain + SpiderFoot + BentoPDF overlay
- `skills/recon/full_recon.yaml`
- `skills/osint/target_profile.yaml`, `spiderfoot_deep_scan.yaml`, `pdf_intel.yaml`
- `skills/web_assessment/web_full.yaml`
- `skills/reporting/pentest_report.md`
- `docs/adr/001-toolchain-sidecar-isolation.md`
- `docs/adr/002-podman-over-docker.md`
- `docs/adr/003-spiderfoot-integration.md`
- `docs/adr/004-bentopdf-integration.md`
- `.github/workflows/ci-security.yml` — bandit, pip-audit, unit tests, Dockerfile build, Trivy, upstream-drift

### Security
- Authorization requirement notice on all active tool documentation

---

## Upstream Sync History

| Date | Commits Merged | Notes |
|------|---------------|-------|
| 2026-06-24 | 65 | llama.cpp detection, credential URL redaction, atomic API key writes, OpenDyslexic font, ReDoS fix in calendar extractor, 30+ bug fixes |
