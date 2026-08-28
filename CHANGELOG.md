# Changelog

All notable changes to **Odysseus Red** (this fork) are documented here. Changes to the upstream Odysseus platform appear in the [upstream repository](https://github.com/pewdiepie-archdaemon/odysseus).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Releases in progress may be tagged `vX.Y.Z-alpha.N` / `-beta.N` / `-rc.N` before the final `vX.Y.Z` — see [ADR 006](docs/adr/006-release-channel-strategy.md). Those prerelease tags don't get their own section here; their GitHub Release notes are generated from whatever's under `[Unreleased]` at tag time.

---

## [Unreleased]

### Added
- Multi-target support for `scheduled_recon` (`src/builtin_actions.py`): the
  task prompt now also accepts a `"targets"` array (merged with a single
  `"target"` string if both are present) and a `"use_engagement_assets":
  true` flag that resolves targets from an engagement's own asset
  inventory (`asset_server`'s `asset_list`) instead of listing them by
  hand. One reminder is sent per run covering every target's drift, not
  one per target — same batching `watchlist_check` already used. Fully
  backward compatible with a single `"target"` string.
- `verify_remediation` scheduled-task action (`src/builtin_actions.py`) — the
  remediation-verification loop: re-checks every `scheduled_recon`-sourced
  finding marked `remediated` to confirm the underlying issue is actually
  still gone, reconstructing what to re-test entirely from the finding's
  own `title`/`description` (no separate state store). Reopens the
  finding + sends a reminder if it's back; logs a confirming
  `engagement_server` event if it's genuinely still remediated. Scoped to
  `scheduled_recon` findings only — deliberately not `watchlist_check`/
  `sigma_sweep`/`host_monitor` findings, none of which carry an
  equivalently well-defined single re-testable item.
- `sigma_sweep` and `yara_sweep` scheduled-task actions (`src/builtin_actions.py`)
  — the scheduled-sweep fast-follow `sigma_server`/`yara_server` called out
  in 0.5.0's "v1 is on-demand only" notes. `sigma_sweep` converts every
  stored Sigma rule (or a configured subset) and re-runs it against
  OpenSearch; `yara_sweep` re-runs `yara_scan` against a configured target
  in the Kali toolchain container. Both diff their results against the last
  stored snapshot (`monitor_server`, extended with per-rule/per-target
  check types) and only file a finding + send a reminder when something
  actually changed since the last sweep — same drift-only-alerting design
  as `scheduled_recon`/`watchlist_check`. `sigma_sweep` reads each rule's
  own `level:` field for the filed finding's severity.
- `mcp_servers/host_telemetry_server.py` (19th MCP server) + `src/
  builtin_actions.py`'s new `host_monitor` action — read-only host
  telemetry (processes, listening sockets, logged-in users, cron jobs,
  installed packages) for the host/container Odysseus itself runs in, via
  `psutil` rather than the Kali toolchain sidecar (querying the sidecar's
  own process list would be useless for defensive monitoring of anything
  real). `host_monitor` diffs each check against the last stored snapshot
  (`monitor_server`) the same drift-only-alerting way as the other
  scheduled actions, filtering out kernel-thread name churn
  (`kworker/N:M`, renumbered by the kernel constantly) before diffing so
  it doesn't look like drift on every run. Container-boundary caveat: when
  Odysseus runs in Docker (the default), this only sees the container's
  own namespace, not the true host — documented in the module and README,
  not solved in this pass.
- Shared `_file_drift_finding()` helper in `src/builtin_actions.py`,
  extracted from the file-a-finding-and-log-an-engagement-event block that
  `scheduled_recon`/`watchlist_check`/`sigma_sweep`/`yara_sweep`/
  `host_monitor` all repeated. Also fixes a real gap this surfaced:
  `watchlist_check` was filing findings but never logging the
  corresponding engagement timeline event; it now does, like every other
  drift-detecting action.

---

## [0.5.0] — 2026-08-27

Five additions aimed at turning the security toolset from a one-shot toolbox
into something that keeps working while nobody's watching: case/engagement
grouping, continuous scheduled scanning with drift-only alerting, a
persistent IOC watchlist, notification wiring for both (reusing the existing
reminder-channel system — no new channel), and a Sigma detection-rule server
closing the log-detection gap next to YARA's file-pattern detection. 4 new
MCP servers (18 total), 2 modified, 61 new tests.

### Added
- `mcp_servers/sigma_server.py` — a new MCP server for authoring and
  testing Sigma detection rules, the log-detection complement to
  `yara_server.py`'s file-pattern detection. Runs entirely in-process
  (no Kali sidecar — Sigma rules match structured log/finding data, not
  files) via the optional `pysigma` + `pysigma-backend-opensearch`
  packages (`requirements-optional.txt`); without them,
  `sigma_rule_write`/`list`/`delete` still work (a rule just needs to be
  valid YAML), and `sigma_rule_convert`/`sigma_rule_test` return a clear
  `not_installed` error instead of crashing server registration.
  `sigma_rule_test` converts a stored rule to an OpenSearch Lucene query
  and runs it against `findings_server.py`'s `odysseus-findings` index by
  default. v1 is on-demand only — no scheduled rule sweep yet.
- `mcp_servers/watchlist_server.py` + `src/builtin_actions.py`'s new
  `watchlist_check` action — a persistent IOC watchlist (`watchlist_add`,
  IPs/domains/hashes/URLs, validated per kind) re-checked on a cron
  schedule against whichever of Shodan/VirusTotal/OTX/Censys are
  configured for that indicator's kind, filing a finding and sending one
  batched reminder only when a provider's result changes since the last
  check (open ports, VirusTotal detection counts, OTX pulse count,
  Censys services). The first check per (entry, provider) establishes the
  baseline silently, same as `scheduled_recon`.
- `mcp_servers/monitor_server.py` + `src/builtin_actions.py`'s new
  `scheduled_recon` action — turns one-shot recon into continuous
  monitoring. A `ScheduledTask` with `task_type="action"` and
  `action="scheduled_recon"` (configured via its `prompt` as JSON, e.g.
  `{"target": "example.com", "checks": ["ports", "cert"]}`) re-runs
  `nmap_scan`/`subdomain_enum`/the new `tls_cert_info` (`recon_server.py`)/a
  Shodan CVE lookup on whatever cron schedule the task uses, diffs the
  result against the last stored snapshot in `monitor_server.py`, and files
  a finding (via `findings_server`) plus a reminder (`dispatch_reminder`,
  respecting the user's existing `reminder_channel` setting) only when
  something actually changed — a new open port, new subdomain, changed TLS
  cert fingerprint, or a new CVE. The first run for a target/check
  establishes the baseline without filing anything. Fires a new
  `security_finding_added` event (`src/event_bus.py`) other scheduled tasks
  can trigger off of. `intel_server.py`'s Shodan/VirusTotal/NVD/OTX/Censys
  lookups were each split into a `_X_fetch() -> dict` (raw data) plus
  `_X_format() -> str` (existing text output, unchanged) so this and future
  callers can diff structured data instead of parsing formatted strings.
- `mcp_servers/engagement_server.py` — a new MCP server for grouping recon
  scans, findings, and watchlist activity under a named engagement/case
  (scope, client, start/end date), with an event timeline
  (`engagement_log_event` / `engagement_timeline`) for report assembly.
  `asset_server.py`'s `assets`/`findings` tables gained an `engagement_id`
  column (migrated in place for existing databases) and `findings_server.py`'s
  existing `engagement` field is now documented as accepting the id
  `engagement_create` returns. There's no shared database between MCP
  servers, so `engagement_id` is a convention key threaded through each
  server's own tools, not a real foreign key — see `engagement_server.py`'s
  module docstring.
- `src/host_capabilities.py` + `setup.py` — a new interactive host-capability
  scan (setup.py step 6, native installs) that probes `PATH` for the 16
  toolchain binaries and the well-known ports of the 6 sidecar services
  (Ollama, ChromaDB, SearXNG, SpiderFoot, OpenSearch, BentoPDF), verifies
  each service by its actual response shape rather than "port is open"
  alone (avoids mistaking an unrelated service on the same port for the
  real one), then offers to write the matching `TOOLCHAIN_EXEC_MODE_*` /
  service-URL lines into `.env` and logs accepted suggestions to
  `logs/host_capability_scan.log`. Self-detects when running inside the
  container (via `docker/entrypoint.sh`'s automatic `setup.py` invocation)
  and skips the binary scan there — container isolation makes it
  structurally meaningless — while still running the service scan against
  `host.docker.internal`. No-ops without prompting when stdin isn't a TTY
  or `ODYSSEUS_SKIP_HOST_SCAN` is set.
- `docker-compose.security.yml` — `toolchain`, `spiderfoot`, `bentopdf`,
  and `opensearch` each gained their own Compose profile name alongside
  the shared `sidecars` profile, so a subset of sidecars can now actually
  be started independently (e.g. `--profile toolchain --profile bentopdf
  --profile opensearch`). Previously all four shared one profile value,
  making the existing "omit `--profile sidecars` to skip just this one"
  doc comment literally false.
- [ADR 006](docs/adr/006-release-channel-strategy.md) — documents the
  chosen release-channel strategy: one working branch (`main`) with
  SemVer prerelease tags (`vX.Y.Z-alpha.N` → `-beta.N` → `-rc.N` →
  `vX.Y.Z`) instead of parallel long-lived alpha/beta/rc branches, plus
  the matching `release.yml` changes (prerelease detection, `[Unreleased]`
  fallback for prerelease tag CHANGELOG extraction).

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
