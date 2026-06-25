# Changelog

All notable changes to **Odysseus Red** (this fork) are documented here. Changes to the upstream Odysseus platform appear in the [upstream repository](https://github.com/pewdiepie-archdaemon/odysseus).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

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
