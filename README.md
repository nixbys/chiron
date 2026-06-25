<p align="center">
  <img src="docs/odysseus-wordmark.png" alt="Odysseus Red" width="280">
</p>

<p align="center">
  <strong>Odysseus Red</strong> — a cybersecurity-focused fork of <a href="https://github.com/pewdiepie-archdaemon/odysseus">Odysseus</a>.<br>
  Self-hosted AI workspace extended with penetration testing, OSINT, and threat intelligence tooling.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#mcp-tools">MCP Tools</a> ·
  <a href="#skills">Skills</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="docs/adr/">Decision Records</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="License">
  <img src="https://img.shields.io/github/actions/workflow/status/nixbys/odysseus-red/ci-security.yml?branch=dev&label=CI" alt="CI">
  <img src="https://img.shields.io/badge/upstream-pewdiepie--archdaemon%2Fodysseus-purple" alt="Upstream">
</p>

<p align="center">
  <img src="docs/odysseus-browser.jpg" alt="Odysseus interface">
</p>

---

## What This Is

Odysseus Red layers a complete cybersecurity toolchain on top of the [Odysseus](https://github.com/pewdiepie-archdaemon/odysseus) self-hosted AI workspace. The base platform provides chat, agents, memory, deep research, documents, and MCP — this fork adds:

- **14 cybersecurity MCP servers** wired to a Kali-based sidecar, SpiderFoot OSINT platform, OpenSearch, and BentoPDF
- **Pre-built agent skill workflows** for reconnaissance, OSINT, incident response, threat hunting, malware analysis, web assessment, and reporting
- **SpiderFoot** (200+ correlated OSINT modules) running as a persistent REST API sidecar
- **BentoPDF** — client-side PDF toolkit for metadata extraction, report assembly, and interactive editing
- **Asset inventory** with SQLite-backed tracking of hosts, services, and findings
- **MITRE ATT&CK mapping** — STIX-based technique lookup and TTP correlation
- **CVSS risk scoring** — aggregated risk summaries and prioritized remediation plans
- **OpenSearch findings persistence** — index, search, and track findings across engagements
- **Pentest report templates** aligned to PTES and the OWASP Testing Guide

Everything runs locally. No telemetry. All tool execution stays on your own infrastructure.

> **Authorization requirement:** All active tools (nmap, sqlmap, nuclei, etc.) require explicit authorization for any target. The toolchain will execute what you instruct — only point it at systems you are authorized to test.

---

## Quick Start

**Prerequisites:** Podman + podman-compose (or Docker + docker compose), git.

```bash
git clone https://github.com/nixbys/odysseus-red.git
cd odysseus-red
cp .env.example .env
# Edit .env — add your API keys (see Configuration below)
podman-compose -f docker-compose.yml -f docker-compose.security.yml up -d --build
```

Open `http://localhost:7000` once containers are healthy. The first admin password prints in:

```bash
podman logs odysseus
```

For Docker hosts, replace `podman-compose` with `docker compose` and set `ODYSSEUS_CONTAINER_RUNTIME=docker` in your `.env`.

Native installs, GPU notes, Windows/macOS instructions, and HTTPS are covered in the upstream [setup guide](docs/setup.md).

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Odysseus Red (port 7000)                       │
│           Chat · Agents · Research · Documents · MCP              │
└──┬──────────────┬──────────────┬──────────────┬───────────────────┘
   │ MCP stdio    │ MCP stdio    │ MCP stdio    │ MCP stdio
   ▼              ▼              ▼              ▼
┌──────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────────┐
│ mcp_servers/ │ │mcp_servers/│ │mcp_servers/│ │ mcp_servers/     │
│ recon        │ │ spiderfoot │ │ asset      │ │ pdf_server       │
│ osint        │ │(REST client│ │ attck      │ │ (pypdf)          │
│ web_vuln     │ └─────┬──────┘ │ risk       │ └──────────────────┘
│ intel        │       │:5001   │ findings   │
│ hashcrack    │ ┌─────▼──────┐ └─────┬──────┘
│ yara         │ │odysseus-   │       │ HTTP
│ exploit      │ │spiderfoot  │ ┌─────▼──────────┐
│ transform    │ │200+ modules│ │ OpenSearch     │
└──────┬───────┘ └────────────┘ │ :9200          │
       │ HTTP :8088             │ findings index  │
       ▼                        └────────────────┘
┌──────────────────────┐   ┌───────────────────────┐
│ odysseus-toolchain   │   │ odysseus-bentopdf      │
│ (Kali Rolling)       │   │ localhost:3000          │
│ nmap  masscan  ffuf  │   │ client-side WASM/JS     │
│ nikto gobuster sqlmap│   │ edit · redact · sign    │
│ nuclei  subfinder    │   └───────────────────────┘
│ john  hydra  yara    │
│ theHarvester recon-ng│
│ exploitdb  trivy     │
└──────────────────────┘
```

The Odysseus core image is **not modified**. All sidecars are managed via `docker-compose.security.yml` and attach to the same internal network.

---

## MCP Tools

### `recon_server` — Network Reconnaissance

| Tool | Description |
|------|-------------|
| `nmap_scan` | Port and service version scan (nmap) |
| `masscan_scan` | High-speed TCP port discovery (masscan) |

### `intel_server` — Threat Intelligence

| Tool | Description |
|------|-------------|
| `shodan_host` | Open ports, banners, and CVEs from Shodan |
| `virustotal_lookup` | Hash, URL, domain, or IP reputation check |
| `cve_lookup` | NVD CVE search by ID or keyword |
| `otx_indicator` | AlienVault OTX threat intel lookup |

### `osint_server` — Passive OSINT

| Tool | Description |
|------|-------------|
| `harvester` | Email, subdomain, and employee harvest (theHarvester) |
| `username_search` | Cross-platform username enumeration (Sherlock) |
| `dns_enum` | DNS record enumeration (A, MX, NS, TXT, CNAME) |
| `whois_lookup` | WHOIS registration data |

### `web_vuln_server` — Web Assessment

| Tool | Description |
|------|-------------|
| `nikto_scan` | Web server misconfiguration and version scan |
| `gobuster_dir` | Directory and file brute-force |
| `sqlmap_scan` | SQL injection detection (non-destructive by default) |
| `nuclei_scan` | Template-based vulnerability scanning |

### `hashcrack_server` — Password / Hash

| Tool | Description |
|------|-------------|
| `identify_hash` | Hash type identification (hashid) |
| `john_crack` | Wordlist-based hash cracking (john) |

### `spiderfoot_server` — Correlated OSINT (SpiderFoot)

| Tool | Description |
|------|-------------|
| `sf_scan_start` | Start an async SpiderFoot scan, returns scan ID |
| `sf_scan_status` | Poll scan progress by ID |
| `sf_scan_results` | Retrieve structured results, optionally filtered by event type |
| `sf_quick_scan` | Blocking convenience: start → wait → return results |
| `sf_list_scans` | List all scans with status and result counts |
| `sf_module_list` | Browse available SpiderFoot modules |

SpiderFoot use cases: `passive` (no active probing), `investigate` (balanced), `footprint` (full surface mapping), `all`.

### `pdf_server` — PDF Intelligence and Report Assembly

| Tool | Description |
|------|-------------|
| `pdf_metadata` | Extract author, company, software, and timestamps — OSINT goldmine |
| `pdf_extract_text` | Pull text content from collected PDFs for keyword analysis |
| `pdf_info` | Page count, encryption status, embedded files — quick triage |
| `pdf_merge` | Assemble a final pentest report from per-tool output PDFs |
| `pdf_extract_pages` | Carve specific pages from a large document |
| `pdf_bentopdf_url` | Return the BentoPDF UI URL for interactive editing tasks |

Uses `pypdf` (already in `requirements.txt`) — no additional dependencies. For interactive work (redaction, compression, format conversion, signing), the agent hands users the BentoPDF URL at `http://localhost:3000`.

### `yara_server` — YARA Malware Detection

| Tool | Description |
|------|-------------|
| `yara_scan` | Scan a file or directory against stored YARA rules |
| `yara_rule_write` | Save a new YARA rule to the rules directory |
| `yara_list_rules` | List all available YARA rules |

Rules are stored under `/workspaces/yara_rules/` inside the Kali container.

### `exploit_server` — Exploit Database

| Tool | Description |
|------|-------------|
| `searchsploit` | Search Exploit-DB by keyword via searchsploit |
| `exploit_db_lookup` | Fetch exploit details by EDB ID |
| `cve_to_exploit` | Find all known exploits for a CVE identifier |

Uses the local `exploitdb` package installed in the Kali container — no network required.

### `transform_server` — Data Transformation

| Tool | Description |
|------|-------------|
| `encode` | Base64, hex, URL, or HTML encode |
| `decode` | Reverse of encode |
| `hash_data` | MD5, SHA1, SHA256, SHA512, bcrypt hash |
| `gzip_compress` | Compress data to base64-encoded gzip |
| `gzip_decompress` | Decompress base64-encoded gzip |
| `regex_extract` | Extract all regex matches from text |
| `jwt_decode` | Decode and inspect a JWT (no verification) |
| `xor` | XOR a string against a single-byte or multi-byte key |

All transforms run in-process — no toolchain call required.

### `asset_server` — Asset Inventory

| Tool | Description |
|------|-------------|
| `asset_add` | Register a host in the inventory |
| `asset_list` | List all tracked assets with metadata |
| `asset_get` | Retrieve a specific asset by IP |
| `service_add` | Record an open service on a tracked asset |
| `service_list` | List services for a given asset |
| `finding_add` | Log a security finding against an asset |
| `finding_list` | List findings, optionally filtered by asset or severity |

Backed by a WAL-mode SQLite database at `$ODYSSEUS_DATA_DIR/assets.db`.

### `attck_server` — MITRE ATT&CK

| Tool | Description |
|------|-------------|
| `attck_update` | Refresh the local ATT&CK STIX dataset (7-day TTL cache) |
| `attck_technique` | Look up a technique by ID (e.g., T1059.001) |
| `attck_tactic` | List all techniques under a tactic |
| `attck_search` | Free-text search across technique names and descriptions |
| `attck_map` | Map a list of technique IDs to their full details |

STIX data sourced from `github.com/mitre/cti`, cached locally.

### `risk_server` — CVSS Risk Scoring

| Tool | Description |
|------|-------------|
| `risk_score_finding` | Score a finding: CVSS base × criticality × exploitability |
| `asset_risk` | Aggregate risk score for a single asset |
| `risk_summary` | Full risk summary across all tracked assets |
| `remediation_plan` | Prioritized remediation list sorted by risk score |

Risk formula: `CVSS_base × criticality_multiplier × exploitability_factor`, capped at 30.0.

### `findings_server` — OpenSearch Findings Persistence

| Tool | Description |
|------|-------------|
| `finding_index` | Index a finding into OpenSearch |
| `finding_search` | Full-text search across all indexed findings |
| `finding_stats` | Count findings by severity and status |
| `finding_update_status` | Update the remediation status of a finding |

Index: `odysseus-findings` in the `opensearch` service (see `docker-compose.security.yml`).

---

## Skills

Pre-built agent workflows in [`skills/`](skills/):

**Reconnaissance & OSINT**

| Skill | Description |
|-------|-------------|
| [`recon/full_recon`](skills/recon/full_recon.yaml) | Port scan → web enum → vuln scan → report |
| [`osint/target_profile`](skills/osint/target_profile.yaml) | DNS + WHOIS + theHarvester + Shodan passive profile |
| [`osint/spiderfoot_deep_scan`](skills/osint/spiderfoot_deep_scan.yaml) | Full SpiderFoot correlated scan with CVE and breach extraction |
| [`osint/pdf_intel`](skills/osint/pdf_intel.yaml) | Metadata + text extraction from collected PDFs, with entity correlation |

**Web Assessment**

| Skill | Description |
|-------|-------------|
| [`web_assessment/web_full`](skills/web_assessment/web_full.yaml) | nikto + gobuster + sqlmap + nuclei chain |

**Incident Response**

| Skill | Description |
|-------|-------------|
| [`incident_response/ransomware_response`](skills/incident_response/ransomware_response.yaml) | Host triage → IOC extraction → ATT&CK mapping → remediation plan |
| [`incident_response/network_compromise`](skills/incident_response/network_compromise.yaml) | Entry point scan → C2 intel → lateral movement TTPs → report |
| [`incident_response/credential_breach`](skills/incident_response/credential_breach.yaml) | Attacker intel → exposed service scan → credential-focused TTPs |
| [`incident_response/ioc_triage`](skills/incident_response/ioc_triage.yaml) | Rapid IOC triage against threat intel |
| [`incident_response/threat_actor_profile`](skills/incident_response/threat_actor_profile.yaml) | Build a threat actor dossier from OSINT and ATT&CK data |

**Threat Hunting**

| Skill | Description |
|-------|-------------|
| [`threat_hunting/ioc_hunt`](skills/threat_hunting/ioc_hunt.yaml) | Hunt for IOCs across the asset inventory |
| [`threat_hunting/network_exposure_audit`](skills/threat_hunting/network_exposure_audit.yaml) | Identify unexpected network exposure on known assets |

**Malware Analysis**

| Skill | Description |
|-------|-------------|
| [`malware_analysis/file_triage`](skills/malware_analysis/file_triage.yaml) | Static file triage: hashes, strings, YARA, exiftool |

**Reporting**

| Skill | Description |
|-------|-------------|
| [`reporting/pentest_report`](skills/reporting/pentest_report.md) | PTES/OWASP-aligned Markdown report template |

---

## Configuration

Copy `.env.example` to `.env` and populate the security overlay section:

```bash
# Shared secret for the Kali toolchain exec API
EXEC_API_TOKEN=change_me_before_deploy   # openssl rand -hex 32

# Threat intelligence APIs
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
OTX_API_KEY=

# Censys (censys_server)
CENSYS_API_ID=
CENSYS_API_SECRET=

# OpenSearch (findings_server)
OPENSEARCH_URL=http://opensearch:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=admin
```

All Odysseus platform options (model endpoints, auth, HTTPS, RAG, GPU) are documented in the upstream [setup guide](docs/setup.md). See `.env.example` for the complete annotated reference.

---

## Repository Layout

```
odysseus-red/
├── mcp_servers/
│   ├── common.py                # Shared: exec_in_toolchain, mcp_error, validators
│   ├── recon_server.py          # nmap, masscan
│   ├── intel_server.py          # Shodan, VirusTotal, CVE/NVD, OTX
│   ├── osint_server.py          # theHarvester, Sherlock, DNS, WHOIS
│   ├── web_vuln_server.py       # nikto, gobuster, sqlmap, nuclei
│   ├── hashcrack_server.py      # hashid, john
│   ├── spiderfoot_server.py     # SpiderFoot REST API client
│   ├── pdf_server.py            # PDF intel + report assembly (pypdf)
│   ├── yara_server.py           # YARA scan, rule management
│   ├── exploit_server.py        # searchsploit, Exploit-DB lookup
│   ├── transform_server.py      # encode/decode, hash, JWT, XOR (in-process)
│   ├── asset_server.py          # SQLite asset + findings inventory
│   ├── attck_server.py          # MITRE ATT&CK STIX lookup
│   ├── risk_server.py           # CVSS scoring + remediation plans
│   └── findings_server.py       # OpenSearch findings persistence
├── skills/
│   ├── recon/full_recon.yaml
│   ├── osint/                   # target_profile, spiderfoot_deep_scan, pdf_intel
│   ├── web_assessment/web_full.yaml
│   ├── incident_response/       # ransomware_response, network_compromise,
│   │                            # credential_breach, ioc_triage, threat_actor_profile
│   ├── threat_hunting/          # ioc_hunt, network_exposure_audit
│   ├── malware_analysis/        # file_triage
│   └── reporting/pentest_report.md
├── modules/
│   ├── engagement_manager/      # in development
│   ├── finding_tracker/         # in development
│   └── report_builder/          # in development
├── docker/
│   └── toolchain/
│       ├── Dockerfile           # Kali Rolling sidecar image
│       └── exec_api.py          # HTTP exec API (Bearer auth + structured logging)
├── docker-compose.security.yml  # Compose overlay: toolchain + SpiderFoot + OpenSearch + BentoPDF
├── docs/
│   ├── adr/                     # Architecture decision records (ADR 001–004)
│   ├── develop-mcp-servers.md   # Guide for adding new MCP servers
│   └── reverse-proxy.md         # HTTPS + Caddy/nginx/Traefik examples
└── tests/
    └── mcp_servers/             # Unit tests (all outbound HTTP/subprocess mocked)
```

Everything under `mcp_servers/`, `skills/`, `modules/`, `docker/toolchain/`, and `docs/adr/` is specific to this fork. All other files are upstream Odysseus — kept unmodified to simplify future upstream merges.

---

## Upstream Sync

This fork tracks [`pewdiepie-archdaemon/odysseus`](https://github.com/pewdiepie-archdaemon/odysseus) `dev` branch via the `upstream` remote. Sync weekly:

```bash
git fetch upstream
git checkout dev
git merge upstream/dev --no-ff -m "chore: sync upstream dev $(date +%Y-%m-%d)"
git push origin dev
```

The CI `upstream-drift` job warns if the fork falls more than 50 commits behind.

---

## Development

```bash
# Install dev dependencies (inside a distrobox/venv on immutable hosts)
pip install -r requirements.txt pytest pytest-asyncio bandit ruff black pre-commit

# Run MCP server unit tests
pytest tests/mcp_servers/ -v

# Security lint (our additions only)
bandit -r mcp_servers/ modules/ -ll

# Install pre-commit hooks
pre-commit install
```

See [`docs/develop-mcp-servers.md`](docs/develop-mcp-servers.md) for the guide to adding new MCP servers.

CI runs on every push to `dev` and `main` via [`.github/workflows/ci-security.yml`](.github/workflows/ci-security.yml) (bandit, pip-audit, unit tests, Dockerfile build, Trivy scan, upstream-drift check).

---

## Security

Active tools in this repo can cause significant impact on target systems. Before using any active tool:

1. Confirm you hold written authorization for the target.
2. Understand the rules of engagement.
3. Use `passive` SpiderFoot use case for external targets unless active probing is explicitly authorized.

Keep Odysseus auth enabled. Do not expose the SpiderFoot port (5001) or toolchain container ports to the public internet — both are internal-network only by default. BentoPDF is bound to `127.0.0.1:3000` and processes all files client-side — no document content passes through the container.

For Odysseus platform security notes see the upstream [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

---

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE) and [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).

SpiderFoot ([`smicallef/spiderfoot`](https://github.com/smicallef/spiderfoot)) is MIT licensed.

BentoPDF ([`alam00000/bentopdf`](https://github.com/alam00000/bentopdf)) is AGPL-3.0 licensed.
