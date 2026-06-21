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

---

## What This Is

Odysseus Red layers a complete cybersecurity toolchain on top of the [Odysseus](https://github.com/pewdiepie-archdaemon/odysseus) self-hosted AI workspace. The base platform provides chat, agents, memory, deep research, documents, and MCP — this fork adds:

- **6 cybersecurity MCP servers** wired to a Kali-based sidecar and SpiderFoot OSINT platform
- **Pre-built agent skill workflows** for reconnaissance, OSINT, web assessment, and reporting
- **SpiderFoot** (200+ correlated OSINT modules) running as a persistent REST API sidecar
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
┌─────────────────────────────────────────────────────┐
│                  Odysseus Red (port 7000)            │
│         Chat · Agents · Research · Documents         │
│              MCP client built-in                     │
└──────────┬──────────────┬───────────────────────────┘
           │ MCP stdio    │ MCP stdio
           ▼              ▼
┌──────────────────┐  ┌──────────────────────────────┐
│  mcp_servers/    │  │  mcp_servers/                │
│  recon_server    │  │  spiderfoot_server           │
│  osint_server    │  │  (REST client)               │
│  web_vuln_server │  └──────────────┬───────────────┘
│  intel_server    │                 │ HTTP :5001
│  hashcrack_server│  ┌──────────────▼───────────────┐
└──────────┬───────┘  │  odysseus-spiderfoot          │
           │ podman   │  smicallef/spiderfoot:latest  │
           │ exec     │  200+ OSINT modules           │
           ▼          │  REST API on internal network │
┌──────────────────┐  └──────────────────────────────┘
│  odysseus-       │
│  toolchain       │
│  (Kali Rolling)  │
│  nmap · masscan  │
│  nikto · gobuster│
│  sqlmap · nuclei │
│  theHarvester    │
│  john · hydra    │
└──────────────────┘
```

The Odysseus core image is **not modified**. Both sidecars are managed via `docker-compose.security.yml` and attach to the same internal network.

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

---

## Skills

Pre-built agent workflows in [`skills/`](skills/):

| Skill | Description |
|-------|-------------|
| [`recon/full_recon`](skills/recon/full_recon.yaml) | Port scan → web enum → vuln scan → report |
| [`osint/target_profile`](skills/osint/target_profile.yaml) | DNS + WHOIS + theHarvester + Shodan passive profile |
| [`osint/spiderfoot_deep_scan`](skills/osint/spiderfoot_deep_scan.yaml) | Full SpiderFoot correlated scan with CVE and breach extraction |
| [`web_assessment/web_full`](skills/web_assessment/web_full.yaml) | nikto + gobuster + sqlmap + nuclei chain |
| [`reporting/pentest_report`](skills/reporting/pentest_report.md) | PTES/OWASP-aligned Markdown report template |

---

## Configuration

Copy `.env.example` to `.env` and populate:

```bash
# --- Threat intelligence API keys (intel_server + SpiderFoot) ---
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
OTX_API_KEY=
NVD_API_KEY=              # optional — removes NVD rate limits

# --- SpiderFoot (if auth is enabled on the SpiderFoot container) ---
SPIDERFOOT_URL=http://odysseus-spiderfoot:5001
SPIDERFOOT_USERNAME=
SPIDERFOOT_PASSWORD=

# --- Container runtime (default: podman; set to docker on non-Fedora hosts) ---
ODYSSEUS_CONTAINER_RUNTIME=podman
ODYSSEUS_TOOLCHAIN_CONTAINER=odysseus-toolchain
```

All other Odysseus configuration options (model endpoints, auth, HTTPS, etc.) are documented in the upstream [setup guide](docs/setup.md).

---

## Repository Layout

```
odysseus-red/
├── mcp_servers/
│   ├── recon_server.py          # nmap, masscan
│   ├── intel_server.py          # Shodan, VirusTotal, CVE/NVD, OTX
│   ├── osint_server.py          # theHarvester, Sherlock, DNS, WHOIS
│   ├── web_vuln_server.py       # nikto, gobuster, sqlmap, nuclei
│   ├── hashcrack_server.py      # hashid, john
│   └── spiderfoot_server.py     # SpiderFoot REST API client
├── skills/
│   ├── recon/full_recon.yaml
│   ├── osint/{target_profile,spiderfoot_deep_scan}.yaml
│   ├── web_assessment/web_full.yaml
│   └── reporting/pentest_report.md
├── modules/
│   ├── engagement_manager/      # in development
│   ├── finding_tracker/         # in development
│   └── report_builder/          # in development
├── docker/
│   └── toolchain/Dockerfile     # Kali Rolling sidecar image
├── docker-compose.security.yml  # Compose overlay: toolchain + SpiderFoot
├── docs/adr/                    # Architecture decision records
│   ├── 001-toolchain-sidecar-isolation.md
│   ├── 002-podman-over-docker.md
│   └── 003-spiderfoot-integration.md
└── tests/
    └── mcp_servers/             # Unit tests (subprocess/HTTP fully mocked)
```

Everything under `mcp_servers/`, `skills/`, `modules/`, `docker/toolchain/`, and `docs/adr/` is specific to this fork. All other files are upstream Odysseus — kept unmodified to make merging upstream changes straightforward.

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

# Run security lint on our additions only
bandit -r mcp_servers/recon_server.py mcp_servers/intel_server.py \
          mcp_servers/osint_server.py mcp_servers/web_vuln_server.py \
          mcp_servers/hashcrack_server.py mcp_servers/spiderfoot_server.py \
          modules/ -ll

# Install pre-commit hooks
pre-commit install
```

CI runs on every push to `dev` and `main` via [`.github/workflows/ci-security.yml`](.github/workflows/ci-security.yml).

---

## Security

Active tools in this repo can cause significant impact on target systems. Before using any active tool:

1. Confirm you hold written authorization for the target.
2. Understand the rules of engagement.
3. Use `passive` SpiderFoot use case for external targets unless active probing is explicitly authorized.

Keep Odysseus auth enabled. Do not expose the SpiderFoot port (5001) or toolchain container ports to the public internet — both are internal-network only by default.

For Odysseus platform security notes see the upstream [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

---

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE) and [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).

SpiderFoot ([`smicallef/spiderfoot`](https://github.com/smicallef/spiderfoot)) is MIT licensed.
