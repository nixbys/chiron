#!/usr/bin/env python3
"""register_fork_mcp_servers.py

Register every fork-added security MCP server (mcp_servers/*.py this fork
owns, per scripts/mcp_health_check.py's FORK_SECURITY_SERVERS list -- the
same canonical list docs/develop-mcp-servers.md tells a contributor to
extend when adding a new one) with a running Chiron instance, via its own
admin API -- the exact POST /api/mcp/servers call Settings -> Integrations
-> MCP makes in the browser, just for all of them in one shot.

Odysseus has no static MCP config file by design (see
docs/develop-mcp-servers.md): servers are rows in the app's own database,
normally added one at a time through the UI. That's a deliberate choice,
not a bug -- but it also means a fresh install (or a fork update that adds
a new server) means clicking through Settings once per server, with no
built-in way to check what's still missing. This script exists to close
that gap without changing the underlying design: it reads the *current*
registrations back from GET /api/mcp/servers first and only POSTs the ones
missing, so it's always safe to re-run after a fork update.

Usage:
    python3 scripts/register_fork_mcp_servers.py \\
        --url http://localhost:7000 --username admin --password ...

    # Or read credentials from the environment (same names setup.py itself
    # reads, so a copy-paste from your own shell history usually just works):
    ODYSSEUS_ADMIN_USER=admin ODYSSEUS_ADMIN_PASSWORD=... \\
        python3 scripts/register_fork_mcp_servers.py

    # See what would change without touching anything:
    python3 scripts/register_fork_mcp_servers.py --dry-run
"""
import argparse
import os
import sys
from pathlib import Path

import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from scripts.mcp_health_check import FORK_SECURITY_SERVERS  # noqa: E402 -- see module docstring

# name -> display label shown in Settings -> Integrations -> MCP. Red/Blue
# mirrors this fork's own offense/defense split (docs/adr/
# 007-security-detection-lifecycle.md); "Utility" is the one server that's
# neither (transform_server: pure data transforms, no target, no findings).
# The first 7 match labels already used by hand-registered servers in the
# wild (checked against a real instance) so re-running this script against
# one doesn't produce a second, differently-labeled entry for the same tool.
LABELS: dict[str, str] = {
    "recon_server": "Red: Recon (nmap/masscan)",
    "intel_server": "Red: Intel (Shodan/VT/CVE/OTX)",
    "osint_server": "Red: OSINT (theHarvester/DNS/WHOIS)",
    "web_vuln_server": "Red: Web Vuln (nikto/gobuster/sqlmap/nuclei)",
    "hashcrack_server": "Red: Hash Crack (john/hashid)",
    "spiderfoot_server": "Red: SpiderFoot (correlated OSINT)",
    "pdf_server": "Red: PDF Intel (metadata/merge/extract)",
    "exploit_server": "Red: Exploit DB (searchsploit)",
    "transform_server": "Utility: Transform (encode/decode/hash)",
    "yara_server": "Blue: YARA (malware detection)",
    "sigma_server": "Blue: Sigma (detection rules)",
    "asset_server": "Blue: Asset Inventory",
    "attck_server": "Blue: MITRE ATT&CK",
    "risk_server": "Blue: Risk Scoring (CVSS)",
    "findings_server": "Blue: Findings (OpenSearch)",
    "engagement_server": "Blue: Engagements",
    "monitor_server": "Blue: Scan Drift Monitor",
    "watchlist_server": "Blue: IOC Watchlist",
    "host_telemetry_server": "Blue: Host Telemetry",
    "compliance_server": "Blue: NIST Compliance",
    "audit_server": "Blue: Audit Log",
}


def _login(session: requests.Session, base_url: str, username: str, password: str) -> None:
    resp = session.post(f"{base_url}/api/auth/login", json={"username": username, "password": password}, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if data.get("requires_totp"):
        raise SystemExit("This account has 2FA enabled -- register servers with an account that doesn't, or add them by hand once.")
    if not data.get("ok"):
        raise SystemExit(f"Login failed: {data}")


def _existing_script_paths(session: requests.Session, base_url: str) -> set[str]:
    """Script paths (the /app/mcp_servers/<name>.py this fork's stdio
    servers are always launched with) already registered, so this script
    is idempotent regardless of what display name they were given."""
    resp = session.get(f"{base_url}/api/mcp/servers", timeout=15)
    resp.raise_for_status()
    paths = set()
    for srv in resp.json():
        args = srv.get("args") or []
        for a in args:
            if isinstance(a, str) and a.endswith(".py") and "/mcp_servers/" in a:
                paths.add(Path(a).name)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=os.environ.get("CHIRON_URL", "http://localhost:7000"),
                         help="Base URL of the running instance (default: http://localhost:7000)")
    parser.add_argument("--username", default=os.environ.get("ODYSSEUS_ADMIN_USER", "admin"))
    parser.add_argument("--password", default=os.environ.get("ODYSSEUS_ADMIN_PASSWORD"))
    parser.add_argument("--container-prefix", default="/app",
                         help="Path the app process itself sees mcp_servers/ under (default: /app, the container image's WORKDIR)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be registered without making changes")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    servers = [(name, LABELS.get(name, name)) for name in FORK_SECURITY_SERVERS]

    if args.dry_run:
        print(f"Would check {base_url} and register any of these {len(servers)} not already present:")
        for name, label in servers:
            print(f"  {label:<48} -> {args.container_prefix}/mcp_servers/{name}.py")
        return 0

    if not args.password:
        print("error: --password or ODYSSEUS_ADMIN_PASSWORD is required (or pass --dry-run)", file=sys.stderr)
        return 1

    session = requests.Session()
    _login(session, base_url, args.username, args.password)
    existing = _existing_script_paths(session, base_url)

    added, skipped, failed = [], [], []
    for name, label in servers:
        script_name = f"{name}.py"
        if script_name in existing:
            skipped.append(label)
            continue
        # Each registration makes the server spawn and initialize a new
        # stdio subprocess before responding -- reusing the same keep-alive
        # connection for the *next* registration right after can race with
        # that subprocess's own async cleanup and drop the connection with
        # no response (seen in practice: registering 21 servers back to
        # back on one persistent session). A fresh connection per request
        # sidesteps it entirely, at the cost of one extra TCP handshake per
        # server -- irrelevant next to the seconds a subprocess spawn costs.
        resp = session.post(
            f"{base_url}/api/mcp/servers",
            data={
                "name": label,
                "transport": "stdio",
                "command": "python3",
                "args": f'["{args.container_prefix}/mcp_servers/{name}.py"]',
                "env": "{}",
            },
            headers={"Connection": "close"},
            timeout=30,
        )
        if resp.ok:
            added.append(label)
        else:
            failed.append((label, resp.status_code, resp.text[:200]))

    print(f"Added {len(added)}, already present {len(skipped)}, failed {len(failed)}.")
    for label in added:
        print(f"  + {label}")
    for label, status, body in failed:
        print(f"  ! {label}: HTTP {status} {body}", file=sys.stderr)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
