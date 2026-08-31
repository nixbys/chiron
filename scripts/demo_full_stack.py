#!/usr/bin/env python3
"""demo_full_stack.py — one guided tour through every service Chiron adds
on top of upstream Odysseus: all 22 security MCP servers, and (through
them) every sidecar -- the Kali toolchain, SpiderFoot, OpenSearch,
BentoPDF, and CyberChef.

Speaks the real MCP stdio protocol directly to each server (spawn ->
initialize -> call_tool), the same mechanism scripts/mcp_health_check.py
already uses to verify registration -- except this script actually calls
representative tools instead of only listing them, so it exercises the
real toolchain sidecar, the real OpenSearch index, the real SpiderFoot
API, and so on. It bypasses the chat/LLM layer entirely (deterministic
and scriptable, doesn't depend on a model's tool-calling judgment) and
also bypasses the app's own MCP-server registration table (like
mcp_health_check.py, it talks to each server script directly) -- so this
demonstrates that the *tools themselves* work end to end, independent of
whether they happen to be registered in Settings on this instance.

Run this INSIDE the odysseus app container (or anywhere its exact
environment is replicated) so the spawned servers inherit the same env
vars the real app gives them -- ODYSSEUS_TOOLCHAIN_API/EXEC_API_TOKEN,
OPENSEARCH_URL, SPIDERFOOT_URL, BENTOPDF_URL, SHODAN_API_KEY, etc.:

    podman exec -it chiron_odysseus_1 python3 scripts/demo_full_stack.py

or, from a native (non-container) install with docker-compose.security.yml's
sidecars already reachable at their .env-configured URLs:

    python3 scripts/demo_full_stack.py

Every target used is either this stack's own self-hosted sidecar (CyberChef),
a domain/IP explicitly set aside for this exact purpose (scanme.nmap.org --
Nmap's own public, always-authorized scan target; example.com -- IANA's
reserved documentation domain; 8.8.8.8 -- Google Public DNS, queried only
via passive threat-intel database lookups, never actively scanned), or a
small, well-known open-source repo (gitleaks' own, which ships intentional
test-fixture secrets in its own test suite) -- see AUTHORIZED SCOPE below
for the full list and the reasoning behind each one. Nothing here targets
a third party without a standing, public invitation to be tested.

Everything runs inside one Engagement ("Project") so its whole trail --
every finding, every audit row, every timeline event -- is visible
together afterward in the Security Hub, filtered to this engagement, and
in the one-call PDF report this script generates as its own last step.

Non-destructive and safe to re-run: it creates a *new* engagement each
run (timestamped name) rather than reusing one, and every write it makes
(findings, watchlist entries, YARA/Sigma rules) is either idempotent or
harmless to have more than one of.
"""

import asyncio
import datetime
import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# ── Authorized scope for this demo run ───────────────────────────────────
#
# Passed to engagement_create as the engagement's own declared scope, so
# every scope-enforced tool call below is also a live demonstration of
# Phase A's check_scope() actually running (not just this script's own
# target choices) -- calling any of these tools against something *not*
# in this list would be blocked, override-required, and audit-logged.
SCANME = "scanme.nmap.org"          # Nmap's own standing public test target
EXAMPLE = "example.com"             # IANA-reserved documentation domain
GOOGLE_DNS = "8.8.8.8"              # public infra, only ever queried passively (Shodan/Censys-style lookups, never scanned)
CYBERCHEF_HOST = "odysseus-cyberchef"  # this stack's own sidecar -- self-hosted, zero third-party exposure
GITLEAKS_REPO = "https://github.com/gitleaks/gitleaks.git"  # small, public, ships intentional test secrets
GITHUB_HOST = "github.com"          # GITLEAKS_REPO's own host -- must be in scope for secrets_scan to pass check_scope()

_CREATED_ID_RE = re.compile(r"\(id=([0-9a-f]+)\)")


def _now_tag() -> str:
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


# ── MCP plumbing ──────────────────────────────────────────────────────────

async def call(server: str, tool: str, args: dict | None = None, timeout: float = 180.0) -> str:
    """Spawn one MCP server, call one tool, return its text result. Fresh
    connection per call (like mcp_health_check.py's check_server) -- a
    server spawn is cheap, and this keeps every call independently
    debuggable instead of threading shared session state through the
    whole script."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    script = REPO_ROOT / "mcp_servers" / f"{server}.py"
    # env=None does NOT mean "inherit the parent environment" -- mcp's
    # stdio_client treats it as "use only get_default_environment()", a
    # hardcoded allowlist (HOME/LOGNAME/PATH/SHELL/TERM/USER) that excludes
    # every secret/URL these servers actually need (EXEC_API_TOKEN,
    # SHODAN_API_KEY, OPENSEARCH_URL, SPIDERFOOT_URL, BENTOPDF_URL, ...).
    # Pass the real environment explicitly so spawned servers see it.
    params = StdioServerParameters(command=sys.executable, args=[str(script)], env=dict(os.environ))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=timeout)
            result = await asyncio.wait_for(
                session.call_tool(tool, args or {}), timeout=timeout
            )
            parts = [c.text for c in result.content if hasattr(c, "text")]
            return "\n".join(parts)


def _snippet(text: str, n: int = 320) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else text[:n].rstrip() + f"… [{len(text) - n} more chars]"


_STEP_N = 0


async def step(label: str, server: str, tool: str, args: dict | None = None, timeout: float = 180.0) -> str:
    global _STEP_N
    _STEP_N += 1
    print(f"\n[{_STEP_N:02d}] {label}")
    print(f"     {server}.{tool}({', '.join(f'{k}={v!r}' for k, v in (args or {}).items())})")
    try:
        text = await call(server, tool, args, timeout=timeout)
    except Exception as e:  # noqa: BLE001 -- a demo script surfaces every failure, never hides one
        print(f"     -> EXCEPTION: {type(e).__name__}: {e}")
        return ""
    flag = "  [error result]" if text.startswith("[error:") else ""
    print(f"     -> {_snippet(text)}{flag}")
    return text


async def main() -> None:
    print("=" * 78)
    print("Chiron full-stack demo — every fork MCP server, one Engagement")
    print("=" * 78)

    engagement_name = f"chiron-demo-{_now_tag()}"

    # ── 1. engagement_server — create the Project everything below is scoped to ──
    text = await step(
        "engagement_server: create this run's Project",
        "engagement_server", "engagement_create",
        {
            "name": engagement_name,
            "description": "Automated full-stack demo run (scripts/demo_full_stack.py)",
            "client": "Chiron Demo",
            "scope": [SCANME, EXAMPLE, GOOGLE_DNS, CYBERCHEF_HOST, GITHUB_HOST],
            "tags": ["demo", "full-stack"],
        },
    )
    m = _CREATED_ID_RE.search(text)
    if not m:
        print("\nCould not parse an engagement_id out of engagement_create's response -- stopping.")
        return
    eid = m.group(1)
    print(f"     engagement_id = {eid}")

    # ── 2. Red team: recon ──────────────────────────────────────────────
    await step(
        "recon_server: port/service scan against Nmap's own public test target",
        "recon_server", "nmap_scan",
        {"target": SCANME, "flags": "-sV -T4 --top-ports 20", "engagement_id": eid},
        timeout=120,
    )

    # ── 3. Red team: OSINT ──────────────────────────────────────────────
    await step(
        "osint_server: WHOIS lookup",
        "osint_server", "whois_lookup",
        {"target": EXAMPLE, "engagement_id": eid},
    )
    await step(
        "osint_server: DNS record enumeration",
        "osint_server", "dns_enum",
        {"domain": EXAMPLE, "record_types": "A MX NS TXT", "engagement_id": eid},
    )
    await step(
        "osint_server: secrets_scan -- gitleaks against a small public repo "
        "that ships intentional test-fixture secrets in its own test suite",
        "osint_server", "secrets_scan",
        {"repo_url": GITLEAKS_REPO, "engagement_id": eid},
        timeout=180,
    )

    # ── 4. Red team: threat intel (passive database lookups, never an active scan) ──
    await step(
        "intel_server: NVD CVE lookup (public API, no target)",
        "intel_server", "cve_lookup",
        {"query": "log4j", "limit": 3},
    )
    await step(
        "intel_server: Shodan host lookup -- reads Shodan's own pre-existing index, "
        "does not scan the target directly (needs SHODAN_API_KEY)",
        "intel_server", "shodan_host",
        {"ip": GOOGLE_DNS, "engagement_id": eid},
    )

    # ── 5. Red team: web assessment, against this stack's own CyberChef sidecar ──
    await step(
        "web_vuln_server: nikto against this stack's own CyberChef sidecar "
        "(self-hosted -- not a third party)",
        "web_vuln_server", "nikto_scan",
        {"url": f"http://{CYBERCHEF_HOST}:8000", "engagement_id": eid},
        timeout=180,
    )

    # ── 6. Red team: exploit intel + Metasploit module search (local DB, no target) ──
    await step(
        "exploit_server: searchsploit",
        "exploit_server", "searchsploit",
        {"query": "apache 2.4"},
    )
    await step(
        "msf_server: Metasploit module search (read-only)",
        "msf_server", "msf_search",
        {"query": "eternalblue"},
    )

    # ── 7. Red team: hash identification ─────────────────────────────────
    await step(
        "hashcrack_server: identify a hash's likely algorithm",
        "hashcrack_server", "identify_hash",
        {"hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
    )

    # ── 8. Red team: SpiderFoot correlated OSINT (passive mode) ──────────
    await step(
        "spiderfoot_server: quick passive OSINT correlation scan",
        "spiderfoot_server", "sf_quick_scan",
        {"target": EXAMPLE, "use_case": "passive"},
        timeout=180,
    )

    # ── 9. Blue team: YARA, scanning the repo secrets_scan just cloned ───
    await step(
        "yara_server: write a demo detection rule",
        "yara_server", "yara_rule_write",
        {
            "name": "demo_readme_marker",
            "content": (
                'rule demo_readme_marker\n{\n    strings:\n        $s = "gitleaks" nocase\n'
                "    condition:\n        $s\n}\n"
            ),
        },
    )
    await step(
        "yara_server: scan the gitleaks checkout secrets_scan just cloned "
        "(same /workspaces/secrets_scan_repo path) against that rule",
        "yara_server", "yara_scan",
        {"target": "secrets_scan_repo", "rule_file": "demo_readme_marker.yar", "engagement_id": eid},
        timeout=60,
    )

    # ── 10. Blue team: Sigma rule authoring (convert/test need optional pysigma) ──
    await step(
        "sigma_server: write a demo detection rule",
        "sigma_server", "sigma_rule_write",
        {
            "name": "demo_suspicious_login",
            "rule_yaml": (
                "title: Demo Suspicious Login\n"
                "logsource:\n  category: authentication\n"
                "detection:\n  selection:\n    EventID: 4625\n  condition: selection\n"
                "level: medium\n"
            ),
        },
    )
    await step("sigma_server: list stored rules", "sigma_server", "sigma_rule_list")

    # ── 11. Blue team: MITRE ATT&CK context ──────────────────────────────
    await step(
        "attck_server: technique detail for T1595 (Active Scanning) -- "
        "what this demo's own recon step above maps to",
        "attck_server", "attck_technique",
        {"technique_id": "T1595"},
    )

    # ── 12. Blue team: asset + findings inventory ────────────────────────
    await step(
        "asset_server: register a scanned asset",
        "asset_server", "asset_add",
        {"ip": GOOGLE_DNS, "hostname": "dns.google", "criticality": "low",
         "tags": ["demo"], "engagement_id": eid},
    )
    finding_text = await step(
        "findings_server: index a demo finding into OpenSearch",
        "findings_server", "finding_index",
        {
            "title": "Demo finding filed by demo_full_stack.py",
            "severity": "low",
            "tool": "demo_full_stack",
            "description": "Illustrative finding tying this run's activity together in one place.",
            "engagement": eid,
            "tags": ["demo"],
        },
    )

    # ── 13. Blue team: risk scoring + compliance mapping ─────────────────
    await step("risk_server: risk summary across all findings", "risk_server", "risk_summary", {"limit": 5})
    await step(
        "compliance_server: NIST 800-53 control search",
        "compliance_server", "nist_search",
        {"keyword": "access control", "limit": 3},
    )

    # ── 14. Blue team: continuous monitoring + IOC watchlist ─────────────
    await step("monitor_server: list any scheduled drift-check tasks", "monitor_server", "monitor_list_tasks")
    await step(
        "watchlist_server: add an IOC to the persistent watchlist",
        "watchlist_server", "watchlist_add",
        {"indicator": GOOGLE_DNS, "kind": "ip", "notes": "demo run", "engagement_id": eid},
    )

    # ── 15. Blue team: this host's own telemetry (Chiron's own container, not a scan) ──
    await step("host_telemetry_server: this container's own listening ports", "host_telemetry_server", "host_listening_ports")

    # ── 16. Utility: data transforms (pure computation, no target) ──────
    await step(
        "transform_server: hash a string with multiple algorithms",
        "transform_server", "hash_data",
        {"data": "Chiron full-stack demo", "algorithms": ["md5", "sha256"]},
    )

    # ── 17. Audit trail — everything above, tagged to this one engagement ──
    await step(
        "audit_server: every toolchain invocation this run made, filtered to this engagement",
        "audit_server", "audit_list",
        {"engagement_id": eid, "limit": 50},
    )
    await step("audit_server: summary stats for this run", "audit_server", "audit_stats", {"window_hours": 1})

    # ── 18. engagement_server — close the loop: log an event, view the timeline ──
    await step(
        "engagement_server: log a closing timeline event",
        "engagement_server", "engagement_log_event",
        {"engagement_id": eid, "event_type": "note", "summary": "demo_full_stack.py run complete"},
    )
    await step(
        "engagement_server: full timeline for this run",
        "engagement_server", "engagement_timeline",
        {"engagement_id": eid, "limit": 50},
    )

    # ── 19. pdf_server — capstone: one PDF pulling engagement + findings + timeline together ──
    report_text = await step(
        "pdf_server: generate a one-call engagement report PDF (via BentoPDF), "
        "folding this run's findings + timeline + a compliance summary into one document",
        "pdf_server", "generate_engagement_report",
        {"engagement_id": eid, "author": "demo_full_stack.py", "compliance_summary": "true"},
        timeout=60,
    )

    print("\n" + "=" * 78)
    print(f"Done. Engagement: {engagement_name}  (id={eid})")
    print("Review it in the Security Hub -> Engagements tab (expand it), and the")
    print("Audit Log tab filtered by this engagement_id, in the running app.")
    if "error" not in report_text.lower():
        print("Report path is in the pdf_server output above.")
    print("=" * 78)


if __name__ == "__main__":
    asyncio.run(main())
