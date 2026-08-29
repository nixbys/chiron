# ADR 007: The Security Detection Lifecycle — One Pipeline, Not Parallel Systems

**Status:** Accepted
**Date:** 2026-08-28

## Context

Odysseus Red grew from a one-shot offensive toolbox (v0.1–v0.4: run a scan, get a report) into something that keeps working while nobody's watching (v0.5: engagements, continuous scanning, a persistent IOC watchlist, Sigma detection rules) and then, in the work this ADR documents, into a genuinely red-*and*-blue platform: scheduled Sigma/YARA sweeps, defensive host telemetry, a remediation-verification loop, multi-target recon, a NIST 800-53 compliance mapping server, one-call engagement reporting, and a security dashboard aggregating all of it.

That's eight separate additions built across one continuous session. Nothing about that count makes them a coherent system by itself — eight capabilities each wired into their own storage, their own notification path, and their own status vocabulary would just be eight small toolboxes sitting next to each other, no more integrated than the pre-v0.5 one-shot tools were. What actually makes this a platform instead of a pile of features is a design rule that was enforced at every checkpoint while building them, not decided after the fact: **every new capability that detects something writes into the same shared plumbing every other capability already uses.** This ADR writes that rule down explicitly, and traces the concrete pipeline it produces.

## The Pipeline

```
Recon (red)                     nmap/masscan/subdomain_enum/tls_cert_info/web_vuln/
                                 exploit/hashcrack/SpiderFoot OSINT — offense-side tools
                                 that produce raw signal about a target.
     │
     ▼
Asset / Finding inventory       asset_server (SQLite asset inventory) +
("the riverbed")                findings_server (OpenSearch `odysseus-findings` index)
                                 — the one shared sink. Every tool above, every
                                 detector below, and every scheduled action writes
                                 findings here. There is no second findings store.
     │
     ▼
Grouped by Engagement           engagement_server — `engagement_id` is a convention
                                 key threaded through asset/finding records and every
                                 scheduled action's config (not a foreign key: there's
                                 no shared database between MCP servers by design, see
                                 each server's own file for why). One case, one
                                 timeline, everything that happened during it visible
                                 in one place (`engagement_timeline`).
     │
     ▼
Detection & Intel (blue)        yara_server + sigma_server (pattern/log detection),
                                 watchlist_server (persistent IOC re-checking),
                                 intel_server (Shodan/VirusTotal/OTX/Censys),
                                 attck_server (MITRE ATT&CK technique context),
                                 host_telemetry_server (processes/ports/users/cron/
                                 packages on Odysseus's own host — defensive, not
                                 offensive; see that module's own container-boundary
                                 caveat). All of these file into the same findings
                                 store as recon does — a Sigma match and an open port
                                 are the same kind of record, just from a different
                                 `tool` field.
     │
     ▼
Risk & Compliance (blue)        risk_server (CVSS × criticality × exploitability
                                 scoring, remediation-plan generation) and
                                 compliance_server (NIST 800-53 Rev 5 lookup +
                                 nist_map's ATT&CK-tactic/finding-tag → control-family
                                 heuristic — a rough compliance-summary grouping, not
                                 authoritative NIST guidance).
     │
     ▼
Continuously re-verified        monitor_server (one snapshot/diff store, shared by
                                 every scheduled check) backs action_scheduled_recon
                                 (now multi-target), action_watchlist_check,
                                 action_sigma_sweep, action_yara_sweep, and
                                 action_host_monitor — all drift-only-alerting: a
                                 finding is filed only when something *changed* since
                                 last run, never on every run. action_verify_remediation
                                 closes the loop the other five don't: it re-checks a
                                 finding already marked "remediated" to confirm the
                                 issue is actually still gone, reopening it if not.
     │
     ▼
Notifications + Dashboard       Every drift-detecting action reuses the *existing*
                                 reminder-channel system (`dispatch_reminder`) and
                                 fires the same `security_finding_added` event — no
                                 new notification channel was built for any of this.
                                 The security dashboard (`GET /api/security/dashboard`)
                                 reads the same five stores above directly (findings,
                                 watchlist, monitor, engagements, host telemetry) for
                                 one aggregated, admin-gated snapshot.
     │
     ▼
Reporting                       pdf_server's generate_report (existing) and
                                 generate_engagement_report (new) render the same
                                 engagement/findings/timeline data into one PDF,
                                 optionally folding in a compliance_summary string
                                 computed from compliance_server's nist_map.
```

## Design Principle

**No new capability gets its own parallel storage, status vocabulary, or notification path.** Concretely, enforced at every checkpoint building the above:

- A new detector files findings into `findings_server`'s existing OpenSearch index with the existing `severity`/`status`/`tags` vocabulary — it does not invent a new store or a new status enum. (`finding_update_status`'s enum stayed `open`/`remediated`/`accepted`/`false_positive` through this entire body of work, including the remediation-verification loop that reopens findings — no `verified` status was added.)
- A new scheduled check reuses `monitor_server`'s snapshot/diff mechanism for "did this change since last run" — it does not build its own diff store. The shared `_file_drift_finding()` helper (extracted once four call sites had converged on byte-for-byte the same file-a-finding-and-log-an-engagement-event block) is the concrete artifact of this: one code path, five callers.
- A new alert reuses `dispatch_reminder` and `security_finding_added` — it does not add a new notification transport.
- A new report or dashboard reads the same underlying stores — it does not maintain its own denormalized copy of engagement/finding state.
- Where duplicating a small amount of code was still the right call — `sigma_server`/`pdf_server` each carry their own minimal OpenSearch/SQLite read helpers rather than importing `findings_server`/`engagement_server` directly — the reason is a *harder* constraint, not a relaxation of this one: MCP servers in this fork are standalone subprocesses and never import each other. `routes/` files (like the security dashboard) are not under that restriction and do import `mcp_servers` modules directly for exactly this reason.

This is what "hand-in-hand, natural flow, a river down a mountain" means concretely, in the data plumbing rather than as prose: tributaries (recon, detection, intel) feed one riverbed (asset/finding inventory), grouped into one watershed (engagement), continuously monitored for change, surfaced through one set of banks (notifications, dashboard), and eventually documented downstream (reporting) — not eight separate streams that happen to run in the same repository.

## Consequences

**Positive:**
- A user working the security dashboard, an engagement PDF, or a reminder notification sees the same vocabulary and the same underlying records regardless of which of the eight (now many more) detection surfaces produced them.
- Adding a ninth detection surface in the future has a clear contract to follow: file into `findings_server`, log to `engagement_server` if scoped to a case, diff via `monitor_server` if it's a scheduled recheck, notify via `dispatch_reminder` + `security_finding_added`. The `_file_drift_finding()` helper and this ADR are both discoverable answers to "how do I wire in a new one of these."
- No proliferation of near-duplicate SQLite databases or OpenSearch indices to keep in sync with each other.

**Negative:**
- The shared stores' schemas (findings' status enum, `engagement_id` as a loose convention key rather than an enforced foreign key, `monitor_server`'s `(task_id, target, check_type)` snapshot key) constrain what a future detector can express without a schema change touching shared infrastructure. This is treated as acceptable friction — the alternative (each detector free to define its own status/grouping vocabulary) is exactly the fragmentation this ADR exists to prevent.
- `host_telemetry_server`'s container-boundary limitation (documented in its own module docstring and in README) means "continuously re-verified" host state is scoped to Odysseus's own container, not a true arbitrary host, until host-namespace passthrough is built — a real, currently-unsolved gap in the "Detection & Intel" stage's host-side coverage, not something this ADR's plumbing model itself fixes.
