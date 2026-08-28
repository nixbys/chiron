<!--
Orchestration (there's no cross-server call to do this in one tool — MCP
servers here are standalone, so an agent/skill run assembles the markdown
below by calling, in order):
  1. engagement_get(engagement_id)            -- engagement_server
  2. asset_list(engagement_id=...)             -- asset_server
  3. finding_list(engagement_id=...)           -- asset_server
     finding_search(engagement=engagement_id)  -- findings_server, if also used
  4. engagement_timeline(engagement_id=...)    -- engagement_server
  5. generate_report(title, content=<this rendered markdown>, ...) -- pdf_server
-->
# Engagement Report

**Engagement:** {{ engagement.name }}
**Client:** {{ engagement.client }}
**Status:** {{ engagement.status }}
**Scope:** {{ engagement.scope | join(", ") }}
**Out of Scope:** {{ engagement.out_of_scope | join(", ") }}

---

## Summary

{{ engagement.description }}

---

## Assets in Scope

| IP | Hostname | Criticality |
|----|----------|-------------|
{% for asset in assets %}
| {{ asset.ip }} | {{ asset.hostname }} | {{ asset.criticality }} |
{% endfor %}

---

## Findings

| ID | Title | Severity | Status | Tool |
|----|-------|----------|--------|------|
{% for finding in findings %}
| {{ finding.id }} | {{ finding.title }} | {{ finding.severity }} | {{ finding.status }} | {{ finding.tool }} |
{% endfor %}

---

## Engagement Timeline

{% for event in timeline %}
- **{{ event.ts }}** [{{ event.event_type }}] {{ event.summary }}
{% endfor %}
