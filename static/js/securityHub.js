/**
 * Security Hub — standalone page (static/security.html), not a modal.
 *
 * This is the full-page evolution of the old securityDashboard.js modal:
 * same tabs (Overview/Engagements/Watchlist/Rules), same `.sec-*`/
 * `.sec-hub-*` component primitives, same REST endpoints under
 * /api/security/ -- only the chrome changed (a real page instead of a
 * floating dialog), plus a new Connected Services tab linking out to the
 * sidecar services (BentoPDF, SpiderFoot, OpenSearch, Ollama, the Kali
 * toolchain) that previously had no path into the UI at all.
 *
 * Every write still goes through the same admin-gated REST endpoints that
 * call straight into the MCP server modules' own call_tool() -- see
 * routes/security_dashboard_routes.py's module docstring.
 */

const API_BASE = window.location.origin;

// Set by the chat SPA's sidebar Security Hub button (static/app.js) as
// ?session_id=... on navigation -- this is a real page load, not a SPA
// route, so a URL param is the only way this page can know which chat sent
// the user here. Absent (direct navigation, bookmark, /login-style access)
// = no "current chat" to offer linking.
const _CURRENT_SESSION_ID = new URLSearchParams(window.location.search).get('session_id') || '';

// Deep-link support for the chat header's "Project" badge (static/js/
// sessions.js) -- /security?tab=engagements&engagement_id=... lands
// directly on that engagement's expanded detail view instead of Overview.
const _DEEP_LINK_PARAMS = new URLSearchParams(window.location.search);
const _DEEP_LINK_TAB = _DEEP_LINK_PARAMS.get('tab') || '';
const _DEEP_LINK_ENGAGEMENT_ID = _DEEP_LINK_PARAMS.get('engagement_id') || '';

let _activeTab = 'overview';

// Per-tab cached state, so switching tabs doesn't lose an in-progress
// form or force a re-fetch every time.
const _state = {
  engagements: { list: null, expandedId: null, detail: null, formOpen: false, newProjectOpen: false },
  watchlist: { list: null, formOpen: false },
  rules: { sigma: null, yara: null, viewing: null, content: null },
  services: { list: null },
  audit: { invocations: null, stats: null, binary: '', outcome: '', engagementId: '' },
};

// ── Shared render helpers ──

function _escape(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

function _sectionCard(title, bodyHtml, headerExtraHtml) {
  return `
    <div style="border:1px solid var(--border);border-radius:var(--radius-md);padding:12px 14px;margin-bottom:12px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
        <div style="font-family:var(--font-family,'IBM Plex Mono',monospace);font-size:10.5px;text-transform:uppercase;letter-spacing:0.06em;color:var(--fg-muted);">${_escape(title)}</div>
        ${headerExtraHtml || ''}
      </div>
      ${bodyHtml}
    </div>`;
}

function _errorLine(msg) {
  return `<div style="color:var(--fg-muted);font-size:12px;">Unavailable: ${_escape(msg)}</div>`;
}

function _smallBtn(label, action, id, extraAttrs) {
  return `<button type="button" class="sec-hub-btn" data-action="${_escape(action)}" data-id="${_escape(id)}" ${extraAttrs || ''}>${_escape(label)}</button>`;
}

function _body() {
  return document.getElementById('hub-body');
}

// ── Overview tab ──

const _SEV_BADGE_CLASS = {
  critical: 'sec-badge-critical', high: 'sec-badge-high', medium: 'sec-badge-medium',
  low: 'sec-badge-low', info: 'sec-badge-info',
};

function _sevBadge(key, count) {
  const cls = _SEV_BADGE_CLASS[String(key).toLowerCase()];
  if (!cls) return `<span class="sec-badge" style="border-color:var(--border);color:var(--fg-muted);">${_escape(key)} ${count}</span>`;
  return `<span class="sec-badge ${cls}">${_escape(key)} ${count}</span>`;
}

function _statTile(label, value, deltaText, valueClass, deltaClass) {
  return `
    <div class="sec-stat-tile">
      <div class="sec-stat-tile-label">${_escape(label)}</div>
      <div class="sec-stat-tile-value${valueClass ? ' ' + valueClass : ''}">${_escape(value)}</div>
      ${deltaText ? `<div class="sec-stat-tile-delta${deltaClass ? ' ' + deltaClass : ''}">${_escape(deltaText)}</div>` : ''}
    </div>`;
}

function _renderStatRow(findings, watchlist, engagements) {
  const critical = (findings.by_severity || []).find(b => String(b.key).toLowerCase() === 'critical');
  return `
    <div class="sec-stat-grid" style="margin-bottom:16px;">
      ${_statTile('Open findings', findings.total ?? '—')}
      ${_statTile('Critical', critical ? critical.doc_count : 0, null, 'sec-crimson')}
      ${_statTile('Watchlist active', watchlist.count ?? '—', null, 'sec-blue')}
      ${_statTile('Engagements', (engagements.list || []).length)}
    </div>`;
}

function _renderFindings(section) {
  if (section.error) return _sectionCard('Findings', _errorLine(section.error));
  const sevs = (section.by_severity || []).map(b => _sevBadge(b.key, b.doc_count)).join(' ') || '<span style="color:var(--fg-muted);font-size:12px;">none</span>';
  const statuses = (section.by_status || []).map(b => `${_escape(b.key)}: ${b.doc_count}`).join('  &nbsp; ') || '(none)';
  const body = `
    <div style="font-size:12px;line-height:1.7;">
      <div style="margin-bottom:6px;">${sevs}</div>
      <div style="color:var(--fg-muted);">By status: ${statuses}</div>
    </div>`;
  return _sectionCard('Findings', body);
}

function _renderWatchlistSummary(section) {
  if (section.error) return _sectionCard('Watchlist', _errorLine(section.error));
  const rows = (section.entries || []).map(e =>
    `<div style="font-size:12px;padding:2px 0;">${_escape(e.kind)} &nbsp; <code style="font-family:var(--font-family,'IBM Plex Mono',monospace);">${_escape(e.indicator)}</code>${e.engagement_id ? ` &nbsp; <span style="color:var(--fg-muted);">(${_escape(e.engagement_id)})</span>` : ''}</div>`
  ).join('') || '<div style="font-size:12px;color:var(--fg-muted);">No active entries.</div>';
  return _sectionCard(`Watchlist (${section.count ?? 0} active)`, rows);
}

function _renderScanDrift(section) {
  if (section.error) return _sectionCard('Recent Scan Drift', _errorLine(section.error));
  const diffs = section.diffs || [];
  if (!diffs.length) return _sectionCard('Recent Scan Drift', '<div style="font-size:12px;color:var(--fg-muted);">No drift recorded yet.</div>');
  const rows = diffs.map(d => {
    const when = d.ts ? new Date(d.ts * 1000).toLocaleString() : '';
    const addedN = (d.added || []).length, removedN = (d.removed || []).length;
    const dotClass = addedN > 0 ? 'sec-blue' : (removedN > 0 ? 'sec-crimson' : 'sec-muted');
    return `
      <div class="sec-tl-row">
        <span class="sec-tl-time">${_escape(when)}</span>
        <span class="sec-tl-dot ${dotClass}"></span>
        <span class="sec-tl-text">[${_escape(d.check_type)}] <span class="sec-tl-target">${_escape(d.target)}</span> &nbsp; +${addedN} -${removedN}</span>
        <span class="sec-tl-tag">${_escape(d.task_id || '')}</span>
      </div>`;
  }).join('');
  return _sectionCard('Recent Scan Drift', `<div class="sec-timeline">${rows}</div>`);
}

function _renderEngagementsSummary(section) {
  if (section.error) return _sectionCard('Engagements', _errorLine(section.error));
  const rows = (section.list || []).map(e =>
    `<div style="font-size:12px;padding:2px 0;">${_escape(e.name)} &nbsp; <span style="color:var(--fg-muted);">${_escape(e.client || '')} &middot; ${_escape(e.status)}</span></div>`
  ).join('') || '<div style="font-size:12px;color:var(--fg-muted);">No engagements yet.</div>';
  return _sectionCard('Engagements', rows);
}

function _renderHostTelemetry(section) {
  if (section.error) return _sectionCard('Host Telemetry', _errorLine(section.error));
  const body = `
    <div style="font-size:12px;line-height:1.7;">
      <div>Processes: <strong>${section.process_count ?? '?'}</strong></div>
      <div>Listening ports: <strong>${section.listening_port_count ?? '?'}</strong></div>
      <div>Logged-in users: <strong>${section.logged_in_user_count ?? '?'}</strong></div>
    </div>`;
  return _sectionCard('Host Telemetry', body);
}

function _renderOverview(data) {
  const el = _body();
  if (!el) return;
  const findings = data.findings || {};
  const watchlist = data.watchlist || {};
  const engagements = data.engagements || {};
  el.innerHTML = [
    !findings.error && !watchlist.error && !engagements.error ? _renderStatRow(findings, watchlist, engagements) : '',
    _renderFindings(findings),
    _renderWatchlistSummary(watchlist),
    _renderScanDrift(data.scan_drift || {}),
    _renderEngagementsSummary(engagements),
    _renderHostTelemetry(data.host_telemetry || {}),
  ].join('');
}

async function _loadOverview() {
  const el = _body();
  if (!el) return;
  el.innerHTML = '<div style="font-size:12px;opacity:0.7;padding:8px 0;">Loading…</div>';
  try {
    const res = await fetch(`${API_BASE}/api/security/dashboard`, { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    _renderOverview(await res.json());
  } catch (err) {
    el.innerHTML = `<div style="font-size:12px;opacity:0.7;">Failed to load: ${_escape(err.message || String(err))}</div>`;
  }
}

// ── Engagements tab ──

const _STATUS_BADGE_CLASS = { active: 'sec-badge-low', paused: 'sec-badge-medium', closed: '' };

function _engagementRow(e) {
  const expanded = _state.engagements.expandedId === e.id;
  const badgeCls = _STATUS_BADGE_CLASS[e.status] || '';
  const statusBadge = badgeCls
    ? `<span class="sec-badge ${badgeCls}">${_escape(e.status)}</span>`
    : `<span class="sec-badge" style="border-color:var(--border);color:var(--fg-muted);">${_escape(e.status)}</span>`;
  let detailHtml = '';
  if (expanded && _state.engagements.detail) {
    const d = _state.engagements.detail;
    const scope = (d.engagement.scope || []).join(', ') || '(none)';
    const outOfScope = (d.engagement.out_of_scope || []).join(', ') || '(none)';
    const authorizedHours = d.engagement.authorized_hours || '(no restriction)';
    const blackoutDates = (d.engagement.blackout_dates || []).join(', ') || '(none)';
    const timeline = (d.timeline || []).map(ev => {
      const when = ev.ts ? new Date(ev.ts * 1000).toLocaleString() : '';
      return `<div class="sec-tl-row"><span class="sec-tl-time">${_escape(when)}</span><span class="sec-tl-dot sec-muted"></span><span class="sec-tl-text">[${_escape(ev.event_type)}] ${_escape(ev.summary)}</span></div>`;
    }).join('') || '<div style="font-size:12px;color:var(--fg-muted);padding:4px 0;">No events yet.</div>';
    detailHtml = `
      <div style="padding:10px 0 2px;font-size:12px;color:var(--fg-muted);">
        <div style="margin-bottom:6px;">${_escape(d.engagement.description || '(no description)')}</div>
        <div style="margin-bottom:6px;">Scope: ${_escape(scope)}</div>
        <div style="margin-bottom:10px;">Out of scope: ${_escape(outOfScope)}</div>
        <div style="margin-bottom:6px;">Authorized hours: ${_escape(authorizedHours)}</div>
        <div style="margin-bottom:10px;">Blackout dates: ${_escape(blackoutDates)}</div>
        <div style="margin-bottom:10px;">Id: <code style="font-family:var(--font-family,'IBM Plex Mono',monospace);">${_escape(e.id)}</code> <span style="opacity:0.75;">(paste into the Audit Log tab's engagement filter)</span></div>
        ${_CURRENT_SESSION_ID ? `<div style="margin-bottom:10px;">${_smallBtn('Link current chat to this engagement', 'link-current-chat', e.id)}</div>` : ''}
        <div class="sec-timeline">${timeline}</div>
      </div>`;
  } else if (expanded) {
    detailHtml = '<div style="font-size:12px;opacity:0.7;padding:8px 0;">Loading…</div>';
  }
  return `
    <div style="border-bottom:1px solid var(--border);padding:8px 0;">
      <div style="display:flex;align-items:center;gap:8px;cursor:pointer;" data-action="toggle-engagement" data-id="${_escape(e.id)}">
        <span style="flex:1;font-size:12.5px;">${_escape(e.name)}</span>
        <span style="font-size:11.5px;color:var(--fg-muted);">${_escape(e.client || '')}</span>
        ${statusBadge}
        ${e.status !== 'closed' ? _smallBtn('Close', 'close-engagement', e.id) : ''}
      </div>
      ${detailHtml}
    </div>`;
}

function _renderEngagementForm() {
  if (_state.engagements.newProjectOpen) {
    return `
      <form data-action="create-new-project" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px;align-items:center;">
        <input class="sec-hub-input" name="name" placeholder="name (required)" required style="flex:1;min-width:140px;">
        <input class="sec-hub-input" name="client" placeholder="client" style="flex:1;min-width:120px;">
        <input class="sec-hub-input" name="scope" placeholder="scope, comma-separated" style="flex:2;min-width:180px;">
        <input class="sec-hub-input" name="out_of_scope" placeholder="out of scope, comma-separated" style="flex:2;min-width:180px;">
        <input class="sec-hub-input" name="tags" placeholder="tags, comma-separated" style="flex:1;min-width:140px;">
        <input class="sec-hub-input" name="authorized_hours" placeholder="authorized hours, HH:MM-HH:MM" style="flex:1;min-width:180px;">
        <input class="sec-hub-input" name="blackout_dates" placeholder="blackout dates, YYYY-MM-DD comma-separated" style="flex:1;min-width:220px;">
        <label style="display:flex;align-items:center;gap:4px;font-size:12px;color:var(--fg-muted);white-space:nowrap;">
          <input type="checkbox" name="rag"> RAG
        </label>
        <button type="submit" class="sec-hub-btn sec-hub-btn-primary">Create Project + Open Chat</button>
        ${_smallBtn('Cancel', 'toggle-new-project-form', '')}
      </form>
      <div style="font-size:11px;color:var(--fg-muted);margin:0 0 8px;">
        Creates the engagement, then a new chat session already linked to it and scoped by it -- pick a model once the chat opens.
      </div>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
        <input type="file" id="roe-pdf-input" accept="application/pdf" style="font-size:12px;max-width:220px;">
        ${_smallBtn('Extract scope from RoE/SOW PDF', 'parse-roe-pdf', '')}
        <span id="roe-pdf-status" style="font-size:11px;color:var(--fg-muted);"></span>
      </div>`;
  }
  if (!_state.engagements.formOpen) {
    return `<div style="margin-bottom:10px;display:flex;gap:8px;flex-wrap:wrap;">
      ${_smallBtn('+ New Project (Engagement + Chat)', 'toggle-new-project-form', '')}
      ${_smallBtn('+ New Engagement', 'toggle-engagement-form', '')}
    </div>`;
  }
  return `
    <form data-action="create-engagement" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;align-items:center;">
      <input class="sec-hub-input" name="name" placeholder="name (required)" required style="flex:1;min-width:140px;">
      <input class="sec-hub-input" name="client" placeholder="client" style="flex:1;min-width:120px;">
      <input class="sec-hub-input" name="scope" placeholder="scope, comma-separated" style="flex:2;min-width:180px;">
      <input class="sec-hub-input" name="out_of_scope" placeholder="out of scope, comma-separated" style="flex:2;min-width:180px;">
      <input class="sec-hub-input" name="authorized_hours" placeholder="authorized hours, HH:MM-HH:MM" style="flex:1;min-width:180px;">
      <input class="sec-hub-input" name="blackout_dates" placeholder="blackout dates, YYYY-MM-DD comma-separated" style="flex:1;min-width:220px;">
      <button type="submit" class="sec-hub-btn sec-hub-btn-primary">Create</button>
      ${_smallBtn('Cancel', 'toggle-engagement-form', '')}
    </form>`;
}

function _renderEngagements() {
  const el = _body();
  if (!el) return;
  const list = _state.engagements.list;
  if (list == null) {
    el.innerHTML = '<div style="font-size:12px;opacity:0.7;padding:8px 0;">Loading…</div>';
    return;
  }
  const rows = list.length
    ? list.map(_engagementRow).join('')
    : '<div style="font-size:12px;color:var(--fg-muted);padding:8px 0;">No engagements yet.</div>';
  el.innerHTML = _renderEngagementForm() + rows;
}

async function _loadEngagements() {
  _renderEngagements();
  try {
    const res = await fetch(`${API_BASE}/api/security/engagements?limit=100`, { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _state.engagements.list = data.list || [];
  } catch (err) {
    _state.engagements.list = [];
    const el = _body();
    if (el) el.innerHTML = _errorLine(err.message || String(err));
    return;
  }
  // Deep link from the chat header's "Project" badge -- land straight on
  // that engagement's expanded detail, once, not on every reload of this tab.
  if (_DEEP_LINK_ENGAGEMENT_ID && _state.engagements.expandedId == null) {
    const target = _state.engagements.list.find(e => e.id === _DEEP_LINK_ENGAGEMENT_ID);
    if (target) {
      _state.engagements.expandedId = target.id;
      await _loadEngagementDetail(target.id);
      return;
    }
  }
  _renderEngagements();
}

async function _loadEngagementDetail(id) {
  _state.engagements.detail = null;
  _renderEngagements();
  try {
    const res = await fetch(`${API_BASE}/api/security/engagements/${encodeURIComponent(id)}`, { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    _state.engagements.detail = await res.json();
  } catch (err) {
    _state.engagements.detail = { engagement: {}, timeline: [], error: err.message || String(err) };
  }
  _renderEngagements();
}

// ── Watchlist tab ──

function _watchlistRow(e) {
  const isPaused = e.status === 'paused';
  return `
    <div style="display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border);padding:8px 0;font-size:12.5px;">
      <span style="width:60px;color:var(--fg-muted);">${_escape(e.kind)}</span>
      <code style="flex:1;font-family:var(--font-family,'IBM Plex Mono',monospace);">${_escape(e.indicator)}</code>
      ${e.engagement_id ? `<span style="color:var(--fg-muted);font-size:11px;">${_escape(e.engagement_id)}</span>` : ''}
      ${isPaused
        ? _smallBtn('Resume', 'resume-watchlist', e.id)
        : _smallBtn('Pause', 'pause-watchlist', e.id)}
      ${_smallBtn('Remove', 'remove-watchlist', e.id)}
    </div>`;
}

function _renderWatchlistForm() {
  if (!_state.watchlist.formOpen) {
    return `<div style="margin-bottom:10px;">${_smallBtn('+ Add Indicator', 'toggle-watchlist-form', '')}</div>`;
  }
  return `
    <form data-action="add-watchlist" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;align-items:center;">
      <input class="sec-hub-input" name="indicator" placeholder="indicator (required)" required style="flex:2;min-width:160px;">
      <select class="sec-hub-input" name="kind" style="flex:0 0 auto;">
        <option value="ip">ip</option>
        <option value="domain">domain</option>
        <option value="hash">hash</option>
        <option value="url">url</option>
      </select>
      <input class="sec-hub-input" name="notes" placeholder="notes" style="flex:1;min-width:120px;">
      <button type="submit" class="sec-hub-btn sec-hub-btn-primary">Add</button>
      ${_smallBtn('Cancel', 'toggle-watchlist-form', '')}
    </form>`;
}

function _renderWatchlistTab() {
  const el = _body();
  if (!el) return;
  const list = _state.watchlist.list;
  if (list == null) {
    el.innerHTML = '<div style="font-size:12px;opacity:0.7;padding:8px 0;">Loading…</div>';
    return;
  }
  const rows = list.length
    ? list.map(_watchlistRow).join('')
    : '<div style="font-size:12px;color:var(--fg-muted);padding:8px 0;">No active entries.</div>';
  el.innerHTML = _renderWatchlistForm() + rows;
}

async function _loadWatchlistTab() {
  _renderWatchlistTab();
  try {
    const res = await fetch(`${API_BASE}/api/security/watchlist`, { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _state.watchlist.list = data.list || [];
  } catch (err) {
    _state.watchlist.list = [];
    const el = _body();
    if (el) el.innerHTML = _errorLine(err.message || String(err));
    return;
  }
  _renderWatchlistTab();
}

// ── Rules tab (Sigma + YARA, browse/view) ──

function _ruleListColumn(title, kind, names, error) {
  const items = (names || []).map(name => {
    const isViewing = _state.rules.viewing && _state.rules.viewing.kind === kind && _state.rules.viewing.name === name;
    return `<div class="sec-rule-item${isViewing ? ' sec-rule-item-active' : ''}" data-action="view-rule" data-kind="${kind}" data-id="${_escape(name)}">${_escape(name)}</div>`;
  }).join('') || `<div style="font-size:12px;color:var(--fg-muted);padding:4px 0;">${error ? _escape(error) : 'No stored rules.'}</div>`;
  return `
    <div style="flex:1;min-width:0;">
      <div style="font-family:var(--font-family,'IBM Plex Mono',monospace);font-size:10.5px;text-transform:uppercase;letter-spacing:0.06em;color:var(--fg-muted);margin-bottom:8px;">${_escape(title)}</div>
      ${items}
    </div>`;
}

function _renderRulesTab() {
  const el = _body();
  if (!el) return;
  const { sigma, yara, viewing, content } = _state.rules;
  if (sigma == null || yara == null) {
    el.innerHTML = '<div style="font-size:12px;opacity:0.7;padding:8px 0;">Loading…</div>';
    return;
  }
  const viewerHtml = viewing
    ? `<div style="margin-top:14px;">
         <div style="font-family:var(--font-family,'IBM Plex Mono',monospace);font-size:10.5px;text-transform:uppercase;letter-spacing:0.06em;color:var(--fg-muted);margin-bottom:6px;">${_escape(viewing.kind)} / ${_escape(viewing.name)}</div>
         <pre style="background:var(--panel-alt);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px;font-size:11.5px;overflow-x:auto;max-height:400px;white-space:pre-wrap;word-break:break-word;">${_escape(content == null ? 'Loading…' : content)}</pre>
       </div>`
    : '';
  el.innerHTML = `
    <div style="display:flex;gap:20px;">
      ${_ruleListColumn('Sigma Rules', 'sigma', sigma.list, sigma.error)}
      ${_ruleListColumn('YARA Rules', 'yara', yara.list, yara.error)}
    </div>
    ${viewerHtml}`;
}

async function _loadRulesTab() {
  _renderRulesTab();
  const [sigmaRes, yaraRes] = await Promise.allSettled([
    fetch(`${API_BASE}/api/security/rules/sigma`, { credentials: 'same-origin' }),
    fetch(`${API_BASE}/api/security/rules/yara`, { credentials: 'same-origin' }),
  ]);
  _state.rules.sigma = await _toRuleListState(sigmaRes);
  _state.rules.yara = await _toRuleListState(yaraRes);
  _renderRulesTab();
}

async function _toRuleListState(settledRes) {
  if (settledRes.status !== 'fulfilled' || !settledRes.value.ok) {
    return { list: [], error: 'Failed to load.' };
  }
  try {
    return await settledRes.value.json();
  } catch {
    return { list: [], error: 'Failed to load.' };
  }
}

async function _loadRuleContent(kind, name) {
  _state.rules.viewing = { kind, name };
  _state.rules.content = null;
  _renderRulesTab();
  try {
    const res = await fetch(`${API_BASE}/api/security/rules/${kind}/${encodeURIComponent(name)}`, { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _state.rules.content = data.content;
  } catch (err) {
    _state.rules.content = `Failed to load: ${err.message || String(err)}`;
  }
  _renderRulesTab();
}

// ── Connected Services tab ──

function _serviceCard(svc) {
  const dotClass = svc.reachable ? 'sec-blue' : 'sec-crimson';
  const statusText = svc.reachable ? 'Reachable' : 'Unreachable';
  const openBtn = svc.browser_url
    ? `<a class="sec-hub-btn sec-hub-btn-primary" href="${_escape(svc.browser_url)}" target="_blank" rel="noopener noreferrer">Open &nearr;</a>`
    : `<span class="sec-badge" style="border-color:var(--border);color:var(--fg-muted);">internal only</span>`;
  return `
    <div style="border:1px solid var(--border);border-radius:var(--radius-md);padding:14px;display:flex;flex-direction:column;gap:8px;">
      <div style="display:flex;align-items:center;justify-content:space-between;">
        <div style="font-family:var(--font-display,'Chakra Petch',sans-serif);font-size:15px;font-weight:600;">${_escape(svc.label)}</div>
        <span class="sec-tl-dot ${dotClass}" title="${_escape(statusText)}" style="justify-self:auto;"></span>
      </div>
      <div style="font-size:12px;color:var(--fg-muted);line-height:1.5;flex:1;">${_escape(svc.description)}</div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
        <span style="font-size:11px;color:var(--fg-muted);font-family:var(--font-family,'IBM Plex Mono',monospace);">${_escape(statusText)}</span>
        ${openBtn}
      </div>
    </div>`;
}

function _renderServicesTab() {
  const el = _body();
  if (!el) return;
  const list = _state.services.list;
  if (list == null) {
    el.innerHTML = '<div style="font-size:12px;opacity:0.7;padding:8px 0;">Loading…</div>';
    return;
  }
  el.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;">
      ${list.map(_serviceCard).join('')}
    </div>`;
}

async function _loadServicesTab() {
  _renderServicesTab();
  try {
    const res = await fetch(`${API_BASE}/api/security/services`, { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _state.services.list = data.services || [];
  } catch (err) {
    _state.services.list = [];
    const el = _body();
    if (el) el.innerHTML = _errorLine(err.message || String(err));
    return;
  }
  _renderServicesTab();
}

// ── Audit Log tab ──

const _OUTCOME_BADGE_CLASS = {
  ok: 'sec-badge-low', error: 'sec-badge-high', timeout: 'sec-badge-medium', rate_limited: 'sec-badge-critical',
  // Scope-enforcement outcomes (mcp_servers/common.py's check_scope()): a
  // block is a hard stop, so it reads as critical/red same as rate_limited;
  // an override proceeded, but is still a flagged deviation worth eyes on,
  // so it reads as a warning/amber rather than the "fine" green of ok.
  blocked_out_of_scope: 'sec-badge-critical', scope_override: 'sec-badge-medium',
};

function _outcomeBadge(outcome) {
  const cls = _OUTCOME_BADGE_CLASS[outcome];
  if (!cls) return `<span class="sec-badge" style="border-color:var(--border);color:var(--fg-muted);">${_escape(outcome)}</span>`;
  return `<span class="sec-badge ${cls}">${_escape(outcome)}</span>`;
}

function _auditFilterForm() {
  const { binary, outcome, engagementId } = _state.audit;
  const outcomes = ['', 'ok', 'error', 'timeout', 'rate_limited', 'blocked_out_of_scope', 'scope_override'];
  return `
    <form data-action="filter-audit" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px;align-items:center;">
      <input class="sec-hub-input" name="binary" placeholder="binary, e.g. nmap" value="${_escape(binary)}" style="flex:1;min-width:140px;">
      <select class="sec-hub-input" name="outcome" style="flex:0 0 auto;">
        ${outcomes.map(o => `<option value="${o}" ${o === outcome ? 'selected' : ''}>${o || 'any outcome'}</option>`).join('')}
      </select>
      <input class="sec-hub-input" name="engagement_id" placeholder="engagement id" value="${_escape(engagementId)}" style="flex:1;min-width:140px;">
      <button type="submit" class="sec-hub-btn sec-hub-btn-primary">Filter</button>
    </form>`;
}

function _auditStatsRow(stats) {
  if (!stats || stats.total === 0) return '';
  const byOutcome = (stats.by_outcome || []).map(r => `${_outcomeBadge(r.outcome)} ${r.n}`).join(' &nbsp; ');
  const topBinaries = (stats.by_binary || []).slice(0, 5).map(r => `${_escape(r.binary)} (${r.n})`).join(', ') || '(none)';
  return `
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:14px;font-size:12px;color:var(--fg-muted);">
      <div><strong style="color:var(--fg);">${stats.total}</strong> invocations in the last 24h</div>
      <div>${byOutcome}</div>
      <div>Top binaries: ${topBinaries}</div>
    </div>`;
}

function _auditRow(inv) {
  const when = inv.ts ? new Date(inv.ts * 1000).toLocaleString() : '';
  const args = Array.isArray(inv.args) ? inv.args.join(' ') : String(inv.args ?? '');
  const dur = inv.duration_ms != null ? `${inv.duration_ms}ms` : '—';
  return `
    <div class="sec-tl-row" style="grid-template-columns:140px 90px 70px 150px 60px 110px 1fr;">
      <span class="sec-tl-time">${_escape(when)}</span>
      <span class="sec-tl-target">${_escape(inv.binary)}</span>
      <span style="color:var(--fg-muted);font-size:11px;">${_escape(inv.mode)}</span>
      <span>${_outcomeBadge(inv.outcome)}</span>
      <span style="color:var(--fg-muted);font-size:11px;font-variant-numeric:tabular-nums;">${dur}</span>
      <span style="color:var(--fg-muted);font-size:11px;">${_escape(inv.engagement_id || '—')}</span>
      <code style="font-family:var(--font-family,'IBM Plex Mono',monospace);font-size:11.5px;color:var(--fg-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${_escape(args)}</code>
    </div>`;
}

function _renderAuditTab() {
  const el = _body();
  if (!el) return;
  const { invocations, stats } = _state.audit;
  if (invocations == null) {
    el.innerHTML = _auditFilterForm() + '<div style="font-size:12px;opacity:0.7;padding:8px 0;">Loading…</div>';
    return;
  }
  const rows = invocations.length
    ? `<div class="sec-timeline">${invocations.map(_auditRow).join('')}</div>`
    : '<div style="font-size:12px;color:var(--fg-muted);padding:8px 0;">No invocations recorded yet -- this fills in as MCP tools run scans through the toolchain sidecar.</div>';
  el.innerHTML = _auditFilterForm() + _auditStatsRow(stats) + rows;
}

async function _loadAuditTab() {
  _renderAuditTab();
  const { binary, outcome, engagementId } = _state.audit;
  const params = new URLSearchParams({ limit: '100' });
  if (binary) params.set('binary', binary);
  if (outcome) params.set('outcome', outcome);
  if (engagementId) params.set('engagement_id', engagementId);
  try {
    const res = await fetch(`${API_BASE}/api/security/audit?${params}`, { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _state.audit.invocations = data.invocations || [];
    _state.audit.stats = data.stats || null;
  } catch (err) {
    _state.audit.invocations = [];
    const el = _body();
    if (el) el.innerHTML = _errorLine(err.message || String(err));
    return;
  }
  _renderAuditTab();
}

// ── Tab dispatch ──

function _loadActiveTab() {
  if (_activeTab === 'overview') return _loadOverview();
  if (_activeTab === 'engagements') return _loadEngagements();
  if (_activeTab === 'watchlist') return _loadWatchlistTab();
  if (_activeTab === 'rules') return _loadRulesTab();
  if (_activeTab === 'services') return _loadServicesTab();
  if (_activeTab === 'audit') return _loadAuditTab();
}

function _switchTab(tab) {
  _activeTab = tab;
  document.querySelectorAll('#hub-tabs [data-sec-tab]').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.secTab === tab);
  });
  _loadActiveTab();
}

// ── Event delegation for actions inside #hub-body ──

async function _onBodyClick(e) {
  const target = e.target.closest('[data-action]');
  if (!target) return;
  const action = target.dataset.action;
  const id = target.dataset.id;

  if (action === 'toggle-engagement-form') {
    _state.engagements.formOpen = !_state.engagements.formOpen;
    _renderEngagements();
  } else if (action === 'toggle-new-project-form') {
    _state.engagements.newProjectOpen = !_state.engagements.newProjectOpen;
    _renderEngagements();
  } else if (action === 'toggle-watchlist-form') {
    _state.watchlist.formOpen = !_state.watchlist.formOpen;
    _renderWatchlistTab();
  } else if (action === 'toggle-engagement') {
    if (_state.engagements.expandedId === id) {
      _state.engagements.expandedId = null;
      _state.engagements.detail = null;
      _renderEngagements();
    } else {
      _state.engagements.expandedId = id;
      await _loadEngagementDetail(id);
    }
  } else if (action === 'close-engagement') {
    if (!confirm('Close this engagement? This records an end date and stops treating it as active.')) return;
    await fetch(`${API_BASE}/api/security/engagements/${encodeURIComponent(id)}/close`, {
      method: 'POST', credentials: 'same-origin',
    });
    await _loadEngagements();
  } else if (action === 'pause-watchlist') {
    await fetch(`${API_BASE}/api/security/watchlist/${encodeURIComponent(id)}/pause`, {
      method: 'POST', credentials: 'same-origin',
    });
    await _loadWatchlistTab();
  } else if (action === 'resume-watchlist') {
    await fetch(`${API_BASE}/api/security/watchlist/${encodeURIComponent(id)}/resume`, {
      method: 'POST', credentials: 'same-origin',
    });
    await _loadWatchlistTab();
  } else if (action === 'remove-watchlist') {
    if (!confirm('Remove this watchlist entry permanently?')) return;
    await fetch(`${API_BASE}/api/security/watchlist/${encodeURIComponent(id)}`, {
      method: 'DELETE', credentials: 'same-origin',
    });
    await _loadWatchlistTab();
  } else if (action === 'view-rule') {
    await _loadRuleContent(target.dataset.kind, id);
  } else if (action === 'parse-roe-pdf') {
    const fileInput = document.getElementById('roe-pdf-input');
    const status = document.getElementById('roe-pdf-status');
    const file = fileInput && fileInput.files && fileInput.files[0];
    if (!file) {
      if (status) status.textContent = 'Choose a PDF first.';
      return;
    }
    if (status) status.textContent = 'Extracting…';
    target.disabled = true;
    try {
      const body = new FormData();
      body.append('file', file);
      const res = await fetch(`${API_BASE}/api/security/roe/parse-scope`, {
        method: 'POST', credentials: 'same-origin', body,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (status) status.textContent = `Failed: ${data.detail || res.status}`;
        return;
      }
      const candidates = data.candidates || [];
      const blackoutDates = data.blackout_dates || [];
      const authorizedHours = data.authorized_hours || '';
      if (!candidates.length && !blackoutDates.length && !authorizedHours) {
        if (status) status.textContent = 'No candidate scope/schedule found in the document.';
        return;
      }
      // Pre-fill, never auto-commit -- every field stays a plain editable
      // input the user reviews before Create is pressed.
      const form = '[data-action="create-new-project"]';
      const scopeInput = document.querySelector(`${form} [name="scope"]`);
      if (scopeInput && candidates.length) {
        const existing = scopeInput.value.split(',').map(s => s.trim()).filter(Boolean);
        scopeInput.value = Array.from(new Set([...existing, ...candidates])).join(', ');
      }
      const hoursInput = document.querySelector(`${form} [name="authorized_hours"]`);
      if (hoursInput && authorizedHours && !hoursInput.value.trim()) {
        hoursInput.value = authorizedHours;
      }
      const blackoutInput = document.querySelector(`${form} [name="blackout_dates"]`);
      if (blackoutInput && blackoutDates.length) {
        const existing = blackoutInput.value.split(',').map(s => s.trim()).filter(Boolean);
        blackoutInput.value = Array.from(new Set([...existing, ...blackoutDates])).join(', ');
      }
      const parts = [];
      if (candidates.length) parts.push(`${candidates.length} target${candidates.length === 1 ? '' : 's'}`);
      if (authorizedHours) parts.push('a testing window');
      if (blackoutDates.length) parts.push(`${blackoutDates.length} blackout date${blackoutDates.length === 1 ? '' : 's'}`);
      if (status) status.textContent = `Found ${parts.join(', ')} -- review before creating.`;
    } catch (err) {
      if (status) status.textContent = `Failed: ${err.message || String(err)}`;
    } finally {
      target.disabled = false;
    }
  } else if (action === 'link-current-chat') {
    if (!_CURRENT_SESSION_ID) return;
    const res = await fetch(`${API_BASE}/api/session/${encodeURIComponent(_CURRENT_SESSION_ID)}`, {
      method: 'PATCH', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ engagement_id: id }),
    });
    if (res.ok) {
      target.textContent = 'Linked ✓';
      target.disabled = true;
    }
  }
}

async function _onBodySubmit(e) {
  const form = e.target.closest('[data-action]');
  if (!form) return;
  e.preventDefault();
  const action = form.dataset.action;
  const fd = new FormData(form);

  if (action === 'create-engagement') {
    const name = String(fd.get('name') || '').trim();
    if (!name) return;
    const scope = String(fd.get('scope') || '').split(',').map(s => s.trim()).filter(Boolean);
    const outOfScope = String(fd.get('out_of_scope') || '').split(',').map(s => s.trim()).filter(Boolean);
    const blackoutDates = String(fd.get('blackout_dates') || '').split(',').map(s => s.trim()).filter(Boolean);
    const res = await fetch(`${API_BASE}/api/security/engagements`, {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name, client: String(fd.get('client') || ''), scope, out_of_scope: outOfScope,
        authorized_hours: String(fd.get('authorized_hours') || '').trim(), blackout_dates: blackoutDates,
      }),
    });
    if (res.ok) _state.engagements.formOpen = false;
    await _loadEngagements();
  } else if (action === 'create-new-project') {
    const name = String(fd.get('name') || '').trim();
    if (!name) return;
    const scope = String(fd.get('scope') || '').split(',').map(s => s.trim()).filter(Boolean);
    const outOfScope = String(fd.get('out_of_scope') || '').split(',').map(s => s.trim()).filter(Boolean);
    const tags = String(fd.get('tags') || '').split(',').map(s => s.trim()).filter(Boolean);
    const blackoutDates = String(fd.get('blackout_dates') || '').split(',').map(s => s.trim()).filter(Boolean);
    const engRes = await fetch(`${API_BASE}/api/security/engagements`, {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name, client: String(fd.get('client') || ''), scope, out_of_scope: outOfScope, tags,
        authorized_hours: String(fd.get('authorized_hours') || '').trim(), blackout_dates: blackoutDates,
      }),
    });
    if (!engRes.ok) {
      alert('Failed to create the engagement -- nothing else was created.');
      return;
    }
    const engData = await engRes.json();
    const engagementId = engData.engagement_id;
    _state.engagements.newProjectOpen = false;
    if (!engagementId) {
      // Created, but the id couldn't be parsed back out (see _CREATED_ID_RE
      // in routes/security_dashboard_routes.py) -- link a chat manually from
      // the engagement's own row instead of guessing at an id.
      alert('Project created, but no session was started automatically -- open it below and use "Link current chat" instead.');
      await _loadEngagements();
      return;
    }
    const sessRes = await fetch(`${API_BASE}/api/session`, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        name: `${name} — Project Chat`,
        skip_validation: 'true',
        rag: fd.get('rag') ? 'true' : 'false',
        engagement_id: engagementId,
      }),
    });
    if (!sessRes.ok) {
      alert('Project created, but starting its chat session failed -- open it below and use "Link current chat" instead.');
      await _loadEngagements();
      return;
    }
    const sess = await sessRes.json();
    // The chat SPA's own session-list boot reads window.location.hash to
    // restore/select a session on load (static/js/sessions.js) -- the same
    // deep-link convention already used for session-switch navigation.
    window.location.href = `/#${encodeURIComponent(sess.id)}`;
  } else if (action === 'add-watchlist') {
    const indicator = String(fd.get('indicator') || '').trim();
    if (!indicator) return;
    const res = await fetch(`${API_BASE}/api/security/watchlist`, {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator, kind: fd.get('kind'), notes: String(fd.get('notes') || '') }),
    });
    if (res.ok) _state.watchlist.formOpen = false;
    await _loadWatchlistTab();
  } else if (action === 'filter-audit') {
    _state.audit.binary = String(fd.get('binary') || '').trim();
    _state.audit.outcome = String(fd.get('outcome') || '');
    _state.audit.engagementId = String(fd.get('engagement_id') || '').trim();
    await _loadAuditTab();
  }
}

// ── Public API ──

export function initSecurityHub() {
  document.querySelectorAll('#hub-tabs [data-sec-tab]').forEach((btn) => {
    btn.addEventListener('click', () => _switchTab(btn.dataset.secTab));
  });
  const body = _body();
  if (body) {
    body.addEventListener('click', _onBodyClick);
    body.addEventListener('submit', _onBodySubmit);
  }
  const validDeepLinkTab = _DEEP_LINK_TAB && document.querySelector(`#hub-tabs [data-sec-tab="${_DEEP_LINK_TAB}"]`);
  if (validDeepLinkTab) {
    _switchTab(_DEEP_LINK_TAB);
  } else {
    _loadActiveTab();
  }
}

export default { initSecurityHub };
