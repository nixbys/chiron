/**
 * Security Hub Module — the security MCP servers' aggregated state
 * (Overview tab, routes/security_dashboard_routes.py's /dashboard) plus
 * management sub-panels for engagements, the watchlist, and Sigma/YARA
 * rules (Phase 2.4) -- a way to browse/manage these from the web UI
 * instead of only via chat/MCP tools.
 *
 * Uses the shared `.sec-*` component primitives (stat tiles, severity
 * badges, timeline rows -- see style.css's "Security UI primitives"
 * section, Phase 2.2) and the site's existing `.admin-tab` tab-bar
 * component (same one the theme picker's Themes/Customize tabs use)
 * rather than inventing a new tab style for this one modal.
 *
 * Every write (create/close an engagement, add/remove/pause a watchlist
 * entry) goes through the same admin-gated REST endpoints that call
 * straight into the MCP server modules' own call_tool() -- there is no
 * separate write path here, just a UI on top of the one that already
 * existed for chat/MCP.
 */

const API_BASE = window.location.origin;

let _open = false;
let _modal = null;
let _activeTab = 'overview';

// Per-tab cached state, so switching tabs doesn't lose an in-progress
// form or force a re-fetch every time.
const _state = {
  engagements: { list: null, expandedId: null, detail: null, formOpen: false },
  watchlist: { list: null, formOpen: false },
  rules: { sigma: null, yara: null, viewing: null, content: null },
};

// ── Modal (same lazy-singleton pattern as calendar.js's _getModal) ──

function _getModal() {
  if (_modal) return _modal;
  _modal = document.createElement('div');
  _modal.id = 'security-dashboard-modal';
  _modal.className = 'modal';
  _modal.style.display = 'none';
  _modal.innerHTML = `
    <div class="modal-content" style="max-width:960px;width:92vw;max-height:85vh;display:flex;flex-direction:column;">
      <div class="modal-header">
        <h4><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:6px"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>Security Hub</h4>
        <button class="close-btn" id="secdash-close">&#x2715;</button>
      </div>
      <div style="display:flex;gap:2px;padding:0 16px;border-bottom:1px solid var(--border);flex-shrink:0;">
        <button class="admin-tab active" data-sec-tab="overview">Overview</button>
        <button class="admin-tab" data-sec-tab="engagements">Engagements</button>
        <button class="admin-tab" data-sec-tab="watchlist">Watchlist</button>
        <button class="admin-tab" data-sec-tab="rules">Rules</button>
      </div>
      <div class="modal-body" id="secdash-body" style="overflow-y:auto;padding:16px;"></div>
    </div>`;
  document.body.appendChild(_modal);
  _modal.querySelector('#secdash-close').addEventListener('click', closeSecurityDashboard);
  _modal.addEventListener('click', (e) => { if (e.target === _modal) closeSecurityDashboard(); });
  _modal.querySelectorAll('[data-sec-tab]').forEach((btn) => {
    btn.addEventListener('click', () => _switchTab(btn.dataset.secTab));
  });
  // One delegated listener for every interactive control rendered inside
  // the body -- panels are fully re-rendered (innerHTML replaced) on every
  // state change, so per-element listeners would need re-binding each time.
  _modal.querySelector('#secdash-body').addEventListener('click', _onBodyClick);
  _modal.querySelector('#secdash-body').addEventListener('submit', _onBodySubmit);
  return _modal;
}

function _switchTab(tab) {
  _activeTab = tab;
  _modal.querySelectorAll('[data-sec-tab]').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.secTab === tab);
  });
  _loadActiveTab();
}

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

// ── Overview tab (unchanged from the v1 dashboard) ──

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
    // Dot color carries what kind of change this was: something newly
    // present (blue, detection-relevant) vs. something that disappeared
    // (crimson) -- if both, added takes priority since a new item is
    // usually the more actionable half.
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
  const el = document.getElementById('secdash-body');
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
  const el = document.getElementById('secdash-body');
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
    const timeline = (d.timeline || []).map(ev => {
      const when = ev.ts ? new Date(ev.ts * 1000).toLocaleString() : '';
      return `<div class="sec-tl-row"><span class="sec-tl-time">${_escape(when)}</span><span class="sec-tl-dot sec-muted"></span><span class="sec-tl-text">[${_escape(ev.event_type)}] ${_escape(ev.summary)}</span></div>`;
    }).join('') || '<div style="font-size:12px;color:var(--fg-muted);padding:4px 0;">No events yet.</div>';
    detailHtml = `
      <div style="padding:10px 0 2px;font-size:12px;color:var(--fg-muted);">
        <div style="margin-bottom:6px;">${_escape(d.engagement.description || '(no description)')}</div>
        <div style="margin-bottom:6px;">Scope: ${_escape(scope)}</div>
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
  if (!_state.engagements.formOpen) {
    return `<div style="margin-bottom:10px;">${_smallBtn('+ New Engagement', 'toggle-engagement-form', '')}</div>`;
  }
  return `
    <form data-action="create-engagement" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;align-items:center;">
      <input class="sec-hub-input" name="name" placeholder="name (required)" required style="flex:1;min-width:140px;">
      <input class="sec-hub-input" name="client" placeholder="client" style="flex:1;min-width:120px;">
      <input class="sec-hub-input" name="scope" placeholder="scope, comma-separated" style="flex:2;min-width:180px;">
      <button type="submit" class="sec-hub-btn sec-hub-btn-primary">Create</button>
      ${_smallBtn('Cancel', 'toggle-engagement-form', '')}
    </form>`;
}

function _renderEngagements() {
  const el = document.getElementById('secdash-body');
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
    const el = document.getElementById('secdash-body');
    if (el) el.innerHTML = _errorLine(err.message || String(err));
    return;
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
  const el = document.getElementById('secdash-body');
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
    const el = document.getElementById('secdash-body');
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
  const el = document.getElementById('secdash-body');
  if (!el) return;
  const { sigma, yara, viewing, content } = _state.rules;
  if (sigma == null || yara == null) {
    el.innerHTML = '<div style="font-size:12px;opacity:0.7;padding:8px 0;">Loading…</div>';
    return;
  }
  const viewerHtml = viewing
    ? `<div style="margin-top:14px;">
         <div style="font-family:var(--font-family,'IBM Plex Mono',monospace);font-size:10.5px;text-transform:uppercase;letter-spacing:0.06em;color:var(--fg-muted);margin-bottom:6px;">${_escape(viewing.kind)} / ${_escape(viewing.name)}</div>
         <pre style="background:var(--panel-alt);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px;font-size:11.5px;overflow-x:auto;max-height:260px;white-space:pre-wrap;word-break:break-word;">${_escape(content == null ? 'Loading…' : content)}</pre>
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

// ── Tab dispatch ──

function _loadActiveTab() {
  if (_activeTab === 'overview') return _loadOverview();
  if (_activeTab === 'engagements') return _loadEngagements();
  if (_activeTab === 'watchlist') return _loadWatchlistTab();
  if (_activeTab === 'rules') return _loadRulesTab();
}

// ── Event delegation for actions inside #secdash-body ──

async function _onBodyClick(e) {
  const target = e.target.closest('[data-action]');
  if (!target) return;
  const action = target.dataset.action;
  const id = target.dataset.id;

  if (action === 'toggle-engagement-form') {
    _state.engagements.formOpen = !_state.engagements.formOpen;
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
    const res = await fetch(`${API_BASE}/api/security/engagements`, {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, client: String(fd.get('client') || ''), scope }),
    });
    if (res.ok) _state.engagements.formOpen = false;
    await _loadEngagements();
  } else if (action === 'add-watchlist') {
    const indicator = String(fd.get('indicator') || '').trim();
    if (!indicator) return;
    const res = await fetch(`${API_BASE}/api/security/watchlist`, {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator, kind: fd.get('kind'), notes: String(fd.get('notes') || '') }),
    });
    if (res.ok) _state.watchlist.formOpen = false;
    await _loadWatchlistTab();
  }
}

// ── Public API ──

export function isSecurityDashboardOpen() {
  return _open;
}

export function openSecurityDashboard() {
  const modal = _getModal();
  modal.style.display = 'flex';
  _open = true;
  _loadActiveTab();
}

export function closeSecurityDashboard() {
  if (_modal) _modal.style.display = 'none';
  _open = false;
}

export default { openSecurityDashboard, closeSecurityDashboard, isSecurityDashboardOpen };
