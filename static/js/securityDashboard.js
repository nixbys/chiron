/**
 * Security Dashboard Module — minimal v1 page for the security MCP
 * servers' aggregated state (routes/security_dashboard_routes.py).
 *
 * Uses the shared `.sec-*` component primitives (stat tiles, severity
 * badges, timeline rows — see style.css's "Security UI primitives"
 * section, Phase 2.2) rather than one-off inline styles. Still a minimal
 * page — 2.4 is where this becomes the full Security Hub with
 * engagement/watchlist/rule-management sub-panels — but it's built on the
 * real primitives from the start now that they exist, not a retrofit.
 */

const API_BASE = window.location.origin;

let _open = false;
let _modal = null;
let _loading = false;

// ── Modal (same lazy-singleton pattern as calendar.js's _getModal) ──

function _getModal() {
  if (_modal) return _modal;
  _modal = document.createElement('div');
  _modal.id = 'security-dashboard-modal';
  _modal.className = 'modal';
  _modal.style.display = 'none';
  _modal.innerHTML = `
    <div class="modal-content" style="max-width:920px;width:92vw;max-height:85vh;display:flex;flex-direction:column;">
      <div class="modal-header">
        <h4><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:6px"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>Security Dashboard</h4>
        <button class="close-btn" id="secdash-close">&#x2715;</button>
      </div>
      <div class="modal-body" id="secdash-body" style="overflow-y:auto;padding:16px;"></div>
    </div>`;
  document.body.appendChild(_modal);
  _modal.querySelector('#secdash-close').addEventListener('click', closeSecurityDashboard);
  _modal.addEventListener('click', (e) => { if (e.target === _modal) closeSecurityDashboard(); });
  return _modal;
}

// ── Rendering ──

function _escape(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

function _sectionCard(title, bodyHtml) {
  return `
    <div style="border:1px solid var(--border);border-radius:var(--radius-md);padding:12px 14px;margin-bottom:12px;">
      <div style="font-family:var(--font-family,'IBM Plex Mono',monospace);font-size:10.5px;text-transform:uppercase;letter-spacing:0.06em;color:var(--fg-muted);margin-bottom:10px;">${_escape(title)}</div>
      ${bodyHtml}
    </div>`;
}

function _errorLine(msg) {
  return `<div style="color:var(--fg-muted);font-size:12px;">Unavailable: ${_escape(msg)}</div>`;
}

// Findings' severity/status keys aren't guaranteed to match the 5-step
// sec-badge scale (OpenSearch just returns whatever string was indexed) --
// map known keys to a badge class and fall back to a plain chip for
// anything unrecognized rather than mislabeling it.
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

function _renderWatchlist(section) {
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

function _renderEngagements(section) {
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

function _render(data) {
  const el = document.getElementById('secdash-body');
  if (!el) return;
  const findings = data.findings || {};
  const watchlist = data.watchlist || {};
  const engagements = data.engagements || {};
  el.innerHTML = [
    !findings.error && !watchlist.error && !engagements.error ? _renderStatRow(findings, watchlist, engagements) : '',
    _renderFindings(findings),
    _renderWatchlist(watchlist),
    _renderScanDrift(data.scan_drift || {}),
    _renderEngagements(engagements),
    _renderHostTelemetry(data.host_telemetry || {}),
  ].join('');
}

async function _load() {
  const el = document.getElementById('secdash-body');
  if (!el || _loading) return;
  _loading = true;
  el.innerHTML = '<div style="font-size:12px;opacity:0.7;padding:8px 0;">Loading…</div>';
  try {
    const res = await fetch(`${API_BASE}/api/security/dashboard`, { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _render(data);
  } catch (err) {
    el.innerHTML = `<div style="font-size:12px;opacity:0.7;">Failed to load: ${_escape(err.message || String(err))}</div>`;
  } finally {
    _loading = false;
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
  _load();
}

export function closeSecurityDashboard() {
  if (_modal) _modal.style.display = 'none';
  _open = false;
}

export default { openSecurityDashboard, closeSecurityDashboard, isSecurityDashboardOpen };
