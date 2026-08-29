/**
 * Security Dashboard Module — minimal v1 page for the security MCP
 * servers' aggregated state (routes/security_dashboard_routes.py).
 *
 * Deliberately minimal: no dashboard-grid/stat-card/severity-badge CSS
 * primitives exist in style.css yet, so this renders with inline styles
 * on top of the shared .modal/.list-item classes rather than inventing a
 * one-off design system for a page a later pass rebuilds anyway (Phase 2
 * turns this into the full Security Hub).
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
    <div style="border:1px solid var(--border-color, #3336);border-radius:8px;padding:12px 14px;margin-bottom:12px;">
      <div style="font-weight:600;font-size:13px;margin-bottom:8px;">${_escape(title)}</div>
      ${bodyHtml}
    </div>`;
}

function _errorLine(msg) {
  return `<div style="opacity:0.7;font-size:12px;">Unavailable: ${_escape(msg)}</div>`;
}

function _renderFindings(section) {
  if (section.error) return _sectionCard('Findings', _errorLine(section.error));
  const sevs = (section.by_severity || []).map(b => `${_escape(b.key)}: ${b.doc_count}`).join('  &nbsp; ') || '(none)';
  const statuses = (section.by_status || []).map(b => `${_escape(b.key)}: ${b.doc_count}`).join('  &nbsp; ') || '(none)';
  const body = `
    <div style="font-size:12px;line-height:1.7;">
      <div>Total: <strong>${section.total ?? 0}</strong></div>
      <div>By severity: ${sevs}</div>
      <div>By status: ${statuses}</div>
    </div>`;
  return _sectionCard('Findings', body);
}

function _renderWatchlist(section) {
  if (section.error) return _sectionCard('Watchlist', _errorLine(section.error));
  const rows = (section.entries || []).map(e =>
    `<div style="font-size:12px;padding:2px 0;">${_escape(e.kind)} &nbsp; <code>${_escape(e.indicator)}</code>${e.engagement_id ? ` &nbsp; <span style="opacity:0.6;">(${_escape(e.engagement_id)})</span>` : ''}</div>`
  ).join('') || '<div style="font-size:12px;opacity:0.7;">No active entries.</div>';
  return _sectionCard(`Watchlist (${section.count ?? 0} active)`, rows);
}

function _renderScanDrift(section) {
  if (section.error) return _sectionCard('Recent Scan Drift', _errorLine(section.error));
  const diffs = section.diffs || [];
  const rows = diffs.map(d => {
    const when = d.ts ? new Date(d.ts * 1000).toLocaleString() : '';
    return `<div style="font-size:12px;padding:2px 0;">
      <span style="opacity:0.6;">${_escape(when)}</span> &nbsp;
      [${_escape(d.check_type)}] ${_escape(d.target)} &nbsp;
      +${(d.added || []).length} -${(d.removed || []).length}
    </div>`;
  }).join('') || '<div style="font-size:12px;opacity:0.7;">No drift recorded yet.</div>';
  return _sectionCard('Recent Scan Drift', rows);
}

function _renderEngagements(section) {
  if (section.error) return _sectionCard('Engagements', _errorLine(section.error));
  const rows = (section.list || []).map(e =>
    `<div style="font-size:12px;padding:2px 0;">${_escape(e.name)} &nbsp; <span style="opacity:0.6;">${_escape(e.client || '')} &middot; ${_escape(e.status)}</span></div>`
  ).join('') || '<div style="font-size:12px;opacity:0.7;">No engagements yet.</div>';
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
  el.innerHTML = [
    _renderFindings(data.findings || {}),
    _renderWatchlist(data.watchlist || {}),
    _renderScanDrift(data.scan_drift || {}),
    _renderEngagements(data.engagements || {}),
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
