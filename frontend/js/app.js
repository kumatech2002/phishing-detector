/**
 * app.js — SPA view router and shared API client for PhishShield NG
 */

// ─── Constants ───────────────────────────────────────────────
// Use an absolute URL so the frontend works whether served by Flask (port 5001)
// or by a separate dev server like VS Code Live Server (port 5500).
// Flask has CORS enabled for all origins so cross-port requests are allowed.
const API_BASE = 'http://127.0.0.1:5001/api';



// ─── View router ─────────────────────────────────────────────
const views = ['dashboard', 'analyzer', 'history', 'about'];

function showView(viewName) {
  views.forEach(v => {
    const section = document.getElementById(`view-${v}`);
    const link    = document.getElementById(`nav-${v}`);
    if (section) section.classList.toggle('active', v === viewName);
    if (link)    link.classList.toggle('active',  v === viewName);
  });
  window._activeView = viewName;
  // Trigger view-specific initialisation
  if (viewName === 'dashboard') window.initDashboard?.();
  if (viewName === 'history')   window.initHistory?.();
}

document.querySelectorAll('.nav-link[data-view]').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    showView(link.dataset.view);
  });
});

// ─── API Client ──────────────────────────────────────────────
const API = {
  async get(path) {
    const res = await fetch(`${API_BASE}${path}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },

  async post(path, body) {
    const res = await fetch(`${API_BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'API error');
    return data;
  },

  async delete(path) {
    const res = await fetch(`${API_BASE}${path}`, { method: 'DELETE' });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'API error');
    return data;
  },
};

// ─── Health / Status polling ─────────────────────────────────
async function updateStatus() {
  const dot  = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  try {
    const data = await API.get('/health');
    dot.className  = 'status-dot online';
    text.textContent = data.model_loaded ? 'Model Ready' : 'Model Not Loaded';
  } catch {
    dot.className  = 'status-dot offline';
    text.textContent = 'Backend Offline';
  }
}

updateStatus();
setInterval(updateStatus, 30_000);

// ─── Utilities ───────────────────────────────────────────────
window.API = API;

window.formatDate = function(isoString) {
  if (!isoString) return '—';
  try {
    return new Date(isoString + (isoString.endsWith('Z') ? '' : 'Z'))
      .toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'short' });
  } catch { return isoString; }
};

window.formatConfidence = function(value) {
  return `${(value * 100).toFixed(1)}%`;
};

// Initialise default view
showView('dashboard');
