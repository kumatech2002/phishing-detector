/**
 * analyzer.js — Domain submission and result display
 */

const domainInput   = document.getElementById('domain-input');
const analyzeBtn    = document.getElementById('analyze-btn');
const clearBtn      = document.getElementById('clear-btn');
const inputHint     = document.getElementById('input-hint');

const resultIdle     = document.getElementById('result-idle');
const resultScanning = document.getElementById('result-scanning');
const resultOutput   = document.getElementById('result-output');
const resultError    = document.getElementById('result-error');

// ─── State helpers ────────────────────────────────────────────
function showState(state) {
  resultIdle.classList.toggle('hidden',     state !== 'idle');
  resultScanning.classList.toggle('hidden', state !== 'scanning');
  resultOutput.classList.toggle('hidden',   state !== 'result');
  resultError.classList.toggle('hidden',    state !== 'error');

  if (state === 'idle' || state === 'scanning' || state === 'error') {
    document.getElementById('result-card').style.alignItems = 'center';
    document.getElementById('result-card').style.justifyContent = 'center';
  } else {
    document.getElementById('result-card').style.alignItems = 'flex-start';
    document.getElementById('result-card').style.justifyContent = 'flex-start';
  }
}

showState('idle');

// ─── Input validation ─────────────────────────────────────────
function validateInput(raw) {
  if (!raw.trim()) return { valid: false, msg: 'Please enter a domain.' };
  if (raw.length > 253) return { valid: false, msg: 'Domain is too long (max 253 characters).' };
  const cleaned = raw.replace(/^https?:\/\//i, '').split('/')[0];
  const pattern = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!pattern.test(cleaned) && !cleaned.startsWith('xn--')) {
    return { valid: false, msg: `"${cleaned}" doesn't look like a valid domain. Try: gtbank.com` };
  }
  return { valid: true, msg: 'Enter the domain only — no http:// needed' };
}

domainInput.addEventListener('input', () => {
  const { valid, msg } = validateInput(domainInput.value);
  inputHint.textContent = msg;
  inputHint.className   = `input-hint${valid ? '' : ' error'}`;
  analyzeBtn.disabled   = !valid && domainInput.value.trim().length > 0;
});

domainInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') triggerAnalysis();
});

clearBtn.addEventListener('click', () => {
  domainInput.value    = '';
  inputHint.textContent = 'Enter the domain only — no http:// needed';
  inputHint.className   = 'input-hint';
  analyzeBtn.disabled   = false;
  showState('idle');
});

// ─── Example chips ────────────────────────────────────────────
document.querySelectorAll('.example-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    domainInput.value = chip.dataset.domain;
    const { valid, msg } = validateInput(domainInput.value);
    inputHint.textContent = msg;
    inputHint.className = `input-hint${valid ? '' : ' error'}`;
    triggerAnalysis();
  });
});

// ─── Analyse button ───────────────────────────────────────────
analyzeBtn.addEventListener('click', triggerAnalysis);

async function triggerAnalysis() {
  const raw = domainInput.value.trim();
  const { valid, msg } = validateInput(raw);

  if (!valid) {
    inputHint.textContent = msg;
    inputHint.className   = 'input-hint error';
    return;
  }

  const domain = raw.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();

  // Show scanning state
  showState('scanning');
  document.getElementById('scanning-domain-text').textContent = domain;
  analyzeBtn.disabled = true;

  try {
    const data = await API.post('/analyze', { domain });
    renderResult(data.result);
    // Refresh stats counter
    if (window._activeView === 'analyzer') {
      // Silently refresh stats in background
      API.get('/stats').then(d => {
        const el = document.getElementById('stat-total-value');
        if (el) animateStatValue(el, d.stats.total_scans);
      }).catch(() => {});
    }
  } catch (err) {
    showState('error');
    document.getElementById('error-message').textContent = err.message || 'Analysis failed. Is the backend running?';
  } finally {
    analyzeBtn.disabled = false;
  }
}

function animateStatValue(el, target) {
  const start = parseInt(el.textContent.replace(/,/g, '')) || 0;
  const startTime = performance.now();
  function tick(now) {
    const p = Math.min((now - startTime) / 500, 1);
    el.textContent = Math.round(start + (target - start) * p).toLocaleString();
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ─── Render result ────────────────────────────────────────────
function renderResult(result) {
  showState('result');

  const isPhishing = result.label === 1;
  const cls        = isPhishing ? 'phishing' : 'legitimate';

  // Verdict banner
  const banner = document.getElementById('verdict-banner');
  banner.className = `verdict-banner ${cls}`;
  document.getElementById('verdict-icon').textContent  = isPhishing ? '🚨' : '✅';
  document.getElementById('verdict-label').textContent = isPhishing ? 'PHISHING DETECTED' : 'LEGITIMATE DOMAIN';
  document.getElementById('verdict-domain').textContent = result.domain;

  // Confidence
  const confPct = Math.round(result.confidence * 100);
  document.getElementById('confidence-value').textContent = `${confPct}%`;
  const bar = document.getElementById('confidence-bar');
  bar.className = `confidence-bar-fill ${cls}`;
  // Animate after DOM paints
  requestAnimationFrame(() => {
    setTimeout(() => { bar.style.width = `${confPct}%`; }, 50);
  });
  document.getElementById('confidence-description').textContent = result.explanation || '';

  // Risk indicators
  renderRiskIndicators(result.risk_indicators || []);

  // Feature table
  renderFeatureTable(result.features || {});

  // Disclaimer
  document.getElementById('result-disclaimer').textContent = result.disclaimer || '';
}

function renderRiskIndicators(indicators) {
  const list = document.getElementById('risk-list');
  list.innerHTML = '';

  if (!indicators.length) {
    list.innerHTML = '<div class="no-indicators">No specific risk indicators detected.</div>';
    return;
  }

  indicators.forEach((ind, i) => {
    const item = document.createElement('div');
    item.className = `risk-item ${ind.level}`;
    item.style.animationDelay = `${i * 60}ms`;
    item.innerHTML = `
      <span class="risk-badge">${ind.level}</span>
      <span class="risk-text">${escapeHtml(ind.text)}</span>
    `;
    list.appendChild(item);
  });
}

function renderFeatureTable(features) {
  const tbody = document.getElementById('features-tbody');
  tbody.innerHTML = '';
  Object.entries(features).forEach(([k, v]) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${escapeHtml(k)}</td><td>${typeof v === 'number' ? v.toFixed(4) : v}</td>`;
    tbody.appendChild(tr);
  });

  // Toggle
  const toggle = document.getElementById('features-toggle');
  const wrap   = document.getElementById('features-table-wrap');
  toggle.onclick = () => {
    const hidden = wrap.classList.toggle('hidden');
    toggle.textContent = hidden ? '[show]' : '[hide]';
  };
}

// ─── Helpers ─────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
