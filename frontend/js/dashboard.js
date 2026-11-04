/**
 * dashboard.js — Dashboard view: stats cards, charts, model performance
 */

let donutChart = null;
let barChart   = null;
let dashInitialised = false;

window.initDashboard = async function () {
  if (dashInitialised) {
    await refreshDashboard();
    return;
  }
  dashInitialised = true;
  await refreshDashboard();
};

async function refreshDashboard() {
  await Promise.all([loadStats(), loadModelInfo()]);
}

// ─── Stats ───────────────────────────────────────────────────
async function loadStats() {
  try {
    const { stats } = await API.get('/stats');
    animateCounter('stat-total-value',    stats.total_scans);
    animateCounter('stat-phishing-value', stats.phishing_count);
    animateCounter('stat-legit-value',    stats.legitimate_count);

    const rateEl = document.getElementById('stat-rate-value');
    rateEl.textContent = stats.total_scans > 0
      ? `${(stats.detection_rate * 100).toFixed(1)}%`
      : '—';

    renderDonut(stats.phishing_count, stats.legitimate_count);
    renderBar(stats.daily_trend || []);
  } catch (err) {
    console.warn('Stats load failed:', err);
  }
}

function animateCounter(elId, target) {
  const el = document.getElementById(elId);
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  const duration = 600;
  const step = (Date.now() % 1000) / 1000;
  const startTime = performance.now();

  function tick(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + (target - start) * eased).toLocaleString();
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ─── Donut Chart ─────────────────────────────────────────────
function renderDonut(phishing, legitimate) {
  const canvas = document.getElementById('donut-chart');
  const empty  = document.getElementById('donut-empty');
  const wrap   = document.getElementById('donut-wrap');

  if (phishing === 0 && legitimate === 0) {
    canvas.style.display = 'none';
    empty.style.display  = 'block';
    return;
  }

  canvas.style.display = 'block';
  empty.style.display  = 'none';

  if (donutChart) donutChart.destroy();

  donutChart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['Phishing', 'Legitimate'],
      datasets: [{
        data: [phishing, legitimate],
        backgroundColor: ['rgba(255,61,90,0.8)', 'rgba(0,230,118,0.8)'],
        borderColor:     ['rgba(255,61,90,1)',   'rgba(0,230,118,1)'],
        borderWidth: 2,
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#8fa3c0',
            font: { family: 'Inter', size: 12 },
            padding: 16,
          },
        },
        tooltip: {
          backgroundColor: 'rgba(10,17,32,0.95)',
          titleColor: '#e8f0fe',
          bodyColor: '#8fa3c0',
          borderColor: 'rgba(0,229,255,0.2)',
          borderWidth: 1,
        },
      },
      animation: { duration: 800 },
    },
  });
}

// ─── Bar Chart ───────────────────────────────────────────────
function renderBar(trend) {
  const canvas = document.getElementById('bar-chart');
  const empty  = document.getElementById('bar-empty');

  if (!trend || trend.length === 0) {
    canvas.style.display = 'none';
    empty.style.display  = 'block';
    return;
  }

  canvas.style.display = 'block';
  empty.style.display  = 'none';

  if (barChart) barChart.destroy();

  const labels    = trend.map(r => r.day);
  const phishing  = trend.map(r => r.phishing);
  const legit     = trend.map(r => r.legitimate);

  barChart = new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'Phishing',
          data: phishing,
          backgroundColor: 'rgba(255,61,90,0.6)',
          borderColor:     'rgba(255,61,90,1)',
          borderWidth: 1,
          borderRadius: 4,
        },
        {
          label: 'Legitimate',
          data: legit,
          backgroundColor: 'rgba(0,230,118,0.5)',
          borderColor:     'rgba(0,230,118,1)',
          borderWidth: 1,
          borderRadius: 4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          stacked: false,
          ticks: { color: '#8fa3c0', font: { size: 11 } },
          grid:  { color: 'rgba(255,255,255,0.04)' },
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#8fa3c0', font: { size: 11 }, stepSize: 1 },
          grid:  { color: 'rgba(255,255,255,0.05)' },
        },
      },
      plugins: {
        legend: {
          labels: {
            color: '#8fa3c0',
            font: { family: 'Inter', size: 12 },
            padding: 16,
          },
        },
        tooltip: {
          backgroundColor: 'rgba(10,17,32,0.95)',
          titleColor: '#e8f0fe',
          bodyColor: '#8fa3c0',
          borderColor: 'rgba(0,229,255,0.2)',
          borderWidth: 1,
        },
      },
      animation: { duration: 600 },
    },
  });
}

// ─── Model Info ──────────────────────────────────────────────
async function loadModelInfo() {
  const loading  = document.getElementById('model-loading');
  const content  = document.getElementById('model-info-content');
  const errEl    = document.getElementById('model-error');

  loading.classList.remove('hidden');
  content.classList.add('hidden');
  errEl.classList.add('hidden');

  try {
    const { model } = await API.get('/model-info');
    loading.classList.add('hidden');
    content.classList.remove('hidden');

    // Header
    document.getElementById('model-badge').textContent = model.best_model || 'Unknown';
    document.getElementById('model-trained-at').textContent =
      model.trained_at ? `Trained ${formatDate(model.trained_at)}` : 'Training date unknown';
    document.getElementById('model-dataset-info').textContent =
      model.n_train ? `${(model.n_train + model.n_test).toLocaleString()} samples` : '';

    // Metrics comparison
    renderMetricsComparison(model.winner_metrics, model.runner_up_metrics);

    // Feature importances
    renderFeatureBars(model.top_features || []);

  } catch (err) {
    loading.classList.add('hidden');
    errEl.classList.remove('hidden');
    console.warn('Model info load failed:', err);
  }
}

function renderMetricsComparison(winner, runnerUp) {
  const container = document.getElementById('metrics-comparison');
  if (!container) return;

  const fmt = v => v != null ? (v * 100).toFixed(2) + '%' : '—';
  const metrics = [
    ['Accuracy',  'accuracy'],
    ['Precision', 'precision'],
    ['Recall',    'recall'],
    ['F1 Score',  'f1_score'],
    ['ROC-AUC',   'roc_auc'],
  ];

  function buildBlock(data, isWinner) {
    const div = document.createElement('div');
    div.className = `metrics-block${isWinner ? ' winner' : ''}`;
    const title = isWinner
      ? `🏆 ${data?.name || 'Best Model'} (Winner)`
      : `${data?.name || 'Runner-up'}`;
    div.innerHTML = `<div class="metrics-block-title">${title}</div>`;
    metrics.forEach(([label, key]) => {
      const row = document.createElement('div');
      row.className = 'metric-row';
      row.innerHTML = `<span class="metric-name">${label}</span><span class="metric-value">${fmt(data?.[key])}</span>`;
      div.appendChild(row);
    });
    return div;
  }

  container.innerHTML = '';
  container.appendChild(buildBlock(winner,   true));
  if (runnerUp?.name) container.appendChild(buildBlock(runnerUp, false));
}

function renderFeatureBars(features) {
  const container = document.getElementById('feature-bars');
  if (!container) return;
  container.innerHTML = '';

  if (!features.length) {
    container.innerHTML = '<span style="color:var(--text-muted);font-size:0.85rem">No feature data available.</span>';
    return;
  }

  const maxVal = features[0].importance;
  features.forEach(({ feature, importance }) => {
    const pct = maxVal > 0 ? (importance / maxVal * 100).toFixed(1) : 0;
    const row = document.createElement('div');
    row.className = 'feature-bar-row';
    row.innerHTML = `
      <div class="feature-bar-name" title="${feature}">${feature}</div>
      <div class="feature-bar-track">
        <div class="feature-bar-fill" style="width:0%"></div>
      </div>
      <div class="feature-bar-value">${(importance * 100).toFixed(2)}%</div>
    `;
    container.appendChild(row);
    // Animate on next frame
    requestAnimationFrame(() => {
      row.querySelector('.feature-bar-fill').style.width = `${pct}%`;
    });
  });
}
