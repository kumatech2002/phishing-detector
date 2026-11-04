/**
 * history.js — Paginated scan history table with delete and CSV export
 */

let historyPage = 1;
const PER_PAGE  = 20;
let historyData = { total: 0, pages: 1, items: [] };

window.initHistory = async function () {
  historyPage = 1;
  await loadHistory();
};

async function loadHistory() {
  const tbody = document.getElementById('history-tbody');
  tbody.innerHTML = '<tr><td colspan="7" class="table-loading">Loading…</td></tr>';

  try {
    const data = await API.get(`/history?page=${historyPage}&per_page=${PER_PAGE}`);
    historyData = data;
    renderHistoryTable(data);
    updatePagination(data);
    document.getElementById('history-count').textContent =
      `${data.total.toLocaleString()} scan${data.total !== 1 ? 's' : ''} total`;
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="table-loading" style="color:var(--accent-red)">Failed to load history: ${err.message}</td></tr>`;
  }
}

function renderHistoryTable(data) {
  const tbody = document.getElementById('history-tbody');
  tbody.innerHTML = '';

  if (!data.items.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="table-loading">No scans recorded yet. Analyse a domain to get started.</td></tr>';
    return;
  }

  data.items.forEach(row => {
    const isPhishing = row.label === 1;
    const cls        = isPhishing ? 'phishing' : 'legitimate';
    const label      = isPhishing ? 'Phishing' : 'Legitimate';
    const confPct    = (row.confidence * 100).toFixed(1);

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="color:var(--text-muted);font-size:0.78rem">#${row.id}</td>
      <td class="domain-cell" title="${escHtml(row.domain)}">${escHtml(row.domain)}</td>
      <td><span class="verdict-chip ${cls}">${label}</span></td>
      <td class="confidence-cell">${confPct}%</td>
      <td style="font-size:0.78rem;color:var(--text-muted)">${escHtml(row.model_name || '—')}</td>
      <td class="timestamp-cell">${formatDate(row.scanned_at)}</td>
      <td>
        <button class="delete-btn" data-id="${row.id}" title="Delete scan #${row.id}">🗑</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  // Delete buttons
  tbody.querySelectorAll('.delete-btn').forEach(btn => {
    btn.addEventListener('click', () => deleteScan(parseInt(btn.dataset.id), btn));
  });
}

async function deleteScan(id, btn) {
  btn.disabled = true;
  btn.textContent = '…';
  try {
    await API.delete(`/history/${id}`);
    // Remove row with animation
    const tr = btn.closest('tr');
    tr.style.transition = 'opacity 0.3s, transform 0.3s';
    tr.style.opacity    = '0';
    tr.style.transform  = 'translateX(20px)';
    setTimeout(() => { tr.remove(); loadHistory(); }, 300);
  } catch (err) {
    btn.disabled = false;
    btn.textContent = '🗑';
    alert(`Failed to delete: ${err.message}`);
  }
}

// ─── Pagination ───────────────────────────────────────────────
function updatePagination(data) {
  document.getElementById('page-info').textContent = `Page ${data.page} of ${data.pages}`;
  document.getElementById('page-prev').disabled = data.page <= 1;
  document.getElementById('page-next').disabled = data.page >= data.pages;
}

document.getElementById('page-prev').addEventListener('click', async () => {
  if (historyPage > 1) { historyPage--; await loadHistory(); }
});

document.getElementById('page-next').addEventListener('click', async () => {
  if (historyPage < historyData.pages) { historyPage++; await loadHistory(); }
});

// ─── Refresh ──────────────────────────────────────────────────
document.getElementById('refresh-history-btn').addEventListener('click', async () => {
  historyPage = 1;
  await loadHistory();
});

// ─── CSV Export ───────────────────────────────────────────────
document.getElementById('export-csv-btn').addEventListener('click', async () => {
  try {
    // Fetch all pages — up to 1000 records
    const { items } = await API.get(`/history?page=1&per_page=1000`);
    if (!items.length) { alert('No data to export.'); return; }

    const headers = ['id', 'domain', 'label', 'label_text', 'confidence', 'phishing_probability', 'model_name', 'scanned_at'];
    const csv = [
      headers.join(','),
      ...items.map(r =>
        headers.map(h => {
          const v = String(r[h] ?? '');
          return v.includes(',') || v.includes('"') ? `"${v.replace(/"/g, '""')}"` : v;
        }).join(',')
      ),
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `phishshield_history_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert(`Export failed: ${err.message}`);
  }
});

// ─── Helpers ─────────────────────────────────────────────────
function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
