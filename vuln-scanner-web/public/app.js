const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const urlInput = document.getElementById('url-input');
const scanBtn = document.getElementById('scan-btn');
const chkPassive = document.getElementById('chk-passive');
const chkActive = document.getElementById('chk-active');
const statusLine = document.getElementById('status-line');
const scanbeam = document.getElementById('scanbeam');

const resultsPanel = document.getElementById('results-panel');
const emptyPanel = document.getElementById('empty-panel');
const resultsList = document.getElementById('results-list');
const detailPane = document.getElementById('detail-pane');
const summaryStrip = document.getElementById('summary-strip');
const exportBtn = document.getElementById('export-btn');

let currentResults = [];
let currentTarget = '';

scanBtn.addEventListener('click', runScan);
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runScan();
});
exportBtn.addEventListener('click', exportReport);

async function runScan() {
  const url = urlInput.value.trim();
  const passive = chkPassive.checked;
  const active = chkActive.checked;

  if (!url) {
    setStatus('Informe uma URL válida.', 'error');
    return;
  }
  if (!passive && !active) {
    setStatus('Selecione ao menos um tipo de análise.', 'error');
    return;
  }

  setScanning(true);
  setStatus(`escaneando ${url} ...`);
  resultsPanel.hidden = true;
  emptyPanel.hidden = true;

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, passive, active }),
    });
    const data = await resp.json();

    if (!resp.ok) {
      setStatus(data.error || 'Erro desconhecido.', 'error');
      return;
    }

    currentResults = sortBySeverity(data.results || []);
    currentTarget = data.target || url;

    if (currentResults.length === 0) {
      emptyPanel.hidden = false;
      setStatus(`concluído — nenhum achado para ${currentTarget}`, 'success');
    } else {
      renderResults();
      resultsPanel.hidden = false;
      setStatus(`concluído — ${currentResults.length} item(ns) encontrado(s) em ${currentTarget}`, 'success');
    }
  } catch (err) {
    setStatus(`Erro de rede: ${err.message}`, 'error');
  } finally {
    setScanning(false);
  }
}

function sortBySeverity(results) {
  return [...results].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
}

function renderResults() {
  resultsList.innerHTML = '';
  detailPane.innerHTML = '<p class="detail-placeholder">Selecione um item para ver os detalhes.</p>';

  const counts = {};
  for (const r of currentResults) counts[r.severity] = (counts[r.severity] || 0) + 1;

  summaryStrip.innerHTML = SEVERITY_ORDER
    .filter((sev) => counts[sev])
    .map((sev) => `<span class="sum-${sev}">${sev} · ${counts[sev]}</span>`)
    .join(' | ');

  currentResults.forEach((r, idx) => {
    const li = document.createElement('li');
    li.className = `result-item sev-${r.severity}`;
    li.dataset.idx = String(idx);
    li.innerHTML = `
      <span class="sev-badge sev-${r.severity}">${r.severity}</span>
      <span class="item-title">${escapeHtml(r.title)}</span>
      <span class="item-cat">${escapeHtml(r.category)}</span>
    `;
    li.addEventListener('click', () => selectResult(idx));
    resultsList.appendChild(li);
  });
}

function selectResult(idx) {
  const r = currentResults[idx];
  document.querySelectorAll('.result-item').forEach((el) => el.classList.remove('selected'));
  const active = resultsList.querySelector(`[data-idx="${idx}"]`);
  if (active) active.classList.add('selected');

  const referenceBlock = r.reference
    ? `<div class="detail-section">
          <strong>🔗 SAIBA MAIS</strong>
          <a href="${escapeHtml(r.reference.url)}" target="_blank" rel="noopener">
            ${escapeHtml(r.reference.label)} ↗
          </a>
        </div>`
    : '';

  const exploitationBlock = r.exploitation
    ? `<div class="detail-section exploitation-section">
          <strong>💀 EXPLORAÇÃO PRÁTICA</strong>
          <div class="exploit-content">${r.exploitation}</div>
        </div>`
    : '';

  detailPane.innerHTML = `
    <div class="detail-header">
      <h3>${escapeHtml(r.title)}</h3>
      <span class="detail-meta">${escapeHtml(r.category)} · ${r.severity}</span>
    </div>
    <div class="detail-section">
      <strong>📋 DESCRIÇÃO</strong>
      <p>${escapeHtml(r.description)}</p>
    </div>
    <div class="detail-section">
      <strong>🛡️ RECOMENDAÇÃO</strong>
      <p>${escapeHtml(r.recommendation)}</p>
    </div>
    ${exploitationBlock}
    ${referenceBlock}
  `;
}

function exportReport() {
  if (currentResults.length === 0) return;
  let text = 'RELATÓRIO DE ANÁLISE DE VULNERABILIDADES\n';
  text += '==========================================\n';
  text += `Alvo: ${currentTarget}\n\n`;
  for (const r of currentResults) {
    text += `[${r.severity}] (${r.category}) ${r.title}\n`;
    text += `  Descrição: ${r.description}\n`;
    text += `  Recomendação: ${r.recommendation}\n`;
    if (r.exploitation) {
      text += `  Exploração:\n`;
      const stripped = r.exploitation.replace(/<[^>]+>/g, '');
      text += `    ${stripped.split('\n').join('\n    ')}\n`;
    }
    if (r.reference) {
      text += `  Saiba mais: ${r.reference.label} — ${r.reference.url}\n`;
    }
    text += '\n';
  }
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'relatorio-vulnerabilidades.txt';
  link.click();
  URL.revokeObjectURL(link.href);
}

function setScanning(isScanning) {
  scanBtn.disabled = isScanning;
  scanBtn.querySelector('.btn-label').textContent = isScanning ? 'ESCANEANDO…' : 'ESCANEAR';
  scanbeam.classList.toggle('active', isScanning);
}

function setStatus(message, kind) {
  statusLine.textContent = message;
  statusLine.classList.remove('error', 'success');
  if (kind) statusLine.classList.add(kind);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}