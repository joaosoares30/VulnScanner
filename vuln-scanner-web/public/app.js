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
urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') runScan(); });
exportBtn.addEventListener('click', exportReport);

async function runScan() {
  const url = urlInput.value.trim();
  const passive = chkPassive.checked;
  const active = chkActive.checked;
  if (!url) { setStatus('Informe uma URL valida.', 'error'); return; }
  if (!passive && !active) { setStatus('Selecione ao menos um tipo de analise.', 'error'); return; }
  setScanning(true);
  setStatus('Escaneando ' + url + ' ...');
  resultsPanel.hidden = true;
  emptyPanel.hidden = true;
  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, passive, active }),
    });
    const data = await resp.json();
    if (!resp.ok) { setStatus(data.error || 'Erro.', 'error'); return; }
    currentResults = sortBySeverity(data.results || []);
    currentTarget = data.target || url;
    if (currentResults.length === 0) {
      emptyPanel.hidden = false;
      setStatus('Concluido - nenhum achado para ' + currentTarget, 'success');
    } else {
      renderResults();
      resultsPanel.hidden = false;
      setStatus('Concluido - ' + currentResults.length + ' item(ns) em ' + currentTarget, 'success');
    }
  } catch (err) { setStatus('Erro de rede: ' + err.message, 'error'); }
  finally { setScanning(false); }
}

function sortBySeverity(results) {
  return [...results].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

function renderResults() {
  resultsList.innerHTML = '';
  detailPane.innerHTML = '<p class="detail-placeholder">Selecione um item para ver os detalhes.</p>';
  const counts = {};
  for (const r of currentResults) counts[r.severity] = (counts[r.severity] || 0) + 1;
  summaryStrip.innerHTML = SEVERITY_ORDER.filter(s => counts[s]).map(s => '<span class="sum-' + s + '">' + s + ' ' + counts[s] + '</span>').join(' | ');
  currentResults.forEach((r, idx) => {
    const li = document.createElement('li');
    li.className = 'result-item sev-' + r.severity;
    li.dataset.idx = String(idx);
    li.innerHTML = '<span class="sev-badge sev-' + r.severity + '">' + r.severity + '</span> <span class="item-title">' + escapeHtml(r.title) + '</span> <span class="item-cat">' + escapeHtml(r.category) + '</span>';
    li.addEventListener('click', () => selectResult(idx));
    resultsList.appendChild(li);
  });
}

function selectResult(idx) {
  const r = currentResults[idx];
  document.querySelectorAll('.result-item').forEach(el => el.classList.remove('selected'));
  const active = resultsList.querySelector('[data-idx="' + idx + '"]');
  if (active) active.classList.add('selected');

  var refBlock = '';
  if (r.reference) {
    refBlock = '<div class="detail-section"><strong>SAIBA MAIS</strong><a href="' + escapeHtml(r.reference.url) + '" target="_blank">' + escapeHtml(r.reference.label) + '</a></div>';
  }

  var exploitBlock = '';
  if (r.exploitation) {
    exploitBlock = '<div class="detail-section exploitation-section"><strong>EXPLORACAO TEXTUAL</strong><div class="exploit-content">' + r.exploitation + '</div></div>';
  }

  var canExploit = (r.category === 'XSS' || r.category === 'SQL Injection' || r.category === 'Exposicao de Arquivos' || r.category === 'CORS');
  var exploitBtn = '';
  if (canExploit) {
    var etype = '';
    if (r.category === 'XSS') etype = 'xss';
    else if (r.category === 'SQL Injection') etype = 'sqli';
    else if (r.category === 'Exposicao de Arquivos') {
      if (r.title.indexOf('.git') !== -1) etype = 'git';
      else etype = 'env';
    }
    else if (r.category === 'CORS') etype = 'cors';
    exploitBtn = '<button class="exploit-btn" data-type="' + etype + '">EXECUTAR EXPLOIT REAL</button><div id="exploit-result" class="exploit-output"></div>';
  }

  detailPane.innerHTML = '<div class="detail-header"><h3>' + escapeHtml(r.title) + '</h3><span class="detail-meta">' + escapeHtml(r.category) + ' | ' + r.severity + '</span></div><div class="detail-section"><strong>DESCRICAO</strong><p>' + escapeHtml(r.description) + '</p></div><div class="detail-section"><strong>RECOMENDACAO</strong><p>' + escapeHtml(r.recommendation) + '</p></div>' + exploitBlock + exploitBtn + refBlock;
}

document.addEventListener('click', async (e) => {
  var btn = e.target.closest('.exploit-btn');
  if (!btn) return;
  var selItem = document.querySelector('.result-item.selected');
  if (!selItem) return;
  var r = currentResults[parseInt(selItem.dataset.idx)];
  if (!r) return;

  var type = btn.dataset.type;
  var resultDiv = document.getElementById('exploit-result');
  resultDiv.innerHTML = 'EXECUTANDO...';
  btn.disabled = true;

  try {
    var param = '';
    if (type === 'xss' || type === 'sqli') {
      var m = r.title.match(/'([^']+)'/);
      param = m ? m[1] : 'id';
    }
    var resp = await fetch('/api/exploit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: type, target: currentTarget, param: param }),
    });
    var data = await resp.json();
    if (!resp.ok) { resultDiv.innerHTML = 'Erro: ' + (data.error || 'desconhecido'); return; }

    var html = '';
    for (var i = 0; i < data.results.length; i++) {
      var res = data.results[i];
      if (res.type === 'error') {
        html += '<div class="exploit-error">' + res.message + '</div>';
      } else if (res.type === 'xss-exploit') {
        html += '<div class="exploit-success"><strong>XSS EXPLOIT EXECUTADO</strong><p>' + res.message + '</p><p>Link: <a href="' + escapeHtml(res.link) + '" target="_blank">' + escapeHtml(res.link) + '</a></p><p>Veja cookies capturados em: <a href="/api/exfil-logs" target="_blank">/api/exfil-logs</a></p></div>';
      } else if (res.type === 'sqli-result') {
        html += '<div class="exploit-success"><strong>SQLi - ' + res.name + '</strong><pre>' + escapeHtml(res.evidence) + '</pre></div>';
      } else if (res.type === 'git-exploit') {
        html += '<div class="exploit-success"><strong>.GIT EXPOSTO - ' + res.files + ' arquivo(s) lido(s)</strong><pre>' + escapeHtml(res.details) + '</pre></div>';
      } else if (res.type === 'env-exploit') {
        var secretsHtml = '';
        if (res.secrets && res.secrets.length > 0) {
          secretsHtml = '<div class="exploit-critical">SEGREDOS: ' + escapeHtml(res.secrets.join('\n')) + '</div>';
        }
        html += '<div class="exploit-success"><strong>.ENV EXPOSTO</strong><pre>' + escapeHtml(res.content) + '</pre>' + secretsHtml + '</div>';
      } else if (res.type === 'cors-exploit') {
        html += '<div class="exploit-success"><strong>CORS - PoC Gerada</strong><p>' + res.message + '</p><details><summary>HTML PoC</summary><pre>' + escapeHtml(res.poc) + '</pre></details></div>';
      }
    }
    resultDiv.innerHTML = html;
  } catch (err) {
    resultDiv.innerHTML = 'Erro de rede: ' + err.message;
  } finally {
    btn.disabled = false;
  }
});

function exportReport() {
  if (currentResults.length === 0) return;
  var text = 'RELATORIO DE ANALISE DE VULNERABILIDADES\n==========================================\nAlvo: ' + currentTarget + '\n\n';
  for (var i = 0; i < currentResults.length; i++) {
    var r = currentResults[i];
    text += '[' + r.severity + '] (' + r.category + ') ' + r.title + '\n  Descricao: ' + r.description + '\n  Recomendacao: ' + r.recommendation + '\n';
    if (r.exploitation) text += '  Exploracao: ' + r.exploitation.replace(/\n/g, '\n    ') + '\n';
    if (r.reference) text += '  Saiba mais: ' + r.reference.label + ' - ' + r.reference.url + '\n';
    text += '\n';
  }
  var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  var link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'relatorio-vulnerabilidades.txt';
  link.click();
  URL.revokeObjectURL(link.href);
}

function setScanning(v) {
  scanBtn.disabled = v;
  scanBtn.querySelector('.btn-label').textContent = v ? 'ESCANEANDO...' : 'ESCANEAR';
  scanbeam.classList.toggle('active', v);
}

function setStatus(msg, kind) {
  statusLine.textContent = msg;
  statusLine.classList.remove('error', 'success');
  if (kind) statusLine.classList.add(kind);
}

function escapeHtml(str) {
  var div = document.createElement('div');
  div.textContent = str || '';
  return div.innerHTML;
}