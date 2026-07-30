import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { runPassiveScan } from './scanners/passiveScanner.js';
import { runActiveScan } from './scanners/activeScanner.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/scan', async (req, res) => {
  const { url, passive, active } = req.body ?? {};

  if (!url || typeof url !== 'string' || !url.trim()) {
    return res.status(400).json({ error: 'Informe uma URL válida.' });
  }
  if (!passive && !active) {
    return res.status(400).json({ error: 'Selecione ao menos um tipo de análise.' });
  }

  let target = url.trim();
  if (!/^https?:\/\//i.test(target)) {
    target = 'https://' + target;
  }

  try {
    // valida se é uma URL bem formada antes de prosseguir
    new URL(target);
  } catch {
    return res.status(400).json({ error: 'URL mal formada.' });
  }

  const results = [];
  try {
    if (passive) {
      results.push(...await runPassiveScan(target));
    }
    if (active) {
      results.push(...await runActiveScan(target));
    }
  } catch (err) {
    return res.status(500).json({ error: `Falha durante o escaneamento: ${err.message}` });
  }

  res.json({ target, results });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vuln Scanner Web rodando em http://localhost:${PORT}`);
});
