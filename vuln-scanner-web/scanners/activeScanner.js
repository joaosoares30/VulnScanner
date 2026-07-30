import * as cheerio from 'cheerio';
import { makeResult } from './references.js';

const UA = 'VulnScannerWeb/1.0 (uso autorizado apenas)';

const XSS_MARKER = 'vsx' + Math.random().toString(36).slice(2, 10);
const XSS_PAYLOAD = `<${XSS_MARKER}>`;
const SQLI_PAYLOAD = `'"`;
const MAX_TARGETS = 15;

const SQL_ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysqli?/i,
  /PostgreSQL.*ERROR/i,
  /ORA-\d{5}/,
  /Microsoft SQL Server.*error/i,
  /SQLite\/JDBCDriver/i,
  /System\.Data\.SqlClient/i,
  /unclosed quotation mark/i,
];

export async function runActiveScan(url) {
  const results = [];
  const targets = new Set();

  if (url.includes('?')) targets.add(url);

  try {
    const resp = await fetch(url, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(15000) });
    const html = await resp.text();
    const $ = cheerio.load(html);
    $('a[href]').each((_, el) => {
      if (targets.size >= MAX_TARGETS) return false;
      const href = $(el).attr('href');
      if (!href) return;
      try {
        const abs = new URL(href, url).toString();
        if (abs.includes('?')) targets.add(abs);
      } catch {
        // href inválido; ignora este link
      }
    });
  } catch {
    // crawling falhou; segue apenas com a URL original, se tiver parâmetros
  }

  if (targets.size === 0) {
    results.push(makeResult('INFO', 'Teste Ativo', 'Nenhum parâmetro encontrado',
      'Não foram encontrados links com parâmetros GET na página inicial para testar.',
      'Informe uma URL com parâmetros (ex: pagina.php?id=1) para testes ativos mais completos.'));
    return results;
  }

  for (const target of targets) {
    results.push(...await testReflectedXss(target));
    results.push(...await testSqlErrorInjection(target));
  }

  return results;
}

function buildVariants(url, payload) {
  const variants = [];
  const base = new URL(url);
  for (const name of base.searchParams.keys()) {
    const variant = new URL(url);
    variant.searchParams.set(name, payload);
    variants.push({ param: name, url: variant.toString() });
  }
  return variants;
}

async function testReflectedXss(target) {
  const results = [];
  for (const { param, url } of buildVariants(target, XSS_PAYLOAD)) {
    try {
      const resp = await fetch(url, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(15000) });
      const body = await resp.text();
      if (body.includes(XSS_PAYLOAD)) {
        results.push(makeResult('HIGH', 'XSS', `Possível XSS refletido no parâmetro '${param}'`,
          `O valor injetado foi refletido na resposta sem sanitização/encoding em: ${target}`,
          'Realize output encoding (HTML entity encoding) e considere uma CSP restritiva.', 'xss'));
      }
    } catch {
      // requisição falhou para este parâmetro; segue para o próximo
    }
  }
  return results;
}

async function testSqlErrorInjection(target) {
  const results = [];
  for (const { param, url } of buildVariants(target, SQLI_PAYLOAD)) {
    try {
      const resp = await fetch(url, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(15000) });
      const body = await resp.text();
      for (const pattern of SQL_ERROR_PATTERNS) {
        if (pattern.test(body)) {
          results.push(makeResult('CRITICAL', 'SQL Injection', `Possível SQL Injection no parâmetro '${param}'`,
            `A injeção de caractere de aspas gerou uma mensagem de erro de banco de dados em: ${target}`,
            'Utilize prepared statements / queries parametrizadas e nunca concatene entrada do usuário em SQL.', 'sqli'));
          break;
        }
      }
    } catch {
      // requisição falhou para este parâmetro; segue para o próximo
    }
  }
  return results;
}
