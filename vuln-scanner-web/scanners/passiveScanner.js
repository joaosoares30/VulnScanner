import tls from 'node:tls';
import * as cheerio from 'cheerio';
import { makeResult } from './references.js';

const UA = 'VulnScannerWeb/1.0 (uso autorizado apenas)';

const HEADER_CHECKS = [
  ['strict-transport-security', 'MEDIUM', 'Ausencia de HSTS',
    'Sem HSTS, navegadores podem se conectar via HTTP antes do redirecionamento.',
    "Adicione 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.", 'hsts', 'hsts'],
  ['content-security-policy', 'MEDIUM', 'Ausencia de Content-Security-Policy',
    'Sem CSP, o site fica mais vulneravel a XSS e injecao de conteudo.',
    'Defina uma politica CSP restritiva.', 'csp', 'csp'],
  ['x-frame-options', 'LOW', 'Ausencia de X-Frame-Options',
    'O site pode ser incorporado em iframe, possibilitando clickjacking.',
    "Adicione 'X-Frame-Options: DENY' ou 'SAMEORIGIN'.", 'clickjacking', 'clickjacking'],
  ['x-content-type-options', 'LOW', 'Ausencia de X-Content-Type-Options',
    'Navegadores podem fazer MIME sniffing, abrindo brechas de seguranca.',
    "Adicione 'X-Content-Type-Options: nosniff'.", 'mimeSniffing', 'mimeSniffing'],
  ['referrer-policy', 'INFO', 'Ausencia de Referrer-Policy',
    'URLs completas podem vazar para terceiros via header Referer.',
    "Adicione 'Referrer-Policy: strict-origin-when-cross-origin'.", 'referrer', 'referrer'],
];

const INFO_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version'];

const SENSITIVE_PATHS = [
  '/.git/config', '/.git/HEAD', '/.env', '/.env.example', '/.env.local',
  '/backup', '/backups', '/dump.sql', '/database.sql',
  '/wp-config.php.bak', '/config.php.old', '/.htaccess',
  '/admin/', '/api/', '/swagger.json', '/swagger-ui/',
  '/robots.txt', '/sitemap.xml',
];

const CSRF_TOKEN_HINTS = ['csrf', 'token', '_token', 'authenticity_token', 'xsrf', '__requestverificationtoken', 'nonce'];

function checkHeaders(respHeaders) {
  const results = [];
  for (const [header, severity, title, desc, rec, refKey, exploitKey] of HEADER_CHECKS) {
    if (!(header in respHeaders)) {
      results.push(makeResult(severity, 'Header de Seguranca', title, desc, rec, refKey, exploitKey));
    }
  }
  return results;
}

function checkInfoLeak(respHeaders) {
  const results = [];
  for (const h of INFO_HEADERS) {
    if (respHeaders[h]) {
      results.push(makeResult('INFO', 'Vazamento de Informacao',
        `Header expoe tecnologia: ${h}: ${respHeaders[h]}`,
        'O header informa a tecnologia/versao usada no servidor, auxiliando um atacante.',
        'Remova ou ofusque headers que divulguem versoes.',
        'infoDisclosure', 'infoDisclosure'));
    }
  }
  return results;
}

function checkHttps(url) {
  const results = [];
  if (url.protocol !== 'https:') {
    results.push(makeResult('HIGH', 'Transport Security', 'Site acessivel via HTTP',
      'O site respondeu em HTTP, dados trafegam sem criptografia.',
      'Redirecione todo trafego HTTP para HTTPS e implemente HSTS.',
      'transportSec', 'transportSec'));
  }
  return results;
}

function checkCookieFlags(respHeaders) {
  const results = [];
  const setCookie = respHeaders['set-cookie'];
  if (!setCookie) return results;
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const raw of cookies) {
    const name = raw.split('=')[0] || '(desconhecido)';
    const hasSecure = /;\s*secure\s*(;|$)/i.test(raw);
    const hasHttpOnly = /;\s*httponly\s*(;|$)/i.test(raw);
    const hasSameSite = /;\s*samesite=/i.test(raw);
    if (!hasSecure) {
      results.push(makeResult('MEDIUM', 'Cookie', `Cookie '${name}' sem flag Secure`,
        'O cookie pode ser enviado em HTTP, permitindo captura em MITM.',
        'Adicione flag Secure.', 'session', 'session'));
    }
    if (!hasHttpOnly) {
      results.push(makeResult('MEDIUM', 'Cookie', `Cookie '${name}' sem flag HttpOnly`,
        'O cookie pode ser acessado via JavaScript, permitindo roubo via XSS.',
        'Adicione flag HttpOnly.', 'session', 'session'));
    }
    if (!hasSameSite) {
      results.push(makeResult('LOW', 'Cookie', `Cookie '${name}' sem flag SameSite`,
        'O cookie pode ser enviado em requisicoes cross-site.',
        'Adicione SameSite=Lax ou SameSite=Strict.', 'session', 'session'));
    }
  }
  return results;
}

function checkCsrfForms(html) {
  const results = [];
  if (!html) return results;
  const $ = cheerio.load(html);
  $('form').each((_, form) => {
    const method = ($(form).attr('method') || 'get').toLowerCase();
    if (method !== 'post') return;
    const inputs = $(form).find('input[type="hidden"], input:not([type])');
    const hasToken = inputs.toArray().some((el) => {
      const name = ($(el).attr('name') || '').toLowerCase();
      return CSRF_TOKEN_HINTS.some((hint) => name.includes(hint));
    });
    if (!hasToken) {
      const action = $(form).attr('action') || '(mesma pagina)';
      results.push(makeResult('MEDIUM', 'CSRF',
        `Formulario POST sem token CSRF aparente (action: ${action})`,
        'Nao foi encontrado campo oculto com nome tipico de token anti-CSRF.',
        'GARANTA que toda requisicao que altera estado exija um token CSRF validado.',
        'csrf', 'csrf'));
    }
  });
  return results;
}

async function checkExposedPaths(target) {
  const results = [];
  for (const path of SENSITIVE_PATHS) {
    try {
      const testUrl = new URL(path, target.origin).toString();
      const resp = await fetch(testUrl, {
        headers: { 'User-Agent': UA },
        redirect: 'manual',
        signal: AbortSignal.timeout(8000),
      });
      if (resp.status === 200) {
        results.push(makeResult('HIGH', 'Exposicao de Arquivos',
          `Caminho sensivel acessivel publicamente: ${path}`,
          `O servidor retornou HTTP 200 para ${path}.`,
          'Bloqueie o acesso e remova arquivos sensiveis do diretorio publico.',
          'fileExposure', 'fileExposure'));
      }
    } catch {}
  }
  return results;
}

async function checkCors(url) {
  const results = [];
  const testOrigin = 'https://vulnscan-cors-check.invalid';
  try {
    const resp = await fetch(url, {
      headers: { 'User-Agent': UA, 'Origin': testOrigin },
      signal: AbortSignal.timeout(10000),
    });
    const allowOrigin = resp.headers.get('access-control-allow-origin');
    const allowCreds = resp.headers.get('access-control-allow-credentials');
    if (allowOrigin === '*' && allowCreds === 'true') {
      results.push(makeResult('CRITICAL', 'CORS',
        'CORS permite qualquer origem com credenciais',
        "Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true.",
        "Nunca combine '*' com credentials. Use lista explicita de origens.",
        'cors', 'cors'));
    } else if (allowOrigin === testOrigin) {
      results.push(makeResult('HIGH', 'CORS',
        'CORS reflete a origem sem validacao',
        `O servidor refletiu a origem '${testOrigin}' sem validar.`,
        'Valide a origem contra uma lista explicita antes de refletir.',
        'cors', 'cors'));
    }
  } catch {}
  return results;
}

function checkSsl(hostname) {
  return new Promise((resolve) => {
    const results = [];
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(results); } };
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, timeout: 10000 },
      () => {
        const protocol = socket.getProtocol();
        if (['TLSv1', 'TLSv1.1', 'SSLv3'].includes(protocol)) {
          results.push(makeResult('HIGH', 'TLS', `Protocolo TLS obsoleto: ${protocol}`,
            'Versoes antigas de TLS/SSL possuem vulnerabilidades conhecidas.',
            'Desabilite TLS 1.0/1.1 e SSLv3; utilize TLS 1.2 ou 1.3.',
            'tls', 'tls'));
        }
        const cert = socket.getPeerCertificate();
        if (cert && cert.valid_to) {
          const expiry = new Date(cert.valid_to);
          const daysLeft = Math.floor((expiry.getTime() - Date.now()) / 86400000);
          if (daysLeft < 0) {
            results.push(makeResult('CRITICAL', 'TLS', 'Certificado expirado',
              `O certificado SSL expirou em ${cert.valid_to}.`,
              'Renove o certificado imediatamente.', 'tls', 'tls'));
          } else if (daysLeft < 30) {
            results.push(makeResult('MEDIUM', 'TLS', 'Certificado proximo de expirar',
              `O certificado expira em ${daysLeft} dias.`,
              'Programe a renovacao.', 'tls', 'tls'));
          }
        }
        socket.end();
        finish();
      }
    );
    socket.on('error', (err) => {
      results.push(makeResult('INFO', 'TLS', 'Nao foi possivel inspecionar o TLS',
        `Erro: ${err.message}`, 'Verifique manualmente a configuracao SSL/TLS.', 'tls', null));
      finish();
    });
    socket.on('timeout', () => {
      socket.destroy();
      results.push(makeResult('INFO', 'TLS', 'Timeout ao inspecionar TLS',
        'A conexao para inspecao do certificado expirou.',
        'Verifique manualmente.', 'tls', null));
      finish();
    });
  });
}

export async function runPassiveScan(url) {
  const results = [];
  results.push(...checkHttps(url));
  try {
    const resp = await fetch(url, {
      headers: { 'User-Agent': UA },
      redirect: 'manual',
      signal: AbortSignal.timeout(15000),
    });
    const respHeaders = {};
    for (const [key, value] of resp.headers.entries()) {
      respHeaders[key.toLowerCase()] = value;
    }
    results.push(...checkHeaders(respHeaders));
    results.push(...checkInfoLeak(respHeaders));
    results.push(...checkCookieFlags(respHeaders));
    const contentType = respHeaders['content-type'] || '';
    if (contentType.includes('text/html')) {
      const html = await resp.text();
      results.push(...checkCsrfForms(html));
    }
    results.push(...await checkExposedPaths(url));
    results.push(...await checkCors(url));
  } catch (err) {
    results.push(makeResult('INFO', 'Rede', 'Falha ao acessar o alvo',
      `Nao foi possivel completar a varredura: ${err.message}`,
      'Verifique se a URL esta acessivel.', null, null));
  }
  if (url.protocol === 'https:') {
    results.push(...await checkSsl(url.hostname));
  }
  return results;
}