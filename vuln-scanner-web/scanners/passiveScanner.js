import tls from 'node:tls';
import * as cheerio from 'cheerio';
import { makeResult } from './references.js';

const UA = 'VulnScannerWeb/1.0 (uso autorizado apenas)';

const HEADER_CHECKS = [
  ['strict-transport-security', 'MEDIUM', 'Ausência de HSTS',
    'Sem HSTS, navegadores podem se conectar via HTTP antes do redirecionamento, permitindo ataques de downgrade.',
    "Adicione o header 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.", 'hsts', 'hsts'],
  ['content-security-policy', 'MEDIUM', 'Ausência de Content-Security-Policy',
    'Sem CSP, o site fica mais vulnerável a ataques de XSS e injeção de conteúdo.',
    'Defina uma política CSP restritiva adequada à aplicação.', 'csp', 'csp'],
  ['x-frame-options', 'LOW', 'Ausência de X-Frame-Options',
    'O site pode ser incorporado em um iframe de terceiros, possibilitando clickjacking.',
    "Adicione 'X-Frame-Options: DENY' ou 'SAMEORIGIN', ou use CSP frame-ancestors.", 'clickjacking', 'clickjacking'],
  ['x-content-type-options', 'LOW', 'Ausência de X-Content-Type-Options',
    'Navegadores podem tentar adivinhar o tipo de conteúdo (MIME sniffing), abrindo brechas de segurança.',
    "Adicione 'X-Content-Type-Options: nosniff'.", 'mimeSniffing', 'mimeSniffing'],
  ['referrer-policy', 'INFO', 'Ausência de Referrer-Policy',
    'URLs completas podem vazar para sites de terceiros via header Referer.',
    "Adicione 'Referrer-Policy: strict-origin-when-cross-origin' ou política mais restritiva.", 'referrer', 'referrer'],
];

const INFO_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version'];

const SENSITIVE_PATHS = [
  '/.git/config', '/.env', '/.env.example', '/.env.local',
  '/backup', '/backups', '/dump.sql', '/database.sql',
  '/wp-config.php.bak', '/config.php.old', '/.htaccess',
  '/admin/', '/api/', '/swagger.json', '/swagger-ui/',
  '/robots.txt', '/sitemap.xml',
];

const CSRF_TOKEN_HINTS = [
  'csrf', 'token', '_token', 'authenticity_token',
  'xsrf', '__requestverificationtoken', 'nonce',
];

// ---- Headers de segurança ----
function checkHeaders(respHeaders) {
  const results = [];
  for (const [header, severity, title, desc, rec, refKey, exploitKey] of HEADER_CHECKS) {
    if (!(header in respHeaders)) {
      results.push(makeResult(severity, 'Header de Segurança', title, desc, rec, refKey, exploitKey));
    }
  }
  return results;
}

// ---- Vazamento de informação em headers ----
function checkInfoLeak(respHeaders) {
  const results = [];
  for (const h of INFO_HEADERS) {
    if (respHeaders[h]) {
      const value = respHeaders[h];
      results.push(makeResult('INFO', 'Vazamento de Informação',
        `Header expõe tecnologia: ${h}: ${value}`,
        'O header informa a tecnologia/versão usada no servidor, auxiliando um atacante a direcionar exploits.',
        'Remova ou ofusque headers que divulguem versões de servidor/framework.',
        'infoDisclosure', 'infoDisclosure'));
    }
  }
  return results;
}

// ---- HTTPS ----
function checkHttps(url) {
  const results = [];
  if (url.protocol !== 'https:') {
    results.push(makeResult('HIGH', 'Transport Security', 'Site acessível via HTTP',
      'O site respondeu em HTTP, o que significa que dados trafegam sem criptografia.',
      'Redirecione todo tráfego HTTP para HTTPS e implemente HSTS.',
      'transportSec', 'transportSec'));
  }
  return results;
}

// ---- Cookies (Set-Cookie) ----
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
        'O cookie pode ser enviado em conexões HTTP, permitindo captura em MITM.',
        'Adicione flag Secure.', 'session', 'session'));
    }
    if (!hasHttpOnly) {
      results.push(makeResult('MEDIUM', 'Cookie', `Cookie '${name}' sem flag HttpOnly`,
        'O cookie pode ser acessado via JavaScript, permitindo roubo via XSS.',
        'Adicione flag HttpOnly.', 'session', 'session'));
    }
    if (!hasSameSite) {
      results.push(makeResult('LOW', 'Cookie', `Cookie '${name}' sem flag SameSite`,
        'O cookie pode ser enviado em requisições cross-site, aumentando risco de CSRF.',
        'Adicione SameSite=Lax ou SameSite=Strict.', 'session', 'session'));
    }
  }
  return results;
}

// ---- CSRF em formulários ----
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
      const action = $(form).attr('action') || '(mesma página)';
      results.push(makeResult('MEDIUM', 'CSRF',
        `Formulário POST sem token CSRF aparente (action: ${action})`,
        'Não foi encontrado um campo oculto com nome típico de token anti-CSRF neste formulário. ' +
        'Isso não confirma a vulnerabilidade — o framework pode usar outra proteção (ex.: cookie SameSite, ' +
        'cabeçalho customizado validado no backend) — mas merece verificação manual.',
        'Garanta que toda requisição que altera estado exija um token CSRF validado no servidor, ' +
        'ou dependa de cookies SameSite=Strict/Lax combinados com verificação de origem.',
        'csrf', 'csrf'));
    }
  });

  return results;
}

// ---- Caminhos expostos ----
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
        results.push(makeResult('HIGH', 'Exposição de Arquivos',
          `Caminho sensível acessível publicamente: ${path}`,
          `O servidor retornou HTTP 200 para ${path}, indicando que esse arquivo/diretório ` +
          'pode estar publicamente acessível por erro de configuração de deploy.',
          'Bloqueie o acesso a esse caminho no servidor web e remova arquivos sensíveis do diretório público.',
          'fileExposure', 'fileExposure'));
      }
    } catch {
      // falha de rede pontual para este caminho; segue para o próximo
    }
  }
  return results;
}

// ---- CORS ----
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
        "O servidor respondeu com 'Access-Control-Allow-Origin: *' junto de " +
        "'Access-Control-Allow-Credentials: true', uma combinação inválida e perigosa que " +
        'pode permitir que qualquer site leia respostas autenticadas.',
        "Nunca combine '*' com credentials: true. Use uma lista de origens permitidas explícita.",
        'cors', 'cors'));
    } else if (allowOrigin === testOrigin) {
      results.push(makeResult('HIGH', 'CORS',
        'CORS reflete a origem da requisição sem validação',
        `O servidor refletiu de volta a origem de teste '${testOrigin}' enviada, sem parecer validá-la ` +
        'contra uma lista de origens confiáveis.',
        'Valide a origem contra uma lista explícita de domínios permitidos antes de refleti-la no header.',
        'cors', 'cors'));
    }
  } catch {
    // falha de rede pontual; não é um achado, apenas segue sem reportar
  }
  return results;
}

// ---- SSL/TLS ----
function checkSsl(hostname) {
  return new Promise((resolve) => {
    const results = [];
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve(results);
    };

    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, timeout: 10000 },
      () => {
        const protocol = socket.getProtocol();
        if (['TLSv1', 'TLSv1.1', 'SSLv3'].includes(protocol)) {
          results.push(makeResult('HIGH', 'TLS', `Protocolo TLS obsoleto: ${protocol}`,
            'Versões antigas de TLS/SSL possuem vulnerabilidades conhecidas.',
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
            results.push(makeResult('MEDIUM', 'TLS', 'Certificado próximo de expirar',
              `O certificado expira em ${daysLeft} dias.`,
              'Programe a renovação do certificado.', 'tls', 'tls'));
          }
        }
        socket.end();
        finish();
      }
    );

    socket.on('error', (err) => {
      results.push(makeResult('INFO', 'TLS', 'Não foi possível inspecionar o TLS',
        `Erro: ${err.message}`,
        'Verifique manualmente a configuração SSL/TLS do servidor.', 'tls', null));
      finish();
    });

    socket.on('timeout', () => {
      socket.destroy();
      results.push(makeResult('INFO', 'TLS', 'Timeout ao inspecionar TLS',
        'A conexão para inspeção do certificado expirou.',
        'Verifique manualmente a configuração SSL/TLS do servidor.', 'tls', null));
      finish();
    });
  });
}

// ---- Função principal de exportação ----
export async function runPassiveScan(url) {
  const results = [];

  // HTTPS check
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
      `Não foi possível completar a varredura passiva: ${err.message}`,
      'Verifique se a URL está acessível e se o servidor não está bloqueando o scanner.',
      null, null));
  }

  // SSL check (só para HTTPS)
  if (url.protocol === 'https:') {
    results.push(...await checkSsl(url.hostname));
  }

  return results;
}