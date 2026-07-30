import tls from 'node:tls';
import * as cheerio from 'cheerio';
import { makeResult } from './references.js';

const UA = 'VulnScannerWeb/1.0 (uso autorizado apenas)';

const HEADER_CHECKS = [
  ['strict-transport-security', 'MEDIUM', 'Ausência de HSTS',
    'Sem HSTS, navegadores podem se conectar via HTTP antes do redirecionamento, permitindo ataques de downgrade.',
    "Adicione o header 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.", 'hsts'],
  ['content-security-policy', 'MEDIUM', 'Ausência de Content-Security-Policy',
    'Sem CSP, o site fica mais vulnerável a ataques de XSS e injeção de conteúdo.',
    'Defina uma política CSP restritiva adequada à aplicação.', 'csp'],
  ['x-frame-options', 'LOW', 'Ausência de X-Frame-Options',
    'O site pode ser incorporado em um iframe de terceiros, possibilitando clickjacking.',
    "Adicione 'X-Frame-Options: DENY' ou 'SAMEORIGIN', ou use CSP frame-ancestors.", 'clickjacking'],
  ['x-content-type-options', 'LOW', 'Ausência de X-Content-Type-Options',
    'Navegadores podem tentar adivinhar o tipo de conteúdo (MIME sniffing), abrindo brechas de segurança.',
    "Adicione 'X-Content-Type-Options: nosniff'.", 'mimeSniffing'],
  ['referrer-policy', 'INFO', 'Ausência de Referrer-Policy',
    'URLs completas podem vazar para sites de terceiros via header Referer.',
    "Adicione 'Referrer-Policy: strict-origin-when-cross-origin' ou política mais restritiva.", 'referrer'],
];

const INFO_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version'];

// Caminhos comumente sensíveis: a checagem apenas verifica se ficaram
// publicamente acessíveis por engano (erro de deploy/configuração), sem
// tentar ler ou extrair o conteúdo além de confirmar o status HTTP.
const SENSITIVE_PATHS = [
  '/.git/HEAD',
  '/.git/config',
  '/.env',
  '/.env.local',
  '/wp-config.php.bak',
  '/config.php.bak',
  '/.DS_Store',
  '/backup.zip',
  '/.aws/credentials',
];

const CSRF_TOKEN_HINTS = ['csrf', 'token', 'authenticity_token', '_token', 'xsrf', 'nonce'];

export async function runPassiveScan(url) {
  const results = [];
  const target = new URL(url);
  let response;
  let html = '';

  try {
    response = await fetch(url, {
      redirect: 'follow',
      headers: { 'User-Agent': UA },
      signal: AbortSignal.timeout(15000),
    });
    html = await response.text();
  } catch (err) {
    results.push(makeResult('INFO', 'Conexão', 'Falha ao conectar',
      `Não foi possível completar a requisição HTTP: ${err.message}`,
      'Verifique se a URL está correta e acessível.'));
    return results;
  }

  results.push(...checkHeaders(response.headers));
  results.push(...checkCookies(response.headers));
  results.push(...checkInfoDisclosure(response.headers));
  results.push(...checkCsrfForms(html));

  if (target.protocol === 'https:') {
    results.push(...await checkSsl(target.hostname));
  } else {
    results.push(makeResult('HIGH', 'Transporte', 'Site não usa HTTPS',
      'A conexão inicial não é criptografada, expondo dados a interceptação (MITM).',
      'Habilite HTTPS com um certificado válido e redirecione HTTP para HTTPS.', 'transportSec'));
  }

  results.push(...await checkExposedPaths(target));
  results.push(...await checkCors(url));

  return results;
}

function checkHeaders(headers) {
  const results = [];
  for (const [header, severity, title, description, recommendation, ref] of HEADER_CHECKS) {
    if (!headers.has(header)) {
      results.push(makeResult(severity, 'Headers HTTP', title, description, recommendation, ref));
    }
  }
  return results;
}

function checkCookies(headers) {
  const results = [];
  const raw = typeof headers.getSetCookie === 'function'
    ? headers.getSetCookie()
    : (headers.get('set-cookie') ? [headers.get('set-cookie')] : []);

  for (const cookie of raw) {
    const name = cookie.split('=')[0].trim();
    const lower = cookie.toLowerCase();

    if (!lower.includes('secure')) {
      results.push(makeResult('MEDIUM', 'Cookies', `Cookie sem flag Secure: ${name}`,
        'O cookie pode ser transmitido em conexões não criptografadas.',
        "Adicione o atributo 'Secure' ao cookie.", 'session'));
    }
    if (!lower.includes('httponly')) {
      results.push(makeResult('MEDIUM', 'Cookies', `Cookie sem flag HttpOnly: ${name}`,
        'O cookie pode ser acessado via JavaScript, aumentando o impacto de um XSS.',
        "Adicione o atributo 'HttpOnly' ao cookie.", 'session'));
    }
    if (!lower.includes('samesite')) {
      results.push(makeResult('LOW', 'Cookies', `Cookie sem SameSite: ${name}`,
        'O cookie pode ser enviado em requisições cross-site, facilitando CSRF.',
        "Defina 'SameSite=Lax' ou 'SameSite=Strict' conforme o caso de uso.", 'csrf'));
    }
  }
  return results;
}

function checkInfoDisclosure(headers) {
  const results = [];
  for (const h of INFO_HEADERS) {
    const value = headers.get(h);
    if (value) {
      results.push(makeResult('INFO', 'Divulgação de Informação', `Header revela tecnologia: ${h}`,
        `Valor exposto: '${value}'. Isso facilita a identificação de versões vulneráveis conhecidas.`,
        'Remova ou ofusque esse header na configuração do servidor.', 'infoDisclosure'));
    }
  }
  return results;
}

/**
 * Verifica formulários que alteram estado (POST) em busca de um campo
 * oculto com nome típico de token anti-CSRF. É uma heurística: a ausência
 * de um campo com esses nomes não confirma a falha (o framework pode usar
 * outra defesa, como SameSite ou cabeçalhos customizados), por isso o
 * achado é reportado como severidade MEDIUM e não CRITICAL.
 */
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
        'ou dependa de cookies SameSite=Strict/Lax combinados com verificação de origem.', 'csrf'));
    }
  });

  return results;
}

/**
 * Verifica se caminhos comumente sensíveis (ex.: .git, .env, backups) ficaram
 * expostos publicamente por erro de configuração. Apenas confere o status
 * HTTP da resposta — não baixa nem interpreta o conteúdo do arquivo.
 */
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
          'fileExposure'));
      }
    } catch {
      // falha de rede pontual para este caminho; segue para o próximo
    }
  }
  return results;
}

/** Verifica configuração de CORS enviando um Origin de teste (nenhum payload malicioso). */
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
        "Nunca combine '*' com credentials: true. Use uma lista de origens permitidas explícita.", 'cors'));
    } else if (allowOrigin === testOrigin) {
      results.push(makeResult('HIGH', 'CORS',
        'CORS reflete a origem da requisição sem validação',
        `O servidor refletiu de volta a origem de teste '${testOrigin}' enviada, sem parecer validá-la ` +
        'contra uma lista de origens confiáveis.',
        'Valide a origem contra uma lista explícita de domínios permitidos antes de refleti-la no header.', 'cors'));
    }
  } catch {
    // falha de rede pontual; não é um achado, apenas segue sem reportar
  }
  return results;
}

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
            'Desabilite TLS 1.0/1.1 e SSLv3; utilize TLS 1.2 ou 1.3.', 'tls'));
        }

        const cert = socket.getPeerCertificate();
        if (cert && cert.valid_to) {
          const expiry = new Date(cert.valid_to);
          const daysLeft = Math.floor((expiry.getTime() - Date.now()) / 86400000);
          if (daysLeft < 0) {
            results.push(makeResult('CRITICAL', 'TLS', 'Certificado expirado',
              `O certificado SSL expirou em ${cert.valid_to}.`,
              'Renove o certificado imediatamente.', 'tls'));
          } else if (daysLeft < 30) {
            results.push(makeResult('MEDIUM', 'TLS', 'Certificado próximo de expirar',
              `O certificado expira em ${daysLeft} dias.`,
              'Programe a renovação do certificado.', 'tls'));
          }
        }
        socket.end();
        finish();
      }
    );

    socket.on('error', (err) => {
      results.push(makeResult('INFO', 'TLS', 'Não foi possível inspecionar o TLS',
        `Erro: ${err.message}`,
        'Verifique manualmente a configuração SSL/TLS do servidor.', 'tls'));
      finish();
    });

    socket.on('timeout', () => {
      socket.destroy();
      results.push(makeResult('INFO', 'TLS', 'Timeout ao inspecionar TLS',
        'A conexão para inspeção do certificado expirou.',
        'Verifique manualmente a configuração SSL/TLS do servidor.', 'tls'));
      finish();
    });
  });
}
