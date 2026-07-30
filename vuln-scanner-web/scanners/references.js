// Referências para leitura aprofundada (OWASP Cheat Sheet Series / CWE / WSTG).
// Usadas apenas para direcionar o usuário a material de defesa e de estudo
// estruturado (ex.: PortSwigger Web Security Academy, DVWA, Juice Shop) —
// não contêm nem apontam para instruções de exploração.
export const REFS = {
  hsts: { label: 'OWASP — HTTP Strict Transport Security', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html' },
  csp: { label: 'OWASP — Content Security Policy', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html' },
  clickjacking: { label: 'OWASP — Clickjacking Defense', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html' },
  mimeSniffing: { label: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
  referrer: { label: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
  session: { label: 'OWASP — Session Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' },
  csrf: { label: 'OWASP — CSRF Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html' },
  infoDisclosure: { label: 'CWE-200 — Exposure of Sensitive Information', url: 'https://cwe.mitre.org/data/definitions/200.html' },
  fileExposure: { label: 'CWE-538 — File and Directory Information Exposure', url: 'https://cwe.mitre.org/data/definitions/538.html' },
  transportSec: { label: 'CWE-319 — Cleartext Transmission of Sensitive Information', url: 'https://cwe.mitre.org/data/definitions/319.html' },
  tls: { label: 'OWASP — Transport Layer Security', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' },
  xss: { label: 'OWASP — XSS Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' },
  sqli: { label: 'OWASP — SQL Injection Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' },
  cors: { label: 'OWASP — Cross-Origin Resource Sharing', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html' },
};

export function makeResult(severity, category, title, description, recommendation, refKey) {
  return {
    severity,
    category,
    title,
    description,
    recommendation,
    reference: refKey ? REFS[refKey] ?? null : null,
  };
}
