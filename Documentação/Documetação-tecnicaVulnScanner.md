# VulnScan Web — Documentação Técnica

## 1. Visão geral

VulnScan Web é uma aplicação Node.js (Express) com interface no navegador que
executa varreduras de segurança básicas contra um site alvo. O usuário informa
uma URL na interface, escolhe o tipo de análise (passiva e/ou ativa) e recebe
um relatório com os achados, cada um classificado por severidade e acompanhado
de uma recomendação de correção e um link de referência (OWASP Cheat Sheet /
CWE).

> ⚠️ Uso apenas em sites com autorização explícita do proprietário (site
> próprio ou ambiente de pentest autorizado). Testes ativos enviam payloads de
> teste ao alvo; usá-los sem autorização pode configurar crime (Lei
> 12.737/2012 no Brasil, e legislações equivalentes em outros países).

## 2. Arquitetura

```
vuln-scanner-web/
├── package.json          # dependências: express, cheerio
├── server.js             # servidor Express + rota /api/scan
├── scanners/
│   ├── passiveScanner.js # headers, cookies, TLS, CORS, CSRF, paths sensíveis
│   ├── activeScanner.js  # crawling + testes de detecção de XSS/SQLi
│   └── references.js     # helper makeResult() + links de referência OWASP/CWE
└── public/
    ├── index.html         # formulário de varredura
    ├── app.js              # chama /api/scan via fetch e renderiza o relatório
    └── style.css
```

O front-end é JavaScript puro (sem framework): `app.js` envia um `POST` para
`/api/scan` com `{ url, passive, active }` e renderiza a lista de resultados
retornada em JSON. O navegador não pode inspecionar certificados TLS nem fazer
requisições cross-origin arbitrárias, então toda a varredura é executada no
backend Node, que não tem essas restrições.

## 3. Fluxo de uma varredura

1. Usuário preenche URL e marca "Análise passiva" e/ou "Testes ativos" na UI.
2. `app.js` faz `POST /api/scan` com o corpo `{ url, passive, active }`.
3. `server.js` normaliza a URL (adiciona `https://` se ausente, valida com
   `new URL()`).
4. Se `passive` for verdadeiro, chama `runPassiveScan(url)`.
5. Se `active` for verdadeiro, chama `runActiveScan(url)`.
6. Os resultados de ambos são concatenados e devolvidos como
   `{ target, results }` em JSON.
7. `app.js` renderiza cada item do array `results` como um cartão, com cor por
   severidade e link "Saiba mais".

## 4. Módulo `passiveScanner.js`

Não envia nenhum payload de ataque — apenas observa respostas normais do
servidor.

| Checagem | Função | O que verifica |
|---|---|---|
| HTTPS | `checkHttps` | Se o alvo responde em HTTP puro (severidade HIGH) |
| Headers de segurança | `checkHeaders` | Ausência de HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Vazamento de info | `checkInfoLeak` | Presença de `Server`, `X-Powered-By`, `X-Aspnet-Version` |
| Cookies | `checkCookieFlags` | Ausência das flags `Secure`, `HttpOnly`, `SameSite` em cada `Set-Cookie` |
| CSRF em formulários | `checkCsrfForms` | Formulários `POST` sem campo oculto com nome típico de token anti-CSRF (via `cheerio`) |
| Caminhos sensíveis | `checkExposedPaths` | Testa uma lista fixa de caminhos (`/.git/HEAD`, `/.env`, `/backup`, `/wp-config.php.bak`, etc.) e reporta os que retornam HTTP 200 — **reporta apenas a exposição, não baixa/expõe o conteúdo** |
| CORS | `checkCors` | Envia um `Origin` de teste inexistente e verifica se o servidor reflete a origem ou responde `Access-Control-Allow-Origin: *` combinado com `Access-Control-Allow-Credentials: true` |
| TLS/SSL | `checkSsl` | Conecta via `node:tls` na porta 443, verifica protocolo obsoleto (TLS 1.0/1.1/SSLv3) e validade/expiração do certificado |

Cada achado é construído com `makeResult(severidade, categoria, título,
descrição, recomendação, chave_de_referência, chave_de_exploit)`, definido em
`references.js`, que anexa o link "Saiba mais" (OWASP/CWE) correspondente.

## 5. Módulo `activeScanner.js`

Envia payloads de teste **não destrutivos**, apenas para detecção — não
extrai dados nem explora a falha.

1. **Descoberta de alvos** (`runActiveScan`): coleta a própria URL informada
   (se já tiver `?parâmetros`) e faz *crawling* de um nível nos links `<a
   href>` da página inicial, mantendo apenas os que possuem query string, até
   um limite de `MAX_TARGETS = 15`.
2. **XSS refletido** (`testReflectedXss`): para cada parâmetro GET encontrado,
   substitui o valor por uma marca única e aleatória (`<vsxXXXXXXXX>`) e
   verifica se ela volta *sem sanitização* no corpo da resposta. Não usa
   `<script>` nem qualquer payload capaz de executar/roubar dados — é só uma
   tag de marcação para provar reflexão insegura.
3. **SQL Injection por erro** (`testSqlErrorInjection`): injeta `'"` no
   parâmetro e verifica se a resposta contém alguma das mensagens de erro
   típicas de banco de dados (MySQL, PostgreSQL, Oracle `ORA-xxxxx`, SQL
   Server, SQLite). Não tenta extrair dados via `UNION SELECT` nem qualquer
   outra técnica de exfiltração — só confirma que a entrada não tratada chega
   ao banco.

## 6. Módulo `references.js`

Fornece `makeResult(severity, category, title, description, recommendation,
refKey, exploitKey)`, que monta o objeto de achado padronizado e resolve
`refKey` para uma URL de referência (OWASP Cheat Sheet Series ou entrada CWE)
mostrada como link "Saiba mais" na UI.

## 7. API HTTP

| Rota | Método | Corpo/Query | Descrição |
|---|---|---|---|
| `/api/scan` | POST | `{ url, passive, active }` | Executa `runPassiveScan` e/ou `runActiveScan` e devolve `{ target, results }` |

A interface estática (`public/`) é servida via `express.static`.

## 8. Requisitos e execução

- Node.js ≥ 18.14 (usa `fetch` e `AbortSignal.timeout` nativos do runtime).
- Dependências: `express`, `cheerio` (parsing de HTML para checagem de
  formulários e crawling de links).

```bash
npm install
npm start
# acesse http://localhost:3000
# porta customizada:
PORT=8080 npm start
```

## 9. Laboratório local para prática (`local-lab/`)

O diretório `local-lab/` sobe, via `docker-compose`, um ambiente local com
**OWASP Juice Shop** e **DVWA** — aplicações propositalmente vulneráveis, com
guias oficiais de exploração — para treinar ataque, defesa e resposta a
incidente sem depender de sites de terceiros. Ver `local-lab/README.md` para
instruções.

## 10. Observações de segurança sobre este repositório

Durante a revisão do código-fonte, identifiquei que o repositório contém, além
do scanner descrito acima, um arquivo adicional não documentado no README
(`scanners/exploiter.js`) e rotas extras em `server.js`
(`/api/exploit`, `/api/exfil`, `/api/exfil-logs`, `/api/clear-logs`) que vão
além de detecção: elas executam exploração ativa (incluindo captura de
cookies via XSS, extração de dados via SQL Injection, download de segredos de
arquivos `.env` expostos, e geração de PoC de CORS para roubo de dados de
vítimas) e um canal próprio de coleta/log dos dados capturados.

Isso está fora do escopo de uma ferramenta de *detecção* de vulnerabilidades e
representa risco caso o repositório seja distribuído ou publicado como está.
Recomendo:

- Remover `scanners/exploiter.js` e as rotas `/api/exploit`, `/api/exfil`,
  `/api/exfil-logs`, `/api/clear-logs` de `server.js` antes de publicar ou
  compartilhar o projeto;
- Se o objetivo é ensinar exploração na prática, usar exclusivamente o
  `local-lab/` (Juice Shop/DVWA), que já cumpre esse papel de forma segura e
  contida ao ambiente local;
- Adicionar ao README uma seção explícita de "não inclui exploração ativa",
  reforçando o escopo apenas de detecção, para deixar claro o limite do
  projeto para qualquer colaborador futuro.

Não detalhei aqui o funcionamento interno desses arquivos por serem, na
prática, uma ferramenta de exploração/exfiltração de dados — o que foge do
propósito documentado do projeto.
