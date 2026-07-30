# VULNSCAN — Análise de Vulnerabilidades Web

Site (Node.js + Express + JavaScript puro no front-end) que analisa vulnerabilidades
básicas em outros sites, com interface gráfica no navegador.

## ⚠️ Aviso legal
Use esta ferramenta **apenas em sites que você tem autorização explícita para testar**
(seus próprios sites, ou ambientes de pentest autorizado). O módulo de testes ativos
envia requisições com payloads de teste (não destrutivos); aplicá-los sem autorização
pode ser ilegal no Brasil (Lei 12.737/2012) e em outros países.

## O que o sistema verifica

**Análise passiva** (não envia payloads): headers de segurança ausentes (HSTS, CSP,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy), flags de cookies (Secure,
HttpOnly, SameSite), certificado SSL/TLS (expiração e protocolo obsoleto), divulgação
de informação em headers (Server, X-Powered-By) e ausência de HTTPS.

**Testes ativos** (envia payloads de teste, apenas detecção — não exploração):
XSS refletido (injeta uma marca única em parâmetros GET e verifica reflexão sem
sanitização) e SQL Injection por erro (injeta aspas e verifica mensagens de erro
típicas de banco de dados).

**Também verifica**: formulários POST sem token CSRF aparente, arquivos/diretórios
sensíveis expostos por erro de deploy (`.git`, `.env`, backups) e CORS mal configurado
(`Access-Control-Allow-Origin: *` combinado com credentials, ou reflexão de origem
sem validação).

Cada achado no relatório inclui um link "Saiba mais" apontando para o OWASP Cheat
Sheet ou CWE correspondente, para quem quiser aprofundar.

## Praticar exploração (ambiente próprio)

A pasta [`local-lab/`](local-lab/) sobe um ambiente local com **OWASP Juice Shop**
e **DVWA** — aplicações propositalmente vulneráveis com guias oficiais de
exploração — pra você estudar ataque, defesa e resposta a incidente na prática,
sem depender de sites de terceiros. Veja `local-lab/README.md`.

## Requisitos
- Node.js 18.14+ (usa `fetch` e `AbortSignal.timeout` nativos)

## Como rodar

```bash
npm install
npm start
```

Depois acesse **http://localhost:3000** no navegador.

Por padrão roda na porta 3000; para mudar, defina a variável de ambiente `PORT`:

```bash
PORT=8080 npm start
```

## Estrutura do projeto

```
vuln-scanner-web/
├── package.json
├── server.js                    # servidor Express + rota /api/scan
├── scanners/
│   ├── passiveScanner.js        # headers, cookies, SSL/TLS
│   └── activeScanner.js         # crawling + testes de XSS/SQLi
└── public/
    ├── index.html
    ├── style.css
    └── app.js                   # lógica da interface (fetch para /api/scan)
```

## Como funciona
O navegador não pode fazer requisições arbitrárias a outros domínios nem inspecionar
certificados TLS diretamente (CORS e sandboxing do browser), então o front-end chama
o backend (`POST /api/scan`), que executa as varreduras no servidor Node e devolve o
resultado em JSON para a interface renderizar.

## Possíveis extensões futuras
- Testes adicionais: CSRF, diretórios expostos (robots.txt, .git), CORS mal configurado
- Rate limiting configurável para os testes ativos
- Exportação em PDF/HTML
- Suporte a autenticação (login) antes do scan
- Histórico de varreduras (persistência em banco de dados)
