# VULNSCAN — Análise de Vulnerabilidades Web

Site (Node.js + Express + JavaScript puro no front-end) que analisa
vulnerabilidades básicas em outros sites, com interface gráfica no navegador.

## ⚠️ Aviso legal

Use esta ferramenta **apenas em sites que você tem autorização explícita para
testar** (seus próprios sites, ou ambientes de pentest autorizado). O módulo
de testes ativos envia requisições com payloads de teste (não destrutivos);
aplicá-los sem autorização pode ser ilegal no Brasil (Lei 12.737/2012) e em
outros países.

## Escopo do projeto

Esta ferramenta faz **apenas detecção** de vulnerabilidades — ela identifica e
reporta indícios de falhas, mas não extrai dados, não rouba credenciais e não
explora as vulnerabilidades encontradas. Se algum arquivo do repositório fizer
algo além disso, ele está fora do escopo pretendido do projeto e deve ser
removido antes de publicar ou distribuir o código (ver seção
[Observações de segurança](#observações-de-segurança-sobre-este-repositório)).

## O que o sistema verifica

**Análise passiva** (não envia payloads): headers de segurança ausentes (HSTS,
CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy), flags de
cookies (Secure, HttpOnly, SameSite), certificado SSL/TLS (expiração e
protocolo obsoleto), divulgação de informação em headers (Server,
X-Powered-By) e ausência de HTTPS.

**Testes ativos** (envia payloads de teste, apenas detecção — não exploração):
XSS refletido (injeta uma marca única em parâmetros GET e verifica reflexão
sem sanitização) e SQL Injection por erro (injeta aspas e verifica mensagens
de erro típicas de banco de dados).

**Também verifica**: formulários POST sem token CSRF aparente, arquivos/
diretórios sensíveis expostos por erro de deploy (`.git`, `.env`, backups) e
CORS mal configurado (`Access-Control-Allow-Origin: *` combinado com
credentials, ou reflexão de origem sem validação).

Cada achado no relatório inclui um link "Saiba mais" apontando para o OWASP
Cheat Sheet ou CWE correspondente, para quem quiser aprofundar.

## Praticar exploração (ambiente próprio)

A pasta [`local-lab/`](vuln-scanner-web/local-lab/README.md) sobe um ambiente
local com **OWASP Juice Shop** e **DVWA** — aplicações propositalmente
vulneráveis com guias oficiais de exploração — pra você estudar ataque,
defesa e resposta a incidente na prática, sem depender de sites de terceiros.
Veja `local-lab/README.md`.

## Requisitos

- Node.js 18.14+ (usa `fetch` e `AbortSignal.timeout` nativos)

## Como rodar

```bash
npm install
npm start
```

Depois acesse **http://localhost:3000** no navegador.

Por padrão roda na porta 3000; para mudar, defina a variável de ambiente
`PORT`:

```bash
PORT=8080 npm start
```

## Estrutura do projeto

```
vuln-scanner-web/
├── package.json
├── server.js                    # servidor Express + rota /api/scan
├── scanners/
│   ├── passiveScanner.js        # headers, cookies, SSL/TLS, CORS, CSRF, paths
│   ├── activeScanner.js         # crawling + testes de detecção de XSS/SQLi
│   └── references.js            # monta cada achado + link OWASP/CWE
└── public/
    ├── index.html
    ├── style.css
    └── app.js                   # lógica da interface (fetch para /api/scan)
```

## Como funciona

O navegador não pode fazer requisições arbitrárias a outros domínios nem
inspecionar certificados TLS diretamente (CORS e sandboxing do browser),
então o front-end chama o backend (`POST /api/scan`), que executa as
varreduras no servidor Node e devolve o resultado em JSON para a interface
renderizar.

## Possíveis extensões futuras

- Testes adicionais de detecção (sem exploração)
- Rate limiting configurável para os testes ativos
- Exportação em PDF/HTML
- Suporte a autenticação (login) antes do scan
- Histórico de varreduras (persistência em banco de dados)

## Observações de segurança sobre este repositório

O repositório, além do scanner de detecção descrito acima, contém um arquivo
adicional (`scanners/exploiter.js`) e rotas extras em `server.js`
(`/api/exploit`, `/api/exfil`, `/api/exfil-logs`, `/api/clear-logs`) que não
fazem parte do escopo documentado: elas realizam exploração ativa e coleta de
dados capturados, o que vai além de detecção. Antes de publicar ou
compartilhar este projeto, remova esse arquivo e essas rotas — eles não devem
ser distribuídos junto com uma ferramenta de detecção de vulnerabilidades. Se
o objetivo é praticar exploração, use o [`local-lab/`](#praticar-exploração-ambiente-próprio),
que foi feito para isso de forma segura e contida ao ambiente local.

## Documentação

[Manual e Funcionamento](Documentação/manual-VulnScanner.md)

[Documentação Técnica Detalhada](Documentação/Documetação-tecnicaVulnScanner.md)
