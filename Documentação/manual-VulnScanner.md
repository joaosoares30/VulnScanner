# MANUAL DE OPERAÇÃO E FUNCIONAMENTO

### *VulnScanner Web & Laboratório de Testes de Segurança*

## 1. Visão Geral do Sistema

Este documento descreve os procedimentos passo a passo para inicializar e
utilizar a ferramenta de escaneamento de vulnerabilidades web (*VulnScanner
Web*) e o ambiente de laboratório controlado (*Local Lab*).

**Pré-requisitos do Sistema:**

- **Node.js** (versão 16.0 ou superior)
- **npm** (*Node Package Manager*)
- **Navegador Web** moderno (Chrome, Firefox ou Edge)
- **Docker & Docker Compose** (opcional, para rodar o laboratório isolado)

## 2. Inicialização da Ferramenta Principal (Scanner Web)

### Passo A: Navegar até o diretório do projeto

```bash
cd \Users\seuUsuario\Downloads\vuln-scanner-web
cd vuln-scanner-web
```

### Passo B: Instalar as dependências do Node.js

```bash
npm install
```

### Passo C: Iniciar o servidor de aplicação

```bash
npm start
```

**Acesso Local:** Abra o seu navegador e acesse a URL: **http://localhost:3000**

## 3. Inicialização do Laboratório Local (Alvo de Testes)

O ambiente local de testes (`local-lab`) permite validar a eficácia do
scanner contra vulnerabilidades reais em um ambiente seguro e controlado.

### Passo A: Acessar o diretório do laboratório

```bash
cd local-lab
```

### Passo B: Subir o container do ambiente seguro

```bash
docker-compose up -d
```

| Módulo / Serviço | Comando de Execução | URL de Acesso Local |
|---|---|---|
| Scanner Web (Aplicação Principal) | `npm start` | http://localhost:3000 |
| Laboratório de Testes (Local Lab) | `docker-compose up -d` | http://localhost:8080 |
