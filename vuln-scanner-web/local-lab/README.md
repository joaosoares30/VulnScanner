# Laboratório local de estudo (ambientes intencionalmente vulneráveis)

Este diretório sobe **duas aplicações propositalmente vulneráveis**, mantidas por
projetos de segurança reconhecidos, para você praticar exploração e resposta a
incidente em um ambiente isolado, local e legal.

## Subir o ambiente

Requer [Docker](https://docs.docker.com/get-docker/) instalado.

```bash
cd local-lab
docker compose up -d
```

- **OWASP Juice Shop** → http://localhost:3001
  Guia oficial de exploração (cobre todas as vulnerabilidades, com dicas e soluções):
  https://pwning.owasp-juice.shop/

- **DVWA (Damn Vulnerable Web Application)** → http://localhost:3002
  Login padrão: `admin` / `password`. Depois de logar, vá em **DVWA Security**
  e ajuste o nível de dificuldade (Low/Medium/High) conforme seu progresso.
  Documentação: https://github.com/digininja/DVWA

Para derrubar tudo: `docker compose down`

## Usando o VULNSCAN contra o lab

Com o lab no ar, rode o VULNSCAN normalmente (`npm start` na raiz do projeto,
depois abra http://localhost:3000) e aponte o campo "ALVO" para:

```
localhost:3001      → Juice Shop
localhost:3002       → DVWA
```

Isso te dá o ciclo completo de aprendizado: **explorar manualmente** a
vulnerabilidade seguindo o guia oficial → depois **rodar o scanner** contra o
mesmo alvo e comparar o que ele conseguiu detectar automaticamente vs. o que
só a exploração manual revela. É exatamente essa comparação que ensina tanto
ataque quanto detecção/resposta a incidente.

## Por que eu não gero os passos de exploração diretamente

O VULNSCAN (e eu, como assistente) foco em **detecção**: identificar sinais de
uma vulnerabilidade, não em fornecer os passos para explorá-la. Para a parte de
exploração, o Juice Shop e o DVWA já vêm com material didático completo e
testado, incluindo o "porquê" de cada técnica funcionar — isso costuma ensinar
mais do que uma lista de payloads isolados.
