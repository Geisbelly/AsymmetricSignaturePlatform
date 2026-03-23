# SignVault — Assinador Digital Web

Aplicação web de assinatura digital e chat seguro com Flask + SQLite + RSA-2048.

## Fluxo geral

```
Cadastro  → gera par de chaves RSA-2048 (pub/priv) → armazena no DB
Login     → sessão autenticada
Assinar   → RSA-PKCS1v15(SHA-256) → persiste assinatura + hash + metadados
Verificar → rota pública /verify/<id> → retorna VÁLIDA / INVÁLIDA + log
Chat      → mensagem cifrada 2x (dest + remetente) + assinada → só envolvidos leem
Testes    → rota pública /test → executa suite ao vivo no navegador
```

## Como rodar

### Requisitos
- Python 3.10+
- pip

### Instalação

```bash
pip install flask cryptography
python app.py
```

Acesse: http://localhost:5000

### Docker Compose (opcional)

```yaml
# docker-compose.yml
version: "3.9"
services:
  web:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - .:/app
```

```dockerfile
# Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install flask cryptography
CMD ["python", "app.py"]
```

## Endpoints

| Método   | Rota                | Auth | Descrição                                    |
|----------|---------------------|------|----------------------------------------------|
| GET/POST | `/register`         | —    | Cadastro (gera par de chaves RSA-2048)       |
| GET/POST | `/login`            | —    | Login                                        |
| GET      | `/logout`           | ✓    | Logout                                       |
| GET      | `/dashboard`        | ✓    | Área principal                               |
| GET/POST | `/sign`             | ✓    | Assinar texto → retorna ID                   |
| GET      | `/history`          | ✓    | Histórico de assinaturas                     |
| GET      | `/mykey`            | ✓    | Exibe chave pública PEM                      |
| GET      | `/verify/<id>`      | —    | Verificar assinatura por ID                  |
| GET/POST | `/verify`           | —    | Verificar por ID ou colar dados manualmente  |
| GET      | `/chat`             | ✓    | Lista de usuários para conversar             |
| GET/POST | `/chat/<id>`        | ✓    | Conversa individual cifrada e assinada       |
| GET      | `/chat/admin/todas` | ✓    | Todas as mensagens do sistema (visão global) |
| GET      | `/test`             | —    | Suite de testes automáticos (pública)        |

## Exemplo de requisição/resposta

### POST /sign
```
Form: texto=Contrato de prestação de serviços
```
Resposta (exibe na página):
```json
{
  "id": 1,
  "hash": "a3f1b2c4d5...",
  "assinatura": "BASE64...",
  "algoritmo": "RSA-PKCS1v15-SHA256"
}
```

### GET /verify/1
```json
{
  "resultado": "VÁLIDA",
  "signatario": "alice",
  "algoritmo": "RSA-PKCS1v15-SHA256",
  "criado_em": "2025-06-10 14:32:01"
}
```

### POST /chat/2 (Alice envia para Bob)
```
Form: texto=Olá Bob, mensagem secreta!
```
O servidor executa internamente:
```
texto_cifrado     = cifrar_para(texto, pub_bob)    # só Bob decifra
texto_cifrado_rem = cifrar_para(texto, pub_alice)  # Alice também pode reler
assinatura        = assinar(texto, priv_alice)      # prova de autoria
hash_texto        = sha256(texto)
→ persiste os 4 campos na tabela mensagens
```

### GET /chat/admin/todas
Cada linha exibe para o usuário logado:
- **É o destinatário** → texto em claro + `✔ assinatura válida/inválida`
- **É o remetente** → texto em claro (decifrado via cópia própria)
- **É terceiro** → `🔒 [cifrado]` + metadados apenas

## Chat seguro — detalhes de criptografia

O chat implementa cifração dupla no modelo PGP: tanto o remetente quanto o
destinatário podem ler a mensagem, mas nenhum terceiro consegue — mesmo com
acesso direto ao banco de dados.

### Fluxo de envio

```
Alice escreve: "Olá Bob"
                    │
                    ├─► cifrar_para(texto, pub_Bob)    → texto_cifrado      (só Bob decifra)
                    ├─► cifrar_para(texto, pub_Alice)  → texto_cifrado_rem  (só Alice decifra)
                    ├─► sha256(texto)                  → hash_texto
                    └─► assinar(texto, priv_Alice)     → assinatura
                                    │
                            persiste no banco
```

### Fluxo de leitura

```
Bob abre o chat:
  decifrar_com(texto_cifrado, priv_Bob)         → texto em claro ✔
  verificar(texto, assinatura, pub_Alice)        → assinatura válida ✔

Alice reabre o chat:
  decifrar_com(texto_cifrado_rem, priv_Alice)   → texto em claro ✔

Carlos abre /chat/admin/todas:
  não é remetente nem destinatário              → vê apenas 🔒 [cifrado]
```

### Algoritmos

| Operação              | Algoritmo                          |
|-----------------------|------------------------------------|
| Geração de chaves     | RSA-2048, expoente público 65537   |
| Cifração da mensagem  | AES-256-GCM (chave aleatória)      |
| Envelope da chave AES | RSA-OAEP + MGF1-SHA256             |
| Assinatura            | RSA-PKCS1v15 + SHA-256             |
| Hash do texto         | SHA-256 hexadecimal                |
| Serialização          | PEM (SubjectPublicKeyInfo / PKCS8) |
| Transporte            | Base64                             |

## Casos de teste

Há duas formas de executar:

### 1. Via linha de comando

```bash
python tests.py
```

### 2. Via rota web (pública)

```
GET /test
```

Acesse `http://localhost:5000/test`. Os testes rodam ao vivo a cada requisição
com chaves geradas na hora e exibem tempo de execução por caso.

### Casos cobertos

| # | Caso                             | Tipo           | Resultado esperado  |
|---|----------------------------------|----------------|---------------------|
| 1 | Geração de chaves RSA-2048       | Crypto isolada | Chaves PEM válidas  |
| 2 | Assinatura + verificação correta | ✅ Positivo    | `VÁLIDA`            |
| 3 | Texto adulterado                 | ❌ Negativo    | `INVÁLIDA`          |
| 4 | Assinatura com bits corrompidos  | ❌ Negativo    | `INVÁLIDA`          |
| 5 | Chave pública de outro par       | ❌ Negativo    | `INVÁLIDA`          |
| 6 | Hash SHA-256 determinístico      | Crypto isolada | Hashes consistentes |

## Banco de dados

Arquivo: `assinador.db` (SQLite)  
Migração: `dump/schema.sql`

### Tabelas

**`usuarios`** — id, nome, senha (SHA-256), criado_em

**`chaves`** — usuario_id, publica (PEM SubjectPublicKeyInfo), privada (PEM PKCS8)

**`assinaturas`** — usuario_id, texto, hash_texto, assinatura (Base64), algoritmo, criado_em

**`mensagens`** — remetente_id, destinatario_id, texto_cifrado (para destinatário),
texto_cifrado_rem (cópia para remetente), assinatura, hash_texto, algoritmo, enviado_em, lida

**`logs`** — assinatura_id, resultado (VÁLIDA/INVÁLIDA), verificado_em, ip

## Autores

Projeto acadêmico — Segurança da Informação