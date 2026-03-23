# SignVault — Assinador Digital Web

Aplicação web de assinatura digital com Flask + SQLite + RSA-2048.

## Fluxo

```
Cadastro → gera par de chaves RSA-2048 (pub/priv) → armazena no DB
Login    → sessão autenticada
Assinar  → RSA-PKCS1v15(SHA-256) → persiste assinatura + hash + metadados
Verificar→ rota pública /verify/<id> → retorna VÁLIDA / INVÁLIDA + log
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

| Método | Rota             | Auth | Descrição                          |
|--------|------------------|------|------------------------------------|
| GET/POST | `/register`    | —    | Cadastro (gera par de chaves)      |
| GET/POST | `/login`       | —    | Login                              |
| GET      | `/logout`      | ✓    | Logout                             |
| GET      | `/dashboard`   | ✓    | Área principal                     |
| GET/POST | `/sign`        | ✓    | Assinar texto → retorna ID         |
| GET      | `/history`     | ✓    | Histórico de assinaturas           |
| GET      | `/mykey`       | ✓    | Exibe chave pública PEM            |
| GET      | `/verify/<id>` | —    | Verificar assinatura por ID        |
| GET/POST | `/verify`      | —    | Verificar por ID ou dados manuais  |

## Exemplo de requisição/resposta

### POST /sign
```
Form: texto=Contrato de prestação de serviços
```
Resposta (redirect + exibe):
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

## Casos de teste

```bash
python tests.py
```

- **Teste 1** ✔ Positivo: verifica assinatura correta → `VÁLIDA`
- **Teste 2** ✔ Negativo: texto adulterado → `INVÁLIDA`
- **Teste 3** ✔ Negativo: assinatura com bits corrompidos → `INVÁLIDA`
- **Teste 4** ✔ Negativo: chave pública errada → `INVÁLIDA`
- **Teste 5** ✔ Hash SHA-256 determinístico e sensível a alterações

## Banco de dados

Arquivo: `assinador.db` (SQLite)  
Migração: `dump/schema.sql`

### Tabelas

- `usuarios` — id, nome, senha (SHA-256), criado_em
- `chaves` — usuario_id, publica (PEM), privada (PEM PKCS8)
- `assinaturas` — usuario_id, texto, hash_texto, assinatura (Base64), algoritmo, criado_em
- `logs` — assinatura_id, resultado, verificado_em, ip

## Algoritmo

- **Geração de chaves**: RSA 2048 bits, expoente público 65537
- **Assinatura**: PKCS1v15 + SHA-256
- **Hash do texto**: SHA-256 hexadecimal
- **Serialização**: chave pública em SubjectPublicKeyInfo PEM; privada em PKCS8 PEM sem senha
- **Assinatura armazenada**: Base64 da saída RSA

## Autores

Projeto acadêmico — Segurança da Informação