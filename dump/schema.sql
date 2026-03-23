-- dump/schema.sql
-- Migrações do banco de dados — SignVault

CREATE TABLE IF NOT EXISTS usuarios (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    nome       TEXT UNIQUE NOT NULL,
    senha      TEXT NOT NULL,         -- SHA-256 da senha
    criado_em  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chaves (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    publica    TEXT NOT NULL,         -- PEM / SubjectPublicKeyInfo
    privada    TEXT NOT NULL,         -- PEM / PKCS8 sem criptografia
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
);

CREATE TABLE IF NOT EXISTS assinaturas (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id  INTEGER NOT NULL,
    texto       TEXT NOT NULL,
    hash_texto  TEXT NOT NULL,        -- SHA-256 hex do texto
    assinatura  TEXT NOT NULL,        -- Base64 da assinatura RSA
    algoritmo   TEXT NOT NULL DEFAULT 'RSA-PKCS1v15-SHA256',
    criado_em   TEXT NOT NULL,
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
);

CREATE TABLE IF NOT EXISTS logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    assinatura_id INTEGER,            -- NULL se verificação manual
    resultado     TEXT NOT NULL,      -- 'VÁLIDA' ou 'INVÁLIDA'
    verificado_em TEXT NOT NULL,
    ip            TEXT,
    FOREIGN KEY(assinatura_id) REFERENCES assinaturas(id)
);