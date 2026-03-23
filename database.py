import sqlite3
from flask import g

DATABASE = "assinador.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db(app):
    with app.app_context():
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT UNIQUE NOT NULL,
                senha TEXT NOT NULL,
                criado_em TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chaves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL,
                publica TEXT NOT NULL,
                privada TEXT NOT NULL,
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
            );

            CREATE TABLE IF NOT EXISTS assinaturas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL,
                texto TEXT NOT NULL,
                hash_texto TEXT NOT NULL,
                assinatura TEXT NOT NULL,
                algoritmo TEXT NOT NULL DEFAULT 'RSA-PKCS1v15-SHA256',
                criado_em TEXT NOT NULL,
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
            );

            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assinatura_id INTEGER,
                resultado TEXT NOT NULL,
                verificado_em TEXT NOT NULL,
                ip TEXT,
                FOREIGN KEY(assinatura_id) REFERENCES assinaturas(id)
            );
        """)
        db.commit()
        db.close()