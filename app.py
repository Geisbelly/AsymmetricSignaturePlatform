from flask import Flask, render_template, request, redirect, session, g
from database import get_db, init_db
from crypto_utils import gerar_chaves, assinar, verificar, hash_sha256
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = "chave-super-secreta-troque-em-producao"

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def login_required():
    return "user_id" in session

def agora():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ─── REGISTER ───────────────────────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    erro = None
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        senha = request.form.get("senha", "").strip()

        if not nome or not senha:
            erro = "Preencha todos os campos."
        else:
            senha_hash = hashlib.sha256(senha.encode()).hexdigest()
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO usuarios (nome, senha, criado_em) VALUES (?, ?, ?)",
                    (nome, senha_hash, agora())
                )
                db.commit()
                user_id = db.execute("SELECT id FROM usuarios WHERE nome=?", (nome,)).fetchone()["id"]
                pub, priv = gerar_chaves()
                db.execute(
                    "INSERT INTO chaves (usuario_id, publica, privada) VALUES (?, ?, ?)",
                    (user_id, pub, priv)
                )
                db.commit()
                return redirect("/login")
            except Exception:
                erro = "Nome de usuário já existe."

    return render_template("register.html", erro=erro)


# ─── LOGIN ───────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    erro = None
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        senha = request.form.get("senha", "").strip()
        senha_hash = hashlib.sha256(senha.encode()).hexdigest()

        db = get_db()
        user = db.execute(
            "SELECT * FROM usuarios WHERE nome=? AND senha=?",
            (nome, senha_hash)
        ).fetchone()

        if user:
            session["user_id"] = user["id"]
            session["user_nome"] = user["nome"]
            return redirect("/dashboard")
        else:
            erro = "Usuário ou senha inválidos."

    return render_template("login.html", erro=erro)


# ─── LOGOUT ──────────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ─── DASHBOARD ───────────────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect("/login")

    db = get_db()
    assinaturas = db.execute(
        "SELECT * FROM assinaturas WHERE usuario_id=? ORDER BY id DESC LIMIT 5",
        (session["user_id"],)
    ).fetchall()

    return render_template("dashboard.html", assinaturas=assinaturas)


# ─── ASSINAR ─────────────────────────────────────────────────────────────────
@app.route("/sign", methods=["GET", "POST"])
def sign():
    if not login_required():
        return redirect("/login")

    resultado = None
    if request.method == "POST":
        texto = request.form.get("texto", "").strip()
        if not texto:
            return render_template("sign.html", erro="Digite um texto para assinar.")

        db = get_db()
        chave = db.execute(
            "SELECT privada FROM chaves WHERE usuario_id=?",
            (session["user_id"],)
        ).fetchone()

        h = hash_sha256(texto)
        sig = assinar(texto, chave["privada"])

        db.execute(
            "INSERT INTO assinaturas (usuario_id, texto, hash_texto, assinatura, algoritmo, criado_em) VALUES (?, ?, ?, ?, ?, ?)",
            (session["user_id"], texto, h, sig, "RSA-PKCS1v15-SHA256", agora())
        )
        db.commit()

        sig_id = db.execute(
            "SELECT id FROM assinaturas WHERE usuario_id=? ORDER BY id DESC LIMIT 1",
            (session["user_id"],)
        ).fetchone()["id"]

        resultado = {
            "id": sig_id,
            "hash": h,
            "assinatura": sig[:64] + "…"
        }

    return render_template("sign.html", resultado=resultado)


# ─── VERIFY BY ID ────────────────────────────────────────────────────────────
@app.route("/verify/<int:sig_id>")
def verify_id(sig_id):
    db = get_db()
    sig = db.execute("SELECT * FROM assinaturas WHERE id=?", (sig_id,)).fetchone()

    if not sig:
        return render_template("verify.html", erro="Assinatura não encontrada.", sig_id=sig_id)

    chave = db.execute("SELECT publica FROM chaves WHERE usuario_id=?", (sig["usuario_id"],)).fetchone()
    usuario = db.execute("SELECT nome FROM usuarios WHERE id=?", (sig["usuario_id"],)).fetchone()

    valido = verificar(sig["texto"], sig["assinatura"], chave["publica"])
    resultado = "VÁLIDA" if valido else "INVÁLIDA"

    ip = request.remote_addr
    db.execute(
        "INSERT INTO logs (assinatura_id, resultado, verificado_em, ip) VALUES (?, ?, ?, ?)",
        (sig_id, resultado, agora(), ip)
    )
    db.commit()

    return render_template("verify.html",
        valido=valido,
        resultado=resultado,
        sig=sig,
        signatario=usuario["nome"],
        sig_id=sig_id
    )


# ─── VERIFY BY INPUT ─────────────────────────────────────────────────────────
@app.route("/verify", methods=["GET", "POST"])
def verify_input():
    resultado = None
    if request.method == "POST":
        modo = request.form.get("modo")

        if modo == "id":
            try:
                sig_id = int(request.form.get("sig_id", ""))
                return redirect(f"/verify/{sig_id}")
            except ValueError:
                return render_template("verify_input.html", erro="ID inválido.")

        elif modo == "manual":
            texto = request.form.get("texto", "").strip()
            assinatura_b64 = request.form.get("assinatura", "").strip()
            chave_pub = request.form.get("chave_publica", "").strip()

            valido = verificar(texto, assinatura_b64, chave_pub)
            resultado = "VÁLIDA" if valido else "INVÁLIDA"

            db = get_db()
            db.execute(
                "INSERT INTO logs (assinatura_id, resultado, verificado_em, ip) VALUES (?, ?, ?, ?)",
                (None, resultado, agora(), request.remote_addr)
            )
            db.commit()

    return render_template("verify_input.html", resultado=resultado)


# ─── MINHA CHAVE PÚBLICA ─────────────────────────────────────────────────────
@app.route("/mykey")
def mykey():
    if not login_required():
        return redirect("/login")

    db = get_db()
    chave = db.execute("SELECT publica FROM chaves WHERE usuario_id=?", (session["user_id"],)).fetchone()
    return render_template("mykey.html", chave=chave["publica"])


# ─── HISTÓRICO ───────────────────────────────────────────────────────────────
@app.route("/history")
def history():
    if not login_required():
        return redirect("/login")

    db = get_db()
    assinaturas = db.execute(
        "SELECT * FROM assinaturas WHERE usuario_id=? ORDER BY id DESC",
        (session["user_id"],)
    ).fetchall()

    return render_template("history.html", assinaturas=assinaturas)


# ─── TESTES PÚBLICOS ─────────────────────────────────────────────────────────
@app.route("/test")
def test_page():
    import base64, time

    resultados = []

    def caso(nome, descricao):
        return {"nome": nome, "descricao": descricao, "passos": [], "status": None, "duracao": None}

    def passo(c, texto, ok=None):
        c["passos"].append({"texto": texto, "ok": ok})

    # ── Bloco 1: crypto isolada ───────────────────────────────────────────────
    c = caso("Geração de chaves RSA-2048", "Gera um par pub/priv e valida o formato PEM.")
    t0 = time.time()
    try:
        pub, priv = gerar_chaves()
        passo(c, f"Chave pública gerada ({len(pub)} bytes)", True)
        passo(c, f"Chave privada gerada ({len(priv)} bytes)", True)
        passo(c, "pub contém BEGIN PUBLIC KEY", "BEGIN PUBLIC KEY" in pub)
        passo(c, "priv contém BEGIN PRIVATE KEY", "BEGIN PRIVATE KEY" in priv)
        c["status"] = "ok"
    except Exception as e:
        passo(c, f"Erro: {e}", False)
        c["status"] = "erro"
    c["duracao"] = round((time.time() - t0) * 1000)
    resultados.append(c)

    # ── Bloco 2: assinar e verificar (positivo) ───────────────────────────────
    c = caso("Assinatura válida (positivo)", "Assina um texto e verifica com a chave pública correta.")
    t0 = time.time()
    try:
        texto = "Mensagem de teste — SignVault 2025"
        sig = assinar(texto, priv)
        h = hash_sha256(texto)
        passo(c, f"Texto: \"{texto}\"")
        passo(c, f"Hash SHA-256: {h[:32]}…", True)
        passo(c, f"Assinatura Base64 gerada ({len(sig)} chars)", True)
        valido = verificar(texto, sig, pub)
        passo(c, f"verificar(texto, sig, pub) → {valido}", valido is True)
        c["status"] = "ok" if valido else "erro"
    except Exception as e:
        passo(c, f"Erro: {e}", False)
        c["status"] = "erro"
    c["duracao"] = round((time.time() - t0) * 1000)
    resultados.append(c)

    # ── Bloco 3: texto adulterado (negativo) ──────────────────────────────────
    c = caso("Texto adulterado (negativo)", "Verifica que uma alteração no texto invalida a assinatura.")
    t0 = time.time()
    try:
        texto_adulterado = texto + " [ADULTERADO]"
        valido = verificar(texto_adulterado, sig, pub)
        passo(c, f"Texto adulterado: \"{texto_adulterado}\"")
        passo(c, f"verificar(texto_adulterado, sig, pub) → {valido}", valido is False)
        c["status"] = "ok" if not valido else "erro"
    except Exception as e:
        passo(c, f"Erro: {e}", False)
        c["status"] = "erro"
    c["duracao"] = round((time.time() - t0) * 1000)
    resultados.append(c)

    # ── Bloco 4: assinatura corrompida (negativo) ─────────────────────────────
    c = caso("Assinatura corrompida (negativo)", "Corrompe bytes da assinatura e verifica que é detectado.")
    t0 = time.time()
    try:
        sig_bytes = bytearray(base64.b64decode(sig))
        sig_bytes[10] ^= 0xFF
        sig_corrompida = base64.b64encode(bytes(sig_bytes)).decode()
        valido = verificar(texto, sig_corrompida, pub)
        passo(c, "Bit-flip no byte 10 da assinatura")
        passo(c, f"verificar(texto, sig_corrompida, pub) → {valido}", valido is False)
        c["status"] = "ok" if not valido else "erro"
    except Exception as e:
        passo(c, f"Erro: {e}", False)
        c["status"] = "erro"
    c["duracao"] = round((time.time() - t0) * 1000)
    resultados.append(c)

    # ── Bloco 5: chave pública errada (negativo) ──────────────────────────────
    c = caso("Chave pública errada (negativo)", "Verifica com uma chave pública de outro par — deve falhar.")
    t0 = time.time()
    try:
        pub2, _ = gerar_chaves()
        valido = verificar(texto, sig, pub2)
        passo(c, "Novo par de chaves gerado")
        passo(c, f"verificar(texto, sig, pub2) → {valido}", valido is False)
        c["status"] = "ok" if not valido else "erro"
    except Exception as e:
        passo(c, f"Erro: {e}", False)
        c["status"] = "erro"
    c["duracao"] = round((time.time() - t0) * 1000)
    resultados.append(c)

    # ── Bloco 6: hash determinístico ─────────────────────────────────────────
    c = caso("Hash SHA-256 determinístico", "Mesmo texto sempre gera o mesmo hash; textos diferentes geram hashes diferentes.")
    t0 = time.time()
    try:
        h1 = hash_sha256("abc")
        h2 = hash_sha256("abc")
        h3 = hash_sha256("abC")
        passo(c, f"hash('abc') = {h1[:20]}…", True)
        passo(c, f"hash('abc') == hash('abc') → {h1 == h2}", h1 == h2)
        passo(c, f"hash('abc') != hash('abC') → {h1 != h3}", h1 != h3)
        c["status"] = "ok" if (h1 == h2 and h1 != h3) else "erro"
    except Exception as e:
        passo(c, f"Erro: {e}", False)
        c["status"] = "erro"
    c["duracao"] = round((time.time() - t0) * 1000)
    resultados.append(c)

    total = len(resultados)
    passou = sum(1 for r in resultados if r["status"] == "ok")

    return render_template("test.html", resultados=resultados, passou=passou, total=total)


# ─── INDEX ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if login_required():
        return redirect("/dashboard")
    return redirect("/login")


if __name__ == "__main__":
    init_db(app)
    app.run(debug=True)