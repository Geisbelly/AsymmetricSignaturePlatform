from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64, hashlib


def gerar_chaves():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pub.decode(), priv.decode()


def assinar(texto, chave_privada_str):
    private_key = serialization.load_pem_private_key(
        chave_privada_str.encode(), password=None
    )
    assinatura = private_key.sign(
        texto.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(assinatura).decode()


def verificar(texto, assinatura_str, chave_publica_str):
    public_key = serialization.load_pem_public_key(chave_publica_str.encode())
    assinatura = base64.b64decode(assinatura_str)
    try:
        public_key.verify(assinatura, texto.encode(), padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def hash_sha256(texto):
    return hashlib.sha256(texto.encode()).hexdigest()


# ── Cifração híbrida: RSA-OAEP (envelope) + AES-256-GCM (payload) ────────────
# RSA-2048 só comporta ~190 bytes em OAEP — para textos longos usamos AES.
# Fluxo: gera chave AES aleatória → cifra texto com AES-GCM →
#        cifra a chave AES com RSA-OAEP da chave pública do destinatário →
#        armazena: chave_cifrada || nonce || ciphertext || tag (tudo Base64).

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, json

def cifrar_para(texto, chave_publica_str):
    """Cifra texto para o dono da chave_publica_str (RSA-OAEP + AES-256-GCM)."""
    public_key = serialization.load_pem_public_key(chave_publica_str.encode())

    # 1. Gera chave AES de 256 bits
    aes_key = os.urandom(32)
    nonce   = os.urandom(12)

    # 2. Cifra o texto com AES-GCM
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, texto.encode(), None)  # inclui tag GCM

    # 3. Cifra a chave AES com RSA-OAEP
    chave_cifrada = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    envelope = {
        "k": base64.b64encode(chave_cifrada).decode(),
        "n": base64.b64encode(nonce).decode(),
        "c": base64.b64encode(ct).decode(),
    }
    return base64.b64encode(json.dumps(envelope).encode()).decode()


def decifrar_com(envelope_b64, chave_privada_str):
    """Decifra envelope gerado por cifrar_para() usando a chave privada."""
    private_key = serialization.load_pem_private_key(
        chave_privada_str.encode(), password=None
    )
    envelope = json.loads(base64.b64decode(envelope_b64).decode())

    # 1. Decifra a chave AES com RSA-OAEP
    aes_key = private_key.decrypt(
        base64.b64decode(envelope["k"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 2. Decifra o texto com AES-GCM
    nonce  = base64.b64decode(envelope["n"])
    ct     = base64.b64decode(envelope["c"])
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct, None).decode()