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