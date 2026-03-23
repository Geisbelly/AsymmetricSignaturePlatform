"""
Casos de teste: assinatura digital
- Teste 1: validação positiva (assinatura correta)
- Teste 2: validação negativa (texto adulterado)
- Teste 3: validação negativa (assinatura adulterada)
- Teste 4: chave errada
"""

import sys
sys.path.insert(0, ".")
from crypto_utils import gerar_chaves, assinar, verificar, hash_sha256

def separador(titulo):
    print(f"\n{'='*50}")
    print(f"  {titulo}")
    print('='*50)

def checar(resultado, esperado, desc):
    ok = resultado == esperado
    simbolo = "✔" if ok else "❌"
    status = "PASSOU" if ok else "FALHOU"
    print(f"  {simbolo} {desc}: {status}")
    return ok

# ── Setup ─────────────────────────────────────────────────────────────────────
pub, priv = gerar_chaves()
texto_original = "Contrato de prestação de serviços — versão final"
texto_adulterado = texto_original + " [ADULTERADO]"

assinatura = assinar(texto_original, priv)
hash_original = hash_sha256(texto_original)

passou = 0
total = 0

# ── TESTE 1: positivo ─────────────────────────────────────────────────────────
separador("TESTE 1 — Validação positiva")
print(f"  Texto:      {texto_original}")
print(f"  Hash:       {hash_original[:32]}…")
print(f"  Assinatura: {assinatura[:40]}…")

resultado = verificar(texto_original, assinatura, pub)
total += 1
if checar(resultado, True, "verificar(texto_original, assinatura, pub) == True"):
    passou += 1

# ── TESTE 2: negativo — texto adulterado ──────────────────────────────────────
separador("TESTE 2 — Validação negativa (texto adulterado)")
print(f"  Texto adulterado: {texto_adulterado}")

resultado = verificar(texto_adulterado, assinatura, pub)
total += 1
if checar(resultado, False, "verificar(texto_adulterado, assinatura, pub) == False"):
    passou += 1

# ── TESTE 3: negativo — assinatura corrompida ─────────────────────────────────
separador("TESTE 3 — Validação negativa (assinatura corrompida)")
import base64
sig_bytes = bytearray(base64.b64decode(assinatura))
sig_bytes[10] ^= 0xFF  # flip bits
assinatura_corrompida = base64.b64encode(bytes(sig_bytes)).decode()

resultado = verificar(texto_original, assinatura_corrompida, pub)
total += 1
if checar(resultado, False, "verificar(texto_original, assinatura_corrompida, pub) == False"):
    passou += 1

# ── TESTE 4: negativo — chave pública errada ──────────────────────────────────
separador("TESTE 4 — Validação negativa (chave pública errada)")
pub2, _ = gerar_chaves()

resultado = verificar(texto_original, assinatura, pub2)
total += 1
if checar(resultado, False, "verificar(texto_original, assinatura, pub2) == False"):
    passou += 1

# ── TESTE 5: hash SHA-256 consistente ────────────────────────────────────────
separador("TESTE 5 — Hash SHA-256 determinístico")
h1 = hash_sha256(texto_original)
h2 = hash_sha256(texto_original)
h3 = hash_sha256(texto_adulterado)

total += 1
if checar(h1 == h2, True, "hash(texto) == hash(mesmo texto)"):
    passou += 1

total += 1
if checar(h1 != h3, True, "hash(texto) != hash(texto adulterado)"):
    passou += 1

# ── Resumo ────────────────────────────────────────────────────────────────────
separador(f"RESUMO: {passou}/{total} testes passaram")
if passou == total:
    print("  🎉 Todos os testes passaram!")
else:
    print(f"  ⚠️  {total - passou} teste(s) falharam.")

print()