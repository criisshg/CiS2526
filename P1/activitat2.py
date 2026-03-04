 # =============================================================================
# CS 2026 - Criptografia i Seguretat
# Activitat 2: Verificació del desxifratge AES-128
# Autores: Elena i Cristina
#
# No cal implementar el desxifratge; s'usa la llibreria externa 'cryptography'
# per comprovar que el text xifrat c es desxifra correctament al text clar m.
# =============================================================================

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import random

#  Recrear el mateix m i k que a l'Activitat 1 
message_str = "ElenayCristina  "
m = [ord(c) for c in message_str]

random.seed(42)
k = [random.randint(0, 255) for _ in range(16)]

#  Text xifrat obtingut a l'Activitat 1 
c = [0xc3,0x2d,0x3d,0x95,0x45,0x4d,0x47,0xf6,0x3d,0xc0,0x60,0x77,0xd2,0x09,0x75,0xa9]

print("=" * 55)
print("  ACTIVITAT 2: Verificació del desxifratge")
print("=" * 55)

print(f"\nText xifrat c     : {' '.join(f'{b:02x}' for b in c)}")
print(f"Clau k            : {' '.join(f'{b:02x}' for b in k)}")

# ── Desxifratge amb la llibreria 'cryptography' 
# S'usa AES-128 en mode ECB (el mateix mode que a l'Activitat 1).
# La llibreria implementa el desxifratge complet (InvSubBytes, InvShiftRows,
# InvMixColumns, AddRoundKey) de forma inversa a l'encriptació.

cipher    = Cipher(algorithms.AES(bytes(k)), modes.ECB(), backend=default_backend())
decryptor = cipher.decryptor()
decrypted = list(decryptor.update(bytes(c)) + decryptor.finalize())

# ─── Verificació ─────────────────────────────────────────────────────────────
print(f"\nDesxifrat         : {' '.join(f'{b:02x}' for b in decrypted)}")
print(f"Original m        : {' '.join(f'{b:02x}' for b in m)}")
print(f"\nText recuperat    : '{''.join(chr(b) for b in decrypted)}'")
print(f"Coincideix amb m  : {decrypted == m}")

if decrypted == m:
    print("\n✓ El desxifratge és correcte. La implementació de l'Activitat 1 és vàlida.")
else:
    print("\n✗ Error: el desxifratge no coincideix amb el missatge original.")
