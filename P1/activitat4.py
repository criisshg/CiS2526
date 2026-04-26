# 
# CS 2026 - Criptografia i Seguretat
# Activitat 4: Anàlisi estadística del text xifrat
# Autores: Elena i Cristina
# 

import random
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# AES-128 (implementació pròpia, autocontinguda) 

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


def gmul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        msb = a & 0x80
        a = (a << 1) & 0xff
        if msb:
            a ^= 0x1b
        b >>= 1
    return result


def key_expansion(key):
    w = [[key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]] for i in range(4)]
    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[i // 4]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    return [[[w[rnd*4 + c][r] for c in range(4)] for r in range(4)] for rnd in range(11)]


def aes_encrypt(plaintext, key):
    """AES-128 ECB — implementació pròpia."""
    rks = key_expansion(key)
    s = [[plaintext[r + 4*c] for c in range(4)] for r in range(4)]
    s = [[s[r][c] ^ rks[0][r][c] for c in range(4)] for r in range(4)]

    for rnd in range(1, 10):
        s = [[SBOX[s[r][c]] for c in range(4)] for r in range(4)]
        s = [s[r][r:] + s[r][:r] for r in range(4)]
        ns = [[0]*4 for _ in range(4)]
        for c in range(4):
            s0,s1,s2,s3 = s[0][c],s[1][c],s[2][c],s[3][c]
            ns[0][c] = gmul(2,s0)^gmul(3,s1)^s2^s3
            ns[1][c] = s0^gmul(2,s1)^gmul(3,s2)^s3
            ns[2][c] = s0^s1^gmul(2,s2)^gmul(3,s3)
            ns[3][c] = gmul(3,s0)^s1^s2^gmul(2,s3)
        s = [[ns[r][c] ^ rks[rnd][r][c] for c in range(4)] for r in range(4)]

    s = [[SBOX[s[r][c]] for c in range(4)] for r in range(4)]
    s = [s[r][r:] + s[r][:r] for r in range(4)]
    s = [[s[r][c] ^ rks[10][r][c] for c in range(4)] for r in range(4)]
    return [s[r][c] for c in range(4) for r in range(4)]


# Generació i xifratge dels blocs 

random.seed(42)
k = [random.randint(0, 255) for _ in range(16)]   # mateixa clau que Act. 1

N_BLOCKS = 100_000
random.seed(1)

byte_counts = [0] * 256

print("Xifrant 100,000 blocs... (pot trigar uns segons)")
for _ in range(N_BLOCKS):
    pt = [random.randint(0, 255) for _ in range(16)]
    ct = aes_encrypt(pt, k)
    for b in ct:
        byte_counts[b] += 1

total_bytes    = N_BLOCKS * 16      # 1,600,000
expected_count = total_bytes / 256  # 6,250.0

# Test chi-quadrat 
# H0: la distribució dels bytes és uniforme (cada valor apareix ~6,250 vegades)
chi2 = sum((count - expected_count)**2 / expected_count for count in byte_counts)
# Valor crític per a α=0.05 i df=255 és ≈ 293.25
critical_value = 293.25

print("\n" + "=" * 55)
print("  ACTIVITAT 4: Anàlisi estadística del text xifrat")
print("=" * 55)
print(f"\nTotal de bytes analitzats      : {total_bytes:,}")
print(f"Valors possibles               : 256  (0x00–0xFF)")
print(f"Comptatge esperat per valor    : {expected_count:.2f}")
print(f"Comptatge mínim observat       : {min(byte_counts)}")
print(f"Comptatge màxim observat       : {max(byte_counts)}")
print(f"\nEstadístic chi-quadrat (χ²)    : {chi2:.4f}")
print(f"Graus de llibertat             : 255")
print(f"Valor crític (α=0.05, df=255)  : {critical_value}")

if chi2 < critical_value:
    print("\n→ NO es rebutja H₀: la distribució és compatible amb la uniforme.")
else:
    print("\n→ Es rebutja H₀: la distribució NO és uniforme.")

# Gràfics 
fig, axes = plt.subplots(1, 2, figsize=(14, 5))
x_vals = np.arange(256)

# Esquerra: freqüència per valor de byte
axes[0].bar(x_vals, byte_counts, color='steelblue', width=1.0, alpha=0.75)
axes[0].axhline(expected_count, color='red', linewidth=1.5, linestyle='--',
                label=f'Distribució uniforme ({expected_count:.0f})')
axes[0].set_xlabel("Valor del byte (0–255)", fontsize=11)
axes[0].set_ylabel("Freqüència", fontsize=11)
axes[0].set_title(f"Freqüència de cada valor de byte\n({total_bytes:,} bytes xifrats, N={N_BLOCKS:,} blocs)", fontsize=11)
axes[0].legend(fontsize=10)
axes[0].grid(axis='y', alpha=0.3)

# Dreta: desviació respecte a l'esperat
deviations = [c - expected_count for c in byte_counts]
colors_bar  = ['tomato' if d < 0 else 'steelblue' for d in deviations]
axes[1].bar(x_vals, deviations, color=colors_bar, width=1.0, alpha=0.8)
axes[1].axhline(0, color='black', linewidth=1.0)
axes[1].set_xlabel("Valor del byte (0–255)", fontsize=11)
axes[1].set_ylabel("Desviació respecte a l'esperat", fontsize=11)
axes[1].set_title(f"Desviació de la distribució uniforme\n(χ²={chi2:.2f}, valor crític={critical_value})", fontsize=11)
axes[1].legend(handles=[
    mpatches.Patch(color='steelblue', label='Per sobre la mitjana'),
    mpatches.Patch(color='tomato',    label='Per sota la mitjana'),
], fontsize=10)
axes[1].grid(axis='y', alpha=0.3)

fig.tight_layout()
fig.savefig("plot_byte_distribution.png", dpi=150)
print("\nGràfic guardat a: plot_byte_distribution.png")
