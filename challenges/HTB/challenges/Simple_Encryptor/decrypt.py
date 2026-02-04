import ctypes
import struct
import sys

# Charger la libc pour utiliser les memes srand/rand que le binaire C
libc = ctypes.CDLL("libc.so.6")


def ror(byte, n):
    """Rotation a droite de n bits sur un octet (inverse de ROL)"""
    n = n % 8
    return ((byte >> n) | (byte << (8 - n))) & 0xFF


# Lire le fichier chiffre
with open("flag.enc", "rb") as f:
    data = f.read()

# Les 4 premiers octets sont la seed (timestamp en little-endian)
seed = struct.unpack("<I", data[:4])[0]
encrypted = data[4:]

print(f"Seed (timestamp) : {seed} (0x{seed:08x})")
print(f"Taille des donnees chiffrees : {len(encrypted)} octets")

# Initialiser le generateur avec la meme seed
libc.srand(seed)

# Dechiffrer chaque octet en inversant les operations
result = bytearray()
for i in range(len(encrypted)):
    # Reproduire les memes appels rand() que le chiffrement
    r1 = libc.rand() & 0xFF  # utilise pour le XOR
    r2 = libc.rand() & 0x7  # utilise pour le ROL

    byte = encrypted[i]

    # Inverser dans l'ordre inverse :
    # 1) ROR pour annuler le ROL
    byte = ror(byte, r2)
    # 2) XOR pour annuler le XOR
    byte = byte ^ r1

    result.append(byte)

print(f"Flag : {result.decode('utf-8', errors='replace')}")
