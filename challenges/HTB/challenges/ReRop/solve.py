import struct

# Tableau 'data' extrait du binaire a l'adresse 0x4c5100
# Contient la chaine ROP qui valide le flag caractere par caractere
#
# Formule de validation pour chaque caractere :
#   (char + index) ^ 5 == expected
#
# Formule inverse :
#   char = (expected ^ 5) - index

# Paires (index, expected_value) extraites de la chaine ROP
constraints = [
    (0, 0x4d),
    (1, 0x50),
    (2, 0x41),
    (3, 0x7b),  # correction: 0x7b ^ 5 = 0x7e, 0x7e - 3 = 0x7b = '{'
    (4, 0x5e),
    (5, 0x3c),
    (6, 0x6f),
    (7, 0x51),
    (8, 0x4b),
    (9, 0x60),
    (10, 0x47),
    (11, 0x38),
    (12, 0x5e),
    (13, 0x47),
    (14, 0x67),
    (15, 0x6b),
    (16, 0x5d),
    (17, 0x44),
    (18, 0x71),
    (19, 0x27),
    (20, 0x5f),
    (21, 0x43),
    (22, 0x49),
    (23, 0x41),
    (24, 0x62),
    (25, 0x5c),
    (26, 0x7c),
    (27, 0x60),
    (28, 0x9c),
]

XOR_KEY = 5

flag = ""
for index, expected in constraints:
    char = (expected ^ XOR_KEY) - index
    flag += chr(char)

print(f"Flag: {flag}")
