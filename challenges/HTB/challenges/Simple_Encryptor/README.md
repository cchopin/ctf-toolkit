# Simple Encryptor - Write-up HackTheBox

![HTB Simple Encryptor](https://img.shields.io/badge/HackTheBox-Simple__Encryptor-green)![Difficulty](https://img.shields.io/badge/Difficulty-Very_Easy-brightgreen)![Category](https://img.shields.io/badge/Category-Reversing-blue)

## Résumé

| Info | Valeur |
|------|--------|
| **Flag** | `HTB{XXXXXXXXXXXXXXXXXXXXXXX}` |
| **Vulnérabilité** | Seed du PRNG stockée dans le fichier chiffré |
| **Technique** | Reverse de l'algorithme XOR + ROL avec reproduction de la séquence rand() |
| **Outils** | GDB, objdump, xxd, Python + ctypes |

---

## Table des matières

1. [Contexte](#contexte)
2. [Fichiers fournis](#fichiers-fournis)
3. [Reconnaissance du binaire](#reconnaissance-du-binaire)
4. [Analyse statique du binaire](#analyse-statique-du-binaire)
5. [Analyse du fichier chiffré](#analyse-du-fichier-chiffré)
6. [Stratégie de déchiffrement](#stratégie-de-déchiffrement)
7. [Script de déchiffrement](#script-de-déchiffrement)
8. [Points clés à retenir](#points-clés-à-retenir)

---

## Contexte

Le scénario nous indique qu'un serveur de stockage de flags a été touché par un ransomware. Le flag original a disparu, mais on dispose du fichier chiffré (`flag.enc`) ainsi que du binaire de chiffrement (`encrypt`). L'objectif est de reverser l'algorithme pour retrouver le flag en clair.

---

## Fichiers fournis

L'archive `Simple_Encryptor.zip` contient deux fichiers :

- `encrypt` : le binaire ELF 64 bits qui a chiffré le flag
- `flag.enc` : le fichier chiffré

---

## Reconnaissance du binaire

### Identification du type de fichier

```bash
file encrypt
```

C'est un binaire ELF 64 bits, linké dynamiquement.

### Fonctions importées

```bash
objdump -T encrypt
```

On y trouve notamment `fopen`, `fread`, `fwrite`, `fseek`, `ftell`, `malloc`, `fclose`, `time`, `srand`, `rand`. La présence de `srand` et `rand` est un indice fort : le chiffrement repose sur la génération de nombres pseudo-aléatoires.

---

## Analyse statique du binaire

### Ouverture dans GDB

```bash
gdb ./encrypt
gef> disas main
```

Le désassemblage complet du `main` nous permet de comprendre l'algorithme étape par étape.

### Bloc 1 : lecture du fichier source

```asm
lea    rsi,[rip+0xd59]        # mode d'ouverture ("rb")
lea    rdi,[rip+0xd55]        # nom du fichier ("flag")
call   fopen
mov    [rbp-0x28],rax         # stocke le file pointer
```

Le programme ouvre un fichier en lecture binaire. Ensuite il en détermine la taille avec le pattern classique `fseek(SEEK_END)` + `ftell` + `fseek(SEEK_SET)` :

```asm
mov    edx,0x2          # SEEK_END
mov    esi,0x0           # offset 0
call   fseek             # va à la fin du fichier
call   ftell             # récupère la position = taille du fichier
mov    [rbp-0x20],rax    # stocke la taille dans une variable locale
```

**Pseudo-C équivalent :**

```c
FILE *f = fopen("flag", "rb");
// Calcul de la taille via fseek/ftell
long size = ftell(f);
fseek(f, 0, SEEK_SET);
char *buf = malloc(size);
fread(buf, 1, size, f);
fclose(f);
```

### Bloc 2 : initialisation du générateur pseudo-aléatoire

```asm
mov    edi,0x0
call   time              # time(NULL) → retourne le timestamp UNIX actuel
mov    [rbp-0x38],eax    # stocke le timestamp (32 bits)
mov    eax,[rbp-0x38]
mov    edi,eax
call   srand             # srand(timestamp) → initialise le PRNG
```

Le programme appelle `time(NULL)` pour obtenir le nombre de secondes depuis le 1er janvier 1970 (epoch UNIX), et l'utilise comme seed pour `srand()`. Cela signifie que la séquence de nombres générée par `rand()` est entièrement déterminée par ce timestamp.

L'adresse `[rbp-0x38]` est importante : c'est là que la seed est stockée, et on la retrouvera plus tard lors de l'écriture du fichier chiffré.

### Bloc 3 : la boucle de chiffrement

La boucle itère sur chaque octet du buffer :

```asm
mov    QWORD PTR [rbp-0x30],0x0    # i = 0
jmp    <condition>                  # saute à la vérification
```

La condition de fin :

```asm
mov    rax,[rbp-0x30]     # charge i
cmp    rax,[rbp-0x20]     # compare avec size
jl     <début_boucle>     # si i < size, on continue
```

C'est un simple `for (i = 0; i < size; i++)`.

#### Première opération : XOR

```asm
call   rand               # r1 = rand()
movzx  ecx,al             # ecx = r1 & 0xFF (octet bas uniquement)
; ... chargement de buf[i] ...
xor    ecx,eax            # buf[i] = buf[i] XOR (r1 & 0xFF)
; ... écriture du résultat dans buf[i] ...
```

L'instruction `movzx ecx, al` ne prend que l'octet de poids faible (`al`) de la valeur retournée par `rand()`, ce qui donne une valeur entre 0 et 255.

Le XOR est une opération réversible : `A XOR B XOR B = A`.

#### Deuxième opération : rotation à gauche (ROL)

```asm
call   rand               # r2 = rand()
and    eax,0x7            # r2 = r2 & 7, soit une valeur entre 0 et 7
mov    ecx,eax            # ecx = nombre de bits de rotation
; ... chargement de buf[i] (résultat du XOR) ...
rol    sil,cl             # rotation à gauche de buf[i] de r2 bits
; ... écriture du résultat ...
```

`ROL` (rotate left) décale tous les bits vers la gauche, et les bits qui "sortent" à gauche reviennent à droite. L'opération inverse de ROL est ROR (rotate right) avec le même nombre de bits.

#### Résumé de la boucle en pseudo-C

```c
for (int i = 0; i < size; i++) {
    int r1 = rand();
    buf[i] = buf[i] ^ (r1 & 0xFF);    // XOR
    int r2 = rand() & 0x7;
    buf[i] = rotate_left(buf[i], r2);  // ROL
}
```

### Bloc 4 : écriture du fichier chiffré

```asm
lea    rsi,[rip+0xc3b]    # mode "wb"
lea    rdi,[rip+0xc37]    # nom "flag.enc"
call   fopen
```

Puis vient le point crucial pour le déchiffrement :

```asm
lea    rax,[rbp-0x38]     # adresse de la seed (le timestamp)
mov    edx,0x4            # 4 octets
mov    esi,0x1            # 1 élément
call   fwrite             # écrit la seed dans le fichier
```

Le programme écrit d'abord les 4 octets de la seed (le timestamp) dans le fichier de sortie, puis les données chiffrées. C'est une erreur de conception majeure : la clé est stockée avec les données chiffrées.

**Pseudo-C équivalent :**

```c
FILE *out = fopen("flag.enc", "wb");
fwrite(&seed, 1, 4, out);     // écrit la seed en premier
fwrite(buf, 1, size, out);    // écrit les données chiffrées
fclose(out);
```

---

## Analyse du fichier chiffré

```bash
xxd flag.enc
```

```
00000000: 5a35 b162 00f5 3e12 c0bd 8d16 f0fd 7599  Z5.b..>.......u.
00000010: faef 399a 4b96 21a1 4316 2371 65fb 274b  ..9.K.!.C.#qe.'K
```

Le fichier fait 37 octets au total :

| Octets | Contenu |
|--------|---------|
| 0-3 | `5a 35 b1 62` = seed en little-endian → `0x62b1355a` = `1655780698` |
| 4-36 | 33 octets de données chiffrées (cohérent avec un flag `HTB{...}`) |

Le timestamp correspond au 21 juin 2022, cohérent avec la date du challenge (22 juillet 2022).

---

## Stratégie de déchiffrement

Pour déchiffrer, il faut :

1. Extraire la seed depuis les 4 premiers octets du fichier
2. Initialiser `srand()` avec cette seed pour reproduire la même séquence de `rand()`
3. Pour chaque octet chiffré, générer les mêmes valeurs `r1` et `r2`
4. Appliquer les opérations inverses **dans l'ordre inverse** :
   - D'abord ROR (annule le ROL) avec `r2` bits
   - Puis XOR avec `r1 & 0xFF` (annule le XOR)

L'ordre est important : comme le chiffrement applique XOR puis ROL, le déchiffrement doit appliquer ROR puis XOR.

**Note importante** : L'implémentation de `rand()` varie selon les systèmes. La libc de Linux (glibc) et celle de macOS produisent des séquences différentes pour la même seed. Il faut donc utiliser la même implémentation que celle du binaire original.

---

## Script de déchiffrement

```python
import ctypes
import struct

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
    r1 = libc.rand() & 0xFF   # meme valeur utilisee pour le XOR
    r2 = libc.rand() & 0x7    # meme valeur utilisee pour le ROL

    byte = encrypted[i]

    # Inverser dans l'ordre inverse :
    # 1) ROR pour annuler le ROL
    byte = ror(byte, r2)
    # 2) XOR pour annuler le XOR
    byte = byte ^ r1

    result.append(byte)

print(f"Flag : {result.decode()}")
```

### Exécution

```bash
python3 decrypt.py
```

Le script doit être exécuté sur une machine Linux car il charge directement `libc.so.6` pour garantir la même implémentation de `rand()` que le binaire original.

---

## Points clés à retenir

```
┌─────────────────────────────────────────────────────────────┐
│                    RÉSUMÉ DU CHALLENGE                      │
├─────────────────────────────────────────────────────────────┤
│  1. La seed du PRNG est stockée dans le fichier chiffré     │
│  2. XOR est réversible : A XOR B XOR B = A                  │
│  3. ROL/ROR sont des opérations inverses                    │
│  4. srand/rand sont déterministes (même seed = même séquence│
│  5. L'ordre d'inversion est fondamental en reverse          │
└─────────────────────────────────────────────────────────────┘
```

### Failles de sécurité identifiées

| Faille | Impact |
|--------|--------|
| Seed stockée en clair | Permet de reproduire toute la séquence PRNG |
| Utilisation de rand() | PRNG faible, ne doit jamais être utilisé en crypto |
| Algorithme réversible | XOR + ROL sans clé secrète = pas de sécurité |

### Opérations de chiffrement vs déchiffrement

| Chiffrement | Déchiffrement |
|-------------|---------------|
| XOR avec r1 | ROR de r2 bits |
| ROL de r2 bits | XOR avec r1 |

---

## Fichiers

- `encrypt` : binaire de chiffrement
- `flag.enc` : fichier chiffré
- `decrypt.py` : script de déchiffrement

---
