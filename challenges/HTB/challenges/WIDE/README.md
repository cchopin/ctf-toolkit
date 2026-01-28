# Wide - Write-up HackTheBox

![HTB Wide](https://img.shields.io/badge/HackTheBox-Wide-green)![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen)![Category](https://img.shields.io/badge/Category-Reversing-blue)

## Résumé

| Info | Valeur |
|------|--------|
| **Flag** | `HTB{XXXXXXXXXXXXXXXXXXXXXXX}` |
| **Vulnérabilité** | Clé de déchiffrement stockée en wide characters |
| **Technique** | Extraction de chaînes UTF-16 avec `strings -e L` |
| **Outils** | strings, file, Cutter, objdump |

---

## Table des matières

1. [Reconnaissance initiale](#reconnaissance-initiale)
2. [Analyse statique](#analyse-statique)
3. [Analyse du code dans Cutter](#analyse-du-code-dans-cutter)
4. [Exploitation](#exploitation)
5. [Concepts appris](#concepts-appris)
6. [Méthodologie](#méthodologie)

---

## Reconnaissance initiale

### Identification du type de fichier

```bash
$ file wide
wide: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, not stripped
```

**Informations obtenues :**
- `ELF 64-bit` : Exécutable Linux 64 bits
- `dynamically linked` : Utilise des bibliothèques partagées
- `not stripped` : Les symboles de debug sont présents (noms des fonctions visibles)

### Exécution du programme

```bash
$ ./wide db.ex
[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
[*]                       Displaying Dimensions....                      [*]
[*]       Name       |              Code                |   Encrypted    [*]
[X] Primus           | people are objects               |     NO    [*]
[X] ## secret ##     | ## censored ##                   |    YES    [*]
...
Which dimension would you like to examine?
```

En sélectionnant l'entrée chiffrée (6) :
```
[X] That entry is encrypted - please enter your WIDE decryption key:
```

**Observation clé** : Le programme mentionne "WIDE" dans le nom de la clé.

---

## Analyse statique

### Recherche de chaînes

```bash
$ strings wide | grep -i key
[X] That entry is encrypted - please enter your WIDE decryption key:
[X]                          Key was incorrect
```

Recherche de mots de passe potentiels :
```bash
$ strings wide
...
supersecretkey  # Intéressant mais ne fonctionne pas
```

### L'indice du nom "WIDE"

Le nom du challenge et la mention de "WIDE decryption key" constituent des indices importants.

En informatique, **wide characters** désigne un encodage où chaque caractère utilise 2 octets (ou plus) au lieu d'un seul.

| Type | Encodage | Exemple pour 'A' |
|------|----------|------------------|
| ASCII (char) | 1 octet | `0x41` |
| Wide (wchar_t) | 2 octets | `0x41 0x00` |

### Extraction des wide strings

La commande `strings` standard ne trouve que les caractères ASCII. Pour les wide characters :

```bash
$ strings -e L wide    # -e L = little-endian 16-bit (wide)
sup3rs3cr3tw1d3
```

**Résultat** : Une chaîne différente apparaît : `sup3rs3cr3tw1d3`

---

## Analyse du code dans Cutter

### Fonctions importantes

L'ouverture du binaire dans Cutter révèle la fonction `menu` qui gère la logique principale.

**Fonctions C utilisées :**

| Fonction | Rôle |
|----------|------|
| `fgets()` | Lecture de l'entrée utilisateur |
| `mbstowcs()` | Conversion multi-byte string → wide string |
| `wcscmp()` | Comparaison de deux wide strings |

### Flux du programme

```
Entrée utilisateur (ASCII)
         │
         ▼
    mbstowcs()  → Conversion en wide characters
         │
         ▼
    wcscmp()    → Comparaison avec la clé stockée
         │
         ▼
   Égal ? → Déchiffrement et affichage du flag
```

### Code assembleur clé (adresse 0xce8-0xcfe)

```asm
call   mbstowcs@plt      ; Convertit l'entrée en wide
...
lea    rsi, [0x1118]     ; Charge l'adresse de la clé stockée
mov    rdi, rax          ; Entrée convertie
call   wcscmp@plt        ; Compare les deux wide strings
test   eax, eax          ; Résultat == 0 ?
jne    0xdb9             ; Si différent → "Key was incorrect"
```

### Visualisation de la clé en mémoire

Dans Cutter, à l'adresse `0x1118` (la clé), le hexdump affiche :

```
73 00 75 00 70 00 33 00 72 00 73 00 33 00 63 00 ...
s     u     p     3     r     s     3     c
```

Chaque caractère est suivi de `00` - c'est bien du wide character (UTF-16 LE).

---

## Exploitation

La clé est `sup3rs3cr3tw1d3`.

```bash
$ ./wide db.ex
Which dimension would you like to examine? 6
[X] That entry is encrypted - please enter your WIDE decryption key: sup3rs3cr3tw1d3
HTB{XXXXXXXXXXXXXXXXXXXXXXX}
```

---

## Concepts appris

### Encodage des caractères

```
ASCII "ABC" en mémoire :
41 42 43

Wide "ABC" en mémoire (UTF-16 LE) :
41 00 42 00 43 00
```

### Fonctions C pour wide characters

| ASCII | Wide | Description |
|-------|------|-------------|
| `char` | `wchar_t` | Type de donnée |
| `strcmp()` | `wcscmp()` | Comparaison |
| `strlen()` | `wcslen()` | Longueur |
| `strcpy()` | `wcscpy()` | Copie |

### Options de la commande strings

```bash
strings fichier           # Strings ASCII (défaut)
strings -e l fichier      # Strings 16-bit little-endian
strings -e L fichier      # Strings 32-bit little-endian
strings -e b fichier      # Strings 16-bit big-endian
```

---

## Méthodologie

```
1. file          → Identifier le type de binaire
2. ./programme   → Observer le comportement
3. strings       → Rechercher des indices (ASCII)
4. strings -e L  → Rechercher des wide strings
5. Cutter        → Analyser le flux du programme
6. Identifier    → mbstowcs + wcscmp = comparaison wide
7. Exploiter     → Utiliser la clé trouvée
```

---
