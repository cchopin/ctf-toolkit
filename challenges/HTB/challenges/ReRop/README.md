# ReRop - Write-up HackTheBox

![HTB ReRop](https://img.shields.io/badge/HackTheBox-ReRop-green)![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange)![Category](https://img.shields.io/badge/Category-Reversing-blue)

## Resume

| Info | Valeur |
|------|--------|
| **Flag** | `HTB{XXXXXXXXXXXXXXXXXXXXXXX}` |
| **Technique** | Analyse d'une chaine ROP utilisee comme mecanisme de validation |
| **Mecanisme** | Stack pivot vers un tableau de gadgets ROP qui valident chaque caractere |
| **Outils** | objdump, GDB, Python |

---

## Table des matieres

1. [Contexte](#contexte)
2. [Fichiers fournis](#fichiers-fournis)
3. [Reconnaissance du binaire](#reconnaissance-du-binaire)
4. [Analyse de main](#analyse-de-main)
5. [Analyse de la fonction check](#analyse-de-la-fonction-check)
6. [Comprendre le stack pivot](#comprendre-le-stack-pivot)
7. [Identification des gadgets ROP](#identification-des-gadgets-rop)
8. [Analyse de la chaine ROP](#analyse-de-la-chaine-rop)
9. [Formule de validation et inversion](#formule-de-validation-et-inversion)
10. [Script de resolution](#script-de-resolution)
11. [Points cles a retenir](#points-cles-a-retenir)

---

## Contexte

Le nom du challenge "ReRop" est un jeu de mots entre "Reverse" et "ROP" (Return-Oriented Programming). On nous donne un binaire qui demande un flag et le valide. La particularite : la validation n'est pas implementee de maniere classique mais via une **chaine ROP** stockee dans les donnees du programme.

---

## Fichiers fournis

- `rerop` : binaire ELF 64-bit, statiquement linke

---

## Reconnaissance du binaire

### Identification

```bash
file rerop
```

```
rerop: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),
statically linked, not stripped
```

| Propriete | Signification |
|-----------|---------------|
| **statically linked** | Toutes les librairies sont incluses dans le binaire (pas de dependances externes) |
| **not stripped** | Les noms de fonctions sont conserves |
| **~911 Ko** | Taille importante pour un crackme, typique d'un binaire statique |

Le fait que le binaire soit **statiquement linke** est un indice important : cela fournit un grand nombre de gadgets ROP utilisables.

### Chaines de caracteres

```bash
strings rerop | grep -i "flag\|enter\|wrong\|correct"
```

```
Enter the flag:
```

### Fonctions

```bash
nm rerop | grep " T " | head -20
```

On identifie deux fonctions principales :
- `main` : point d'entree
- `check` : fonction de validation

---

## Analyse de main

```bash
objdump -d -M intel rerop | grep -A 100 "<main>:"
```

Le `main` fait essentiellement :

1. Affiche `"Enter the flag: "`
2. Lit l'entree utilisateur dans un buffer
3. Appelle `check(data)` ou `data` est un tableau global
4. Selon le retour, affiche un message de succes ou d'echec

**Pseudo-C :**

```c
int main() {
    char buf[64];
    printf("Enter the flag: ");
    fgets(buf, 64, stdin);
    check(data);  // data est un tableau global a 0x4c5100
    return 0;
}
```

---

## Analyse de la fonction check

```bash
objdump -d -M intel rerop | grep -A 10 "<check>:"
```

```asm
00000000004017b5 <check>:
  4017b9: lea rsp, [rdi]    ; rsp = adresse du tableau 'data'
  4017bc: ret                ; pop rip depuis le nouveau rsp -> commence la chaine ROP
```

La fonction est extremement courte : **seulement 2 instructions**. C'est un **stack pivot**.

---

## Comprendre le stack pivot

### Qu'est-ce qu'un stack pivot ?

Normalement, `rsp` pointe vers la pile du programme. L'instruction `lea rsp, [rdi]` remplace la pile par le tableau `data` passe en argument.

Quand `ret` s'execute ensuite, le processeur :
1. Lit la valeur a l'adresse pointee par `rsp` (qui est maintenant `data[0]`)
2. Saute a cette adresse
3. Incremente `rsp` de 8

C'est le debut d'une **chaine ROP** : chaque adresse dans le tableau pointe vers un petit bout de code (un "gadget") qui se termine par `ret`, enchainant automatiquement vers le gadget suivant.

### Visualisation

```
Avant le pivot :                 Apres le pivot :
┌──────────┐                    ┌──────────┐
│  stack   │ <-- rsp            │  data    │ <-- rsp (nouveau)
│  normale │                    │ 0x450ec7 │ --> pop rax; ret
│          │                    │ 0x000005 │ --> valeur pour rax
│          │                    │ 0x401eef │ --> pop rdi; ret
│          │                    │   ...    │ --> etc.
└──────────┘                    └──────────┘
```

---

## Identification des gadgets ROP

Le binaire statique contient de nombreux gadgets. Ceux utilises par la chaine :

| Adresse | Gadget | Role |
|---------|--------|------|
| `0x450ec7` | `pop rax; ret` | Charge une valeur dans rax |
| `0x401eef` | `pop rdi; ret` | Charge une valeur dans rdi |
| `0x409f1e` | `pop rsi; ret` | Charge une valeur dans rsi |
| `0x458142` | `pop rdx; ret` | Charge une valeur dans rdx |
| `0x41aab6` | `syscall; ret` | Execute un appel systeme |
| `0x451ff0` | `add rdi, rax; ret` | Addition rdi += rax |
| `0x451fec` | `sub rdi, rax; ret` | Soustraction rdi -= rax |
| `0x451ff8` | `xor rdi, rax; ret` | XOR rdi ^= rax |
| `0x451fe8` | `mov rax, rdi; ret` | Copie rdi dans rax |
| `0x451fe0` | `mov rdi, rax; ret` | Copie rax dans rdi |
| `0x45202f` | `movzx rax, byte [rax]; ret` | Charge un octet depuis la memoire |

Ces gadgets forment un jeu d'instructions simplifie capable de :
- Charger des valeurs
- Faire de l'arithmetique (add, sub, xor)
- Lire la memoire
- Effectuer des appels systeme

---

## Analyse de la chaine ROP

### Schema de validation par caractere

Pour chaque caractere du flag a la position `index`, la chaine ROP execute cette sequence :

```
1. pop rdi, buf + index        ; rdi pointe vers buf[index]
2. mov rax, rdi                ; rax = adresse de buf[index]
3. movzx rax, byte [rax]       ; rax = valeur de buf[index]
4. mov rdi, rax                ; rdi = buf[index]
5. pop rax, index              ; rax = index de position
6. add rdi, rax                ; rdi = buf[index] + index
7. pop rax, 5                  ; rax = 5 (cle XOR)
8. xor rdi, rax                ; rdi = (buf[index] + index) ^ 5
9. pop rax, expected           ; rax = valeur attendue
10. sub rdi, rax               ; rdi = ((buf[index] + index) ^ 5) - expected
```

Si `rdi == 0` apres la soustraction, le caractere est correct. La variable `rdx` accumule les resultats (si un caractere echoue, `rdx` devient non-nul).

### Formule de validation

```
(char + index) ^ 5 == expected
```

Ou :
- `char` : le caractere du flag a la position `index`
- `index` : la position (0, 1, 2, ...)
- `5` : la cle XOR constante
- `expected` : la valeur attendue stockee dans la chaine ROP

### Ordre de verification

Les caracteres ne sont pas verifies dans l'ordre sequentiel. C'est une technique classique pour compliquer l'analyse statique. Il faut extraire chaque paire `(index, expected)` depuis le tableau `data`.

---

## Formule de validation et inversion

### Chiffrement (ce que fait le binaire)

```
encrypted = (char + index) ^ 5
```

### Dechiffrement (ce qu'on fait pour retrouver le flag)

```
char = (expected ^ 5) - index
```

### Exemple pour le premier caractere

```
index = 0, expected = 0x4d
char = (0x4d ^ 5) - 0 = 0x48 = 'H'
```

### Valeurs extraites

| Index | Expected | `^ 5` | `- index` | Char |
|-------|----------|-------|-----------|------|
| 0 | 0x4d | 0x48 | 0x48 | H |
| 1 | 0x50 | 0x55 | 0x54 | T |
| 2 | 0x41 | 0x44 | 0x42 | B |
| 3 | 0x7b | 0x7e | 0x7b | { |
| 4 | 0x5e | 0x5b | 0x57 | W |
| ... | ... | ... | ... | ... |

---

## Script de resolution

```python
# Paires (index, expected_value) extraites de la chaine ROP
constraints = [
    (0, 0x4d),  (1, 0x50),  (2, 0x41),  (3, 0x7b),
    (4, 0x5e),  (5, 0x3c),  (6, 0x6f),  (7, 0x51),
    (8, 0x4b),  (9, 0x60),  (10, 0x47), (11, 0x38),
    (12, 0x5e), (13, 0x47), (14, 0x67), (15, 0x6b),
    (16, 0x5d), (17, 0x44), (18, 0x71), (19, 0x27),
    (20, 0x5f), (21, 0x43), (22, 0x49), (23, 0x41),
    (24, 0x62), (25, 0x5c), (26, 0x7c), (27, 0x60),
    (28, 0x9c),
]

XOR_KEY = 5

flag = ""
for index, expected in constraints:
    char = (expected ^ XOR_KEY) - index
    flag += chr(char)

print(f"Flag: {flag}")
```

### Execution

```bash
python3 solve.py
```

---

## Points cles a retenir

```
┌─────────────────────────────────────────────────────────────┐
│                    RESUME DU CHALLENGE                      │
├─────────────────────────────────────────────────────────────┤
│  1. Un stack pivot redirige rsp vers un tableau de donnees  │
│  2. Ce tableau contient une chaine ROP complete             │
│  3. Les gadgets forment un mini-processeur (add, xor, sub)  │
│  4. Chaque caractere est valide par (char+index) ^ 5        │
│  5. L'inversion est directe : char = (expected ^ 5) - index │
└─────────────────────────────────────────────────────────────┘
```

### Concepts cles

| Concept | Description |
|---------|-------------|
| **Stack pivot** | Technique qui redirige le pointeur de pile vers une zone controlee |
| **Chaine ROP** | Suite d'adresses de gadgets executees sequentiellement via `ret` |
| **Gadget** | Petit fragment de code existant termine par `ret` |
| **Binaire statique** | Inclut toute la libc, fournissant un vaste choix de gadgets |
| **Validation par accumulation** | `rdx` accumule les erreurs, un seul echec invalide tout |

### Pourquoi c'est malin

Le challenge est astucieux car la validation n'apparait nulle part dans le code classique : pas de `cmp` dans `check`, pas de boucle visible. Tout est encode dans les **donnees** du programme, executees comme du code via ROP. Un desassembleur classique ne montre que 2 instructions dans `check`, alors que la vraie logique se cache dans le tableau `data`.

---

## Fichiers

- `rerop` : binaire du challenge
- `solve.py` : script de resolution

---
