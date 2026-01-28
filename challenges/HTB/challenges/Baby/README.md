# Baby - Write-up HackTheBox

![HTB Baby](https://img.shields.io/badge/HackTheBox-Baby-green)![Difficulty](https://img.shields.io/badge/Difficulty-Very_Easy-brightgreen)![Category](https://img.shields.io/badge/Category-Reversing-blue)

## Résumé

| Info | Valeur |
|------|--------|
| **Flag** | `HTB{XXXXXXXXXXXXXXXXXXXXXXX}` |
| **Vulnérabilité** | Clé et flag visibles dans le binaire |
| **Technique** | Extraction de chaînes avec `strings`, analyse du code assembleur |
| **Outils** | strings, file, Cutter, GDB |

---

## Table des matières

1. [Reconnaissance initiale](#reconnaissance-initiale)
2. [Analyse avec strings](#analyse-avec-strings)
3. [Analyse approfondie du binaire](#analyse-approfondie-du-binaire)
4. [Concepts appris](#concepts-appris)
5. [Méthodes de résolution](#méthodes-de-résolution)

---

## Reconnaissance initiale

### Identification du type de fichier

```bash
$ file baby
baby: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, not stripped
```

**Informations obtenues :**
- Exécutable Linux 64 bits
- `not stripped` : les noms des fonctions sont accessibles

### Exécution du programme

```bash
$ ./baby
Dont run `strings` on this challenge, that is not the way!!!!
Insert key: test
Try again later.
```

Le programme :
1. Affiche un message (troll) indiquant de ne pas utiliser `strings`
2. Demande une clé
3. Refuse l'entrée

---

## Analyse avec strings

Malgré l'avertissement, une tentative s'impose :

```bash
$ strings baby
...
HTB{B4BYH        # Fragment du flag
_R3V_TH4H        # Autre fragment
TS_Ef            # Encore un
...
Dont run `strings` on this challenge, that is not the way!!!!
Insert key:
abcde122313      # Clé potentielle
Try again later.
...
```

**Observations :**
- Le flag est visible mais **fragmenté et pollué** par des octets parasites
- Une chaîne `abcde122313` apparaît - c'est probablement la clé

### Test de la clé trouvée

```bash
$ ./baby
Dont run `strings` on this challenge, that is not the way!!!!
Insert key: abcde122313
HTB{XXXXXXXXXXXXXXXXXXXXXXX}
```

**Le flag s'affiche.**

---

## Analyse approfondie du binaire

Même si le flag est obtenu, une analyse approfondie permet de comprendre le fonctionnement du programme.

### Vue d'ensemble du main dans Cutter

```
main()
  │
  ├─→ puts("Dont run strings...")
  │
  ├─→ puts("Insert key: ")
  │
  ├─→ fgets(input, 20, stdin)
  │
  ├─→ strcmp(input, "abcde122313")
  │
  └─→ Si égal : construire et afficher le flag
       Sinon  : puts("Try again later.")
```

### Code assembleur clé

```asm
; Comparaison de la clé
0x1190    lea    rsi, [0x2053]         ; Charge "abcde122313"
0x1197    lea    rdi, [rbp-0x20]       ; Entrée utilisateur
0x119a    call   strcmp                ; Compare
0x119f    test   eax, eax              ; Résultat == 0 ?
0x11a1    jne    0x11da                ; Si différent → "Try again"

; Construction du flag sur la stack
0x11a3    movabs rax, 0x594234427b425448  ; 'HTB{B4BY'
0x11ad    movabs rdx, 0x3448545f5633525f  ; '_R3V_TH4'
0x11b7    mov    [rbp-0x40], rax          ; Stocke partie 1
0x11bb    mov    [rbp-0x38], rdx          ; Stocke partie 2
0x11bf    mov    dword [rbp-0x30], 0x455f5354  ; 'TS_E'
0x11c6    mov    word [rbp-0x2c], 0x7d5a      ; 'Z}'

; Affichage
0x11cc    lea    rax, [rbp-0x40]       ; Adresse du flag
0x11d0    mov    rdi, rax
0x11d3    call   puts                  ; Affiche le flag
```

### Pourquoi le flag est "pollué" dans strings ?

La commande `strings` affiche :
```
HTB{B4BYH
_R3V_TH4H
```

Les `H` à la fin ne font pas partie du flag. Ce sont des **octets du code assembleur** qui suivent les données.

Examen de l'instruction :
```asm
0x11a3    48 b8 48 54 42 7b 42 34 42 59    movabs rax, 0x594234427b425448
```

- `48 b8` = opcode de `movabs rax`
- `48 54 42 7b 42 34 42 59` = `HTB{B4BY` en little-endian

Le `48` suivant (début de l'instruction suivante) est interprété par `strings` comme `H` (0x48 = 'H' en ASCII).

### Décodage des valeurs hexadécimales

| Hex | Octets (Little-Endian) | Texte |
|-----|------------------------|-------|
| `0x594234427b425448` | `48 54 42 7b 42 34 42 59` | `HTB{B4BY` |
| `0x3448545f5633525f` | `5f 52 33 56 5f 54 48 34` | `_R3V_TH4` |
| `0x455f5354` | `54 53 5f 45` | `TS_E` |
| `0x7d5a` | `5a 7d` | `Z}` |

**Concaténation :** `HTB{B4BY` + `_R3V_TH4` + `TS_E` + `Z}` = `HTB{XXXXXXXXXXXXXXXXXXXXXXX}`

---

## Concepts appris

### Little-Endian

Les processeurs x86/x64 stockent les nombres en **little-endian** : l'octet de poids faible en premier.

```
Valeur : 0x41424344
En mémoire : 44 43 42 41
Texte :      D  C  B  A
```

C'est pourquoi, lors de la lecture des octets de gauche à droite, le texte apparaît "à l'endroit".

### Construction de chaîne sur la stack

Au lieu de stocker le flag dans `.rodata` (section des constantes), le compilateur peut le construire dynamiquement :

```c
// Ce que le code source pourrait ressembler
char flag[24];
*(long*)&flag[0] = 0x594234427b425448;   // "HTB{B4BY"
*(long*)&flag[8] = 0x3448545f5633525f;   // "_R3V_TH4"
*(int*)&flag[16] = 0x455f5354;           // "TS_E"
*(short*)&flag[20] = 0x7d5a;             // "Z}"
puts(flag);
```

**Avantage :** Plus rapide que `strcpy()` pour les petites chaînes.
**Inconvénient :** Le flag reste visible dans le désassemblage.

### La fonction strcmp()

```c
int strcmp(const char *s1, const char *s2);
```

- Retourne `0` si les chaînes sont égales
- Retourne une valeur négative si s1 < s2
- Retourne une valeur positive si s1 > s2

En assembleur :
```asm
call   strcmp
test   eax, eax    ; eax == 0 ?
jne    fail        ; Si non-zero (différent) → échec
```

---

## Méthodes de résolution

### Méthode 1 : Strings + Test (rapide)

```bash
strings baby | grep -E "^[a-z0-9]+$"   # Rechercher des clés potentielles
# Tester abcde122313
```

### Méthode 2 : Analyse statique avec Cutter (éducatif)

1. Ouvrir le binaire dans Cutter
2. Naviguer vers `main`
3. Trouver le `strcmp` et identifier la clé comparée
4. Trouver les `movabs`/`mov` qui construisent le flag
5. Décoder les valeurs hex en ASCII

### Méthode 3 : Debugging avec GDB (avancé)

```bash
$ gdb ./baby
(gdb) break *main+126      # Juste après la construction du flag
(gdb) run
Insert key: abcde122313
(gdb) x/s $rbp-0x40        # Afficher le flag sur la stack
0x7fffffffe3c0: "HTB{XXXXXXXXXXXXXXXXXXXXXXX}"
```

---

## Méthodologie

```
1. file baby          → ELF 64-bit, not stripped
2. ./baby             → Demande une clé
3. strings baby       → Trouve "abcde122313" et fragments du flag
4. Test la clé        → Flag obtenu
5. Cutter             → Comprendre la construction du flag sur la stack
```

---
