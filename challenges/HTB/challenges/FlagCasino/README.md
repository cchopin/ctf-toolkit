# FlagCasino - Write-up HackTheBox

![HTB FlagCasino](https://img.shields.io/badge/HackTheBox-FlagCasino-green)![Difficulty](https://img.shields.io/badge/Difficulty-Very_Easy-brightgreen)![Category](https://img.shields.io/badge/Category-Reversing-blue)

## Résumé

| Info | Valeur |
|------|--------|
| **Flag** | `HTB{XXXXXXXXXXXXXXXXXXXXXXX}` |
| **Vulnérabilité** | Utilisation de l'entrée utilisateur comme seed pour srand() |
| **Technique** | Bruteforce des caractères ASCII pour reproduire les valeurs rand() attendues |
| **Outils** | GDB/GEF, strings, Python + ctypes |

---

## Table des matières

1. [Reconnaissance initiale](#reconnaissance-initiale)
2. [Analyse du comportement](#analyse-du-comportement)
3. [Analyse statique avec GDB](#analyse-statique-avec-gdb)
4. [Compréhension de l'algorithme](#compréhension-de-lalgorithme)
5. [Extraction des valeurs attendues](#extraction-des-valeurs-attendues)
6. [Script de bruteforce](#script-de-bruteforce)
7. [Points clés à retenir](#points-clés-à-retenir)

---

## Reconnaissance initiale

### Identification du fichier

```bash
$ file casino
casino: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, not stripped
```

| Information | Signification |
|-------------|---------------|
| ELF 64-bit | Exécutable Linux 64 bits |
| not stripped | Les symboles sont conservés (noms des fonctions visibles) |
| dynamically linked | Utilise des bibliothèques partagées (libc) |

### Recherche de chaînes

```bash
$ strings casino
```

Chaînes intéressantes trouvées :

```
srand
rand
[ * CORRECT *]
[ * INCORRECT * ]
```

La présence de `srand` et `rand` indique que le programme utilise un générateur de nombres pseudo-aléatoires.

---

## Analyse du comportement

### Exécution du programme

```bash
$ ./casino
[ ** WELCOME TO ROBO CASINO **]
     ,     ,
    (\____/)
     (_oo_)
       (O)
     __||__    \)
  []/______\[] /
  / \______/ \/
 /    /__\
(\   /____\
---------------------
[*** PLEASE PLACE YOUR BETS ***]
> test
[ * INCORRECT * ]
[ *** ACTIVATING SECURITY SYSTEM - PLEASE VACATE *** ]
```

**Observations :**
- Le programme demande une entrée ("PLACE YOUR BETS")
- Si l'entrée est incorrecte, il affiche "INCORRECT" et quitte
- Il existe donc une entrée "correcte" à trouver

---

## Analyse statique avec GDB

### Désassemblage de la fonction main

```bash
$ gdb ./casino
gef> disas main
```

```asm
; Initialisation du compteur de boucle
0x5555555551b1 <+44>:    mov    DWORD PTR [rbp-0x4],0x0

; Condition de boucle : i <= 0x1d (29 en décimal, donc 30 itérations)
0x555555555258 <+211>:   mov    eax,DWORD PTR [rbp-0x4]
0x55555555525b <+214>:   cmp    eax,0x1d
0x55555555525e <+217>:   jbe    0x5555555551bd <main+56>

; Lecture d'un caractère avec scanf
0x5555555551e1 <+92>:    call   __isoc99_scanf@plt

; Utilisation du caractère comme seed pour srand
0x5555555551f5 <+112>:   movzx  eax,BYTE PTR [rbp-0x5]
0x5555555551f9 <+116>:   movsx  eax,al
0x5555555551fc <+119>:   mov    edi,eax
0x5555555551fe <+121>:   call   srand@plt

; Appel de rand()
0x555555555203 <+126>:   call   rand@plt

; Comparaison avec une valeur du tableau check
0x555555555216 <+145>:   lea    rdx,[rip+0x2e63]        # 0x555555558080 <check>
0x55555555521d <+152>:   mov    edx,DWORD PTR [rcx+rdx*1]
0x555555555220 <+155>:   cmp    eax,edx
0x555555555222 <+157>:   jne    0x555555555232 <main+173>  ; Si différent → INCORRECT
```

### Structure du programme

```
┌─────────────────────────────────────────────────────────────┐
│                    STRUCTURE DU MAIN                        │
├─────────────────────────────────────────────────────────────┤
│  1. Affiche la bannière du casino                           │
│  2. Boucle 30 fois (i = 0 à 29) :                           │
│     a. Lit UN caractère avec scanf                          │
│     b. Utilise ce caractère comme seed : srand(caractere)   │
│     c. Génère un nombre : rand()                            │
│     d. Compare avec check[i]                                │
│     e. Si différent → "INCORRECT" et exit                   │
│  3. Si les 30 comparaisons réussissent → fin normale        │
└─────────────────────────────────────────────────────────────┘
```

---

## Compréhension de l'algorithme

### Le problème de sécurité

Le programme utilise **l'entrée utilisateur directement comme seed** pour `srand()`. Cela signifie que :

1. Pour un caractère donné, `srand(caractere)` initialise toujours le PRNG de la même façon
2. L'appel `rand()` suivant retournera toujours la même valeur pour ce caractère
3. Il suffit de trouver quel caractère produit la valeur attendue

### Pseudo-code équivalent

```c
int check[30] = { /* valeurs attendues */ };

for (int i = 0; i < 30; i++) {
    char c;
    scanf("%c", &c);

    srand(c);           // Seed = le caractère entré
    int r = rand();     // Génère un nombre "aléatoire"

    if (r != check[i]) {
        puts("INCORRECT");
        exit(-2);
    }
    puts("CORRECT");
}
```

---

## Extraction des valeurs attendues

### Lecture du tableau check avec GDB

Le tableau `check` se trouve à l'adresse `0x555555558080`. On peut l'examiner avec :

```bash
gef> x/30dw 0x555555558080
0x555555558080 <check>:      608905406    183990277    286129175    128959393
0x555555558090 <check+16>:   1795081523   1322670498   868603056    677741240
0x5555555580a0 <check+32>:   1127757600   89789692     421093279    1127757600
0x5555555580b0 <check+48>:   421093279    1954323550   255697463    1633333913
0x5555555580c0 <check+64>:   1795081523   1127757600   255697463    1795081523
0x5555555580d0 <check+80>:   1633333913   677741240    89789692     988039572
0x5555555580e0 <check+96>:   114810857    1322670498   214780621    1473834340
0x5555555580f0 <check+112>:  1633333913   585743402
```

**Explication de la commande :**
- `x` = examine (examiner la mémoire)
- `/30` = 30 éléments
- `d` = afficher en décimal
- `w` = taille "word" (4 octets)

---

## Script de bruteforce

### Stratégie

Pour chaque position du flag (0 à 29) :
1. Récupérer la valeur attendue `check[i]`
2. Essayer tous les caractères ASCII affichables (32 à 126)
3. Pour chaque caractère, faire `srand(caractere)` puis `rand()`
4. Si le résultat correspond à `check[i]`, c'est le bon caractère

### Script Python

```python
import ctypes

# Charger la libc pour utiliser les mêmes srand/rand que le binaire
libc = ctypes.CDLL("libc.so.6")

# Valeurs attendues extraites avec GDB
check = [
    608905406, 183990277, 286129175, 128959393,
    1795081523, 1322670498, 868603056, 677741240,
    1127757600, 89789692, 421093279, 1127757600,
    421093279, 1954323550, 255697463, 1633333913,
    1795081523, 1127757600, 255697463, 1795081523,
    1633333913, 677741240, 89789692, 988039572,
    114810857, 1322670498, 214780621, 1473834340,
    1633333913, 585743402
]

flag = ""

# Pour chaque position du flag
for i in range(30):
    valeur_attendue = check[i]

    # Essayer tous les caractères ASCII affichables
    for caractere in range(32, 127):
        libc.srand(caractere)
        resultat = libc.rand()

        if resultat == valeur_attendue:
            flag += chr(caractere)
            break

print(f"Flag : {flag}")
```

### Exécution

```bash
$ python3 solve.py
Flag : HTB{...}
```

### Vérification

```bash
$ echo 'HTB{...}' | ./casino
[ ** WELCOME TO ROBO CASINO **]
...
[ * CORRECT *]
[ * CORRECT *]
...
```

---

## Points clés à retenir

```
┌─────────────────────────────────────────────────────────────┐
│                    RÉSUMÉ DU CHALLENGE                      │
├─────────────────────────────────────────────────────────────┤
│  1. srand(seed) + rand() est DÉTERMINISTE                   │
│  2. Même seed = même séquence de nombres                    │
│  3. Utiliser l'entrée utilisateur comme seed = vulnérable   │
│  4. Bruteforce possible car peu de caractères ASCII (~95)   │
│  5. ctypes permet d'appeler la libc depuis Python           │
└─────────────────────────────────────────────────────────────┘
```

### Commandes GDB utiles apprises

| Commande | Description |
|----------|-------------|
| `disas main` | Désassembler la fonction main |
| `x/30dw 0xADDR` | Examiner 30 mots de 4 octets en décimal |
| `info functions` | Lister les fonctions du programme |

### La leçon du challenge

Le flag nous rappelle que **rand() n'est pas aléatoire** si on connaît la seed. Ne jamais utiliser `rand()`/`srand()` pour de la cryptographie ou de la sécurité !

---

## Fichiers

- `casino` : binaire du challenge
- `solve.py` : script de résolution

---
