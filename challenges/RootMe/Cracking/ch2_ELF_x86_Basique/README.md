# ELF x86 - Basique - Write-up Root-Me

![Root-Me ch2](https://img.shields.io/badge/RootMe-ch2-orange)![Points](https://img.shields.io/badge/Points-5-brightgreen)![Category](https://img.shields.io/badge/Category-Cracking-blue)

## Resume

| Info | Valeur |
|------|--------|
| **Flag** | `987654321` |
| **Vulnerabilite** | Username et password en clair dans le binaire |
| **Technique** | Double `strcmp` + distinction variables locales vs arguments |
| **Outils** | GDB (GEF) |

---

## Table des matieres

1. [Reconnaissance](#reconnaissance)
2. [Analyse avec GDB](#analyse-avec-gdb)
3. [Notions apprises](#notions-apprises)
4. [Solution](#solution)

---

## Reconnaissance

```bash
$ file ch2.bin
ELF 32-bit LSB executable, Intel 80386, statically linked, with debug_info, not stripped
```

Binaire ELF 32-bit, statiquement lie, non strippe et avec les infos de debug.

---

## Analyse avec GDB

```bash
$ gdb ./ch2.bin
gef> disassemble main
```

### Etape 1 : Identifier les variables locales

Au debut du main, deux valeurs sont chargees dans des variables locales :

```asm
+17:  mov [ebp-0xc],  0x80a6b19    ; 1ere variable locale
+24:  mov [ebp-0x10], 0x80a6b1e    ; 2eme variable locale
```

On les distingue des simples arguments de fonctions car elles sont stockees dans `[ebp-offset]` (variables locales conservees), et non dans `[esp]` (arguments consommes immediatement par un `call`).

### Etape 2 : Comprendre le flux du programme

Le programme effectue **deux verifications successives** avec `strcmp` :

```asm
; --- 1ere verification (username) ---
+85:  call getString                ; lit l'entree utilisateur
+90:  mov [ebp-0x8], eax            ; stocke dans variable locale
+93:  mov eax, [ebp-0xc]            ; charge la 1ere valeur (0x80a6b19)
+106: call strcmp                    ; compare entree vs [ebp-0xc]
+111: test eax,eax
+113: jne main+199                  ; si different -> "Bad username"

; --- 2eme verification (password) ---
+133: call getString                ; lit une 2eme entree
+138: mov [ebp-0x8], eax
+141: mov eax, [ebp-0x10]           ; charge la 2eme valeur (0x80a6b1e)
+154: call strcmp                    ; compare entree vs [ebp-0x10]
+159: test eax,eax
+161: jne main+185                  ; si different -> "Bad password"

; --- Succes ---
+163: printf("Bien joue...")
```

En pseudo-code :

```c
char *username = 0x80a6b19;   // [ebp-0xc]
char *password = 0x80a6b1e;   // [ebp-0x10]

input1 = getString();
if (strcmp(input1, username) != 0) -> "Bad username"

input2 = getString();
if (strcmp(input2, password) != 0) -> "Bad password"

-> "Bien joue !"
```

### Etape 3 : Examiner les chaines en memoire

```
gef> x/s 0x80a6b19
0x80a6b19:    "john"

gef> x/s 0x80a6b1e
0x80a6b1e:    "the ripper"
```

---

## Notions apprises

| Destination | Role | Exemple |
|-------------|------|---------|
| `[ebp-offset]` | Variable locale, conservee pour plus tard | `mov [ebp-0xc], 0x80a6b19` |
| `[esp]` ou `[esp+offset]` | Argument passe au `call` qui suit | `mov [esp], 0x80a6b2c` puis `call puts` |

C'est cette distinction qui permet de reperer les donnees importantes (mots de passe) parmi les chaines d'affichage.

---

## Solution

```
$ ./ch2.bin
username: john
password: the ripper
Bien joue, vous pouvez valider l'epreuve avec le mot de passe : 987654321 !
```

---
