# Guide complet GDB + pwndbg

Un tutoriel pratique pour installer, configurer et utiliser efficacement pwndbg, l'extension qui transforme GDB en outil de reverse engineering et d'exploit development digne de ce nom.

## Sommaire

1. [Prérequis](#prérequis)
2. [Installation](#installation)
3. [Premier lancement](#premier-lancement)
4. [Comprendre l'interface](#comprendre-linterface)
5. [Commandes de base](#commandes-de-base)
6. [Navigation et contrôle d'exécution](#navigation-et-contrôle-dexécution)
7. [Inspection mémoire](#inspection-mémoire)
8. [Analyse du heap](#analyse-du-heap)
9. [Recherche et ROP](#recherche-et-rop)
10. [Astuces et configuration](#astuces-et-configuration)
11. [Cheatsheet](#cheatsheet)

---

## Prérequis

Avant d'installer pwndbg, assure-toi d'avoir :

- Un système Linux (Ubuntu/Debian recommandé, mais Arch, Fedora, etc. fonctionnent aussi)
- GDB version 12.1 ou supérieure
- Python 3.10 ou supérieur
- Git

Vérifie ta version de GDB :

```bash
gdb --version
```

---

## Installation

### Méthode rapide (recommandée)

```bash
# Clone le repo
git clone https://github.com/pwndbg/pwndbg
cd pwndbg

# Lance le script d'installation
./setup.sh
```

Le script s'occupe de tout : dépendances Python, configuration du `.gdbinit`, etc.

### Installation avec Nix (alternative propre)

Si tu utilises Nix :

```bash
nix shell github:pwndbg/pwndbg
```

### Vérification de l'installation

```bash
gdb -q
```

Tu devrais voir le prompt pwndbg avec un message du type :

```
pwndbg: loaded XXX commands. Type pwndbg [filter] for a list.
pwndbg>
```

---

## Premier lancement

### Charger un binaire

```bash
# Depuis le terminal
gdb ./mon_binaire

# Ou depuis pwndbg
pwndbg> file ./mon_binaire
```

### Lancer l'exécution

```bash
# Démarrer et s'arrêter au point d'entrée
pwndbg> start

# Démarrer et s'arrêter à la première instruction
pwndbg> starti

# Lancer normalement
pwndbg> run

# Lancer avec des arguments
pwndbg> run arg1 arg2
```

---

## Comprendre l'interface

Quand le programme s'arrête (breakpoint, step, etc.), pwndbg affiche automatiquement le "context". C'est la vue principale divisée en plusieurs sections :

### REGISTERS

Affiche tous les registres CPU. Les valeurs sont colorées selon le type de données qu'elles pointent :
- Rouge/rose : adresses du code
- Vert : adresses de la stack
- Jaune : adresses du heap
- Bleu : adresses de la libc ou autres libs

### DISASM

Le code désassemblé autour de l'instruction courante. La flèche `►` indique l'instruction qui va être exécutée. pwndbg annote automatiquement :
- Les valeurs des opérandes
- Les résultats des conditions (jumps pris ou non)
- Les arguments des appels de fonction

### STACK

Le contenu de la pile avec déréférencement récursif. Si une valeur sur la stack pointe vers une autre adresse, pwndbg suit la chaîne.

### BACKTRACE

La pile d'appels (call stack) montrant comment on est arrivé là.

### Contrôler ce qui s'affiche

```bash
# Afficher/masquer des sections
pwndbg> context regs disasm stack backtrace

# Voir uniquement le désassemblage
pwndbg> context disasm

# Désactiver le context automatique
pwndbg> set context-sections ''

# Le réactiver
pwndbg> set context-sections regs disasm code stack backtrace
```

---

## Commandes de base

### Breakpoints

```bash
# Sur une fonction
pwndbg> break main
pwndbg> b main

# Sur une adresse
pwndbg> break *0x401234
pwndbg> b *0x401234

# Breakpoint relatif au PIE (base + offset)
pwndbg> breakrva 0x1234

# Sur une ligne de code source
pwndbg> break fichier.c:42

# Lister les breakpoints
pwndbg> info breakpoints
pwndbg> bl                    # style WinDbg

# Supprimer un breakpoint
pwndbg> delete 1              # supprime le breakpoint #1
pwndbg> bc 1                  # style WinDbg

# Désactiver/réactiver
pwndbg> disable 1
pwndbg> enable 1
```

### Breakpoints conditionnels

```bash
# S'arrêter seulement si RAX == 0x42
pwndbg> break *0x401234 if $rax == 0x42

# S'arrêter si un registre contient une certaine valeur
pwndbg> break main if $rdi > 5
```

### Breakpoints spéciaux pwndbg

```bash
# S'arrêter si le jump est pris
pwndbg> break-if-taken *0x401234

# S'arrêter si le jump n'est PAS pris
pwndbg> break-if-not-taken *0x401234
```

---

## Navigation et contrôle d'exécution

### Les classiques

```bash
# Continuer l'exécution
pwndbg> continue
pwndbg> c

# Step into (entre dans les fonctions)
pwndbg> step
pwndbg> s

# Step over (n'entre pas dans les fonctions)
pwndbg> next
pwndbg> n

# Step une instruction assembleur
pwndbg> stepi
pwndbg> si

# Next une instruction assembleur
pwndbg> nexti
pwndbg> ni
```

### Commandes pwndbg avancées

```bash
# Exécuter jusqu'au prochain call
pwndbg> nextcall

# Exécuter jusqu'au prochain ret
pwndbg> nextret

# Exécuter jusqu'au prochain jump
pwndbg> nextjmp

# Exécuter jusqu'au prochain syscall
pwndbg> nextsyscall

# Exécuter jusqu'à une adresse précise
pwndbg> xuntil *0x401234

# Step over les instructions répétitives (utile pour les rep)
pwndbg> stepover
```

---

## Inspection mémoire

### Examiner la mémoire (style GDB)

```bash
# x/[count][format][size] address
# Formats: x(hex), d(decimal), s(string), i(instruction)
# Sizes: b(byte), h(halfword/2), w(word/4), g(giant/8)

pwndbg> x/10gx $rsp          # 10 qwords en hex depuis RSP
pwndbg> x/s 0x402000         # string à cette adresse
pwndbg> x/20i main           # 20 instructions depuis main
```

### Commandes pwndbg (plus lisibles)

```bash
# Telescope : déréférence récursivement
pwndbg> telescope $rsp 20
pwndbg> tele $rsp 20

# Hexdump
pwndbg> hexdump $rsp 64
pwndbg> hexdump 0x7fff1234 128

# Voir la stack
pwndbg> stack 20

# Voir le désassemblage
pwndbg> nearpc 20
pwndbg> disass main
```

### Style WinDbg

Si tu viens de Windows, pwndbg supporte la syntaxe WinDbg :

```bash
pwndbg> dd $rsp              # dump dwords
pwndbg> dq $rsp              # dump qwords
pwndbg> db $rsp              # dump bytes
pwndbg> da 0x402000          # dump ascii string
pwndbg> dps $rsp             # dump pointers with symbols
```

### Écrire en mémoire

```bash
# Style GDB
pwndbg> set *0x7fff1234 = 0x41414141
pwndbg> set $rax = 0x1337

# Style WinDbg
pwndbg> eb $rsp 0x90         # écrire un byte
pwndbg> ed $rsp 0x41414141   # écrire un dword
pwndbg> eq $rsp 0xdeadbeef   # écrire un qword
```

### Virtual memory map

```bash
# Voir toutes les régions mémoire
pwndbg> vmmap

# Filtrer
pwndbg> vmmap libc
pwndbg> vmmap heap
pwndbg> vmmap stack

# Voir où pointe une adresse
pwndbg> xinfo 0x7fff1234
```

---

## Analyse du heap

pwndbg excelle pour l'analyse du heap glibc (ptmalloc2).

### Vue d'ensemble

```bash
# Visualisation du heap
pwndbg> heap

# Vue graphique des chunks
pwndbg> vis_heap_chunks
pwndbg> vis

# Voir les arenas
pwndbg> arenas
pwndbg> arena              # arena courante
```

### Bins

```bash
# Tous les bins
pwndbg> bins

# Par type
pwndbg> fastbins
pwndbg> smallbins
pwndbg> largebins
pwndbg> unsortedbin
pwndbg> tcachebins
pwndbg> tcache
```

### Chunks

```bash
# Analyser un chunk spécifique
pwndbg> malloc_chunk 0x555555559000

# Top chunk
pwndbg> top_chunk
```

### Outils d'exploit

```bash
# Trouver des fake fastbins
pwndbg> find_fake_fast &__malloc_hook
pwndbg> find_fake_fast 0x7ffff7dd1b10

# Simuler un free
pwndbg> try_free 0x555555559010
```

---

## Recherche et ROP

### Recherche en mémoire

```bash
# Chercher une string
pwndbg> search "flag{"
pwndbg> search "/bin/sh"

# Chercher des bytes
pwndbg> search -x "deadbeef"
pwndbg> search -x "4141414141414141"

# Chercher une valeur
pwndbg> search -4 0xdeadbeef    # dword
pwndbg> search -8 0x7fffffff    # qword

# Chercher un pointeur
pwndbg> search -p 0x7ffff7dd1b10

# Limiter la recherche
pwndbg> search -w "test"         # writable memory only
pwndbg> search -x "test"         # executable memory only
```

### ROP gadgets

```bash
# Chercher des gadgets (nécessite ropper ou ROPgadget installé)
pwndbg> rop --grep "pop rdi"
pwndbg> rop --grep "ret"

# Avec ropper directement
pwndbg> ropper --search "pop rdi"
```

### Trouver des leaks

```bash
# Chercher des pointeurs entre deux régions
pwndbg> leakfind $rsp $rsp+0x200 --max-offset 0x100

# Probeleak : voir ce que contient une région
pwndbg> probeleak $rsp 0x100
```

---

## Astuces et configuration

### Configuration de base

Crée ou édite `~/.gdbinit` (pwndbg l'a déjà modifié) :

```bash
# Ajouter après la ligne source de pwndbg

# Désactiver la confirmation pour quit
set confirm off

# Historique des commandes
set history save on
set history size 10000
set history filename ~/.gdb_history

# Pagination désactivée
set pagination off

# Intel syntax (plus lisible que AT&T)
set disassembly-flavor intel
```

### Configuration pwndbg

```bash
# Voir toutes les options
pwndbg> config

# Exemples de personnalisation
pwndbg> set context-sections regs disasm code stack
pwndbg> set show-flags on
pwndbg> set dereference-limit 10
```

### Sauvegarder la config

```bash
pwndbg> configfile
# Affiche le chemin du fichier de config (~/.config/pwndbg/config)
```

### Attacher à un processus

```bash
# Par PID
pwndbg> attach 1234

# Par nom (feature pwndbg)
pwndbg> attachp firefox
pwndbg> attachp -newest python3
```

### Débugger avec des fichiers core

```bash
gdb ./mon_binaire core.12345
```

### Débugger à distance

```bash
# Sur la cible
gdbserver :1234 ./mon_binaire

# Sur ta machine
gdb ./mon_binaire
pwndbg> target remote ip_cible:1234
```

### Intégration avec pwntools

```python
from pwn import *

# Lance le binaire avec GDB attaché
p = gdb.debug('./vuln', '''
    break main
    continue
''')

# Ou attache GDB à un process existant
p = process('./vuln')
gdb.attach(p, 'break *0x401234')
```

---

## Cheatsheet

### Démarrage

| Commande | Description |
|----------|-------------|
| `start` | Démarre et break à main |
| `starti` | Démarre et break à la première instruction |
| `run [args]` | Lance le programme |
| `attach PID` | Attache à un process |
| `attachp name` | Attache par nom |

### Breakpoints

| Commande | Description |
|----------|-------------|
| `b main` | Break sur fonction |
| `b *0x401234` | Break sur adresse |
| `breakrva 0x1234` | Break relatif (PIE) |
| `bl` | Liste les breakpoints |
| `bc N` | Supprime breakpoint N |
| `bd N` / `be N` | Disable/enable breakpoint N |

### Exécution

| Commande | Description |
|----------|-------------|
| `c` | Continue |
| `n` / `ni` | Next (source/asm) |
| `s` / `si` | Step into (source/asm) |
| `nextcall` | Jusqu'au prochain call |
| `nextret` | Jusqu'au prochain ret |
| `finish` | Jusqu'à la fin de la fonction |

### Mémoire

| Commande | Description |
|----------|-------------|
| `tele ADDR [N]` | Telescope N entrées |
| `stack [N]` | Affiche N entrées de stack |
| `vmmap` | Memory map |
| `hexdump ADDR LEN` | Hexdump |
| `search "str"` | Cherche une string |
| `search -x BYTES` | Cherche des bytes |

### Heap

| Commande | Description |
|----------|-------------|
| `heap` | Vue du heap |
| `vis` | Visualisation chunks |
| `bins` | Tous les bins |
| `fastbins` | Fastbins |
| `tcache` | Tcache |
| `find_fake_fast ADDR` | Trouve fake fastbins |
| `try_free ADDR` | Simule free |

### Registres et contexte

| Commande | Description |
|----------|-------------|
| `regs` | Affiche les registres |
| `context` | Rafraîchit le context |
| `nearpc [N]` | Désassemble N instructions |
| `xinfo ADDR` | Info sur une adresse |

### Divers

| Commande | Description |
|----------|-------------|
| `checksec` | Vérifie les protections |
| `got` | Affiche la GOT |
| `plt` | Affiche la PLT |
| `canary` | Affiche le canary |
| `rop --grep "gadget"` | Cherche des gadgets |
| `cyclic N` | Génère un pattern |
| `cyclic -l VALUE` | Trouve l'offset |

---

## Ressources supplémentaires

- Documentation officielle : https://pwndbg.re/
- Cheatsheet PDF : https://pwndbg.re/dev/CHEATSHEET.pdf
- Discord pwndbg : https://discord.gg/x47DssnGwm
- GitHub : https://github.com/pwndbg/pwndbg

---
