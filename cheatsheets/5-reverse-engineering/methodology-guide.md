# Guide Méthodologique - Reverse Engineering

## Introduction

Le reverse engineering (RE) consiste à analyser un binaire pour comprendre son fonctionnement sans accès au code source. Ce guide présente une méthodologie structurée pour aborder l'analyse de n'importe quel binaire.

### Mindset

1. **Patience** - Le RE prend du temps, ne pas se précipiter
2. **Documentation** - Prendre des notes, renommer les fonctions/variables
3. **Itératif** - Alterner analyse statique et dynamique
4. **Hypothèses** - Formuler des hypothèses et les vérifier
5. **Patterns** - Reconnaître les structures récurrentes (boucles, conditions, appels standards)

---

## Phase 1: Triage et Reconnaissance

### Objectif
Identifier rapidement le type de binaire, son architecture, et ses caractéristiques avant toute analyse approfondie.

### 1.1 Identification du Fichier

```bash
# Type de fichier
file binary
# ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked...

# Magic bytes
xxd binary | head -5
hexdump -C binary | head -5

# Strings visibles (indices rapides)
strings binary | head -50
strings -n 10 binary | less    # Strings >= 10 chars

# Entropie (détection packing/chiffrement)
binwalk -E binary
# Entropie haute (>7.5) = probablement packé/chiffré
```

### 1.2 Informations Détaillées

```bash
# ELF
readelf -h binary              # Header (arch, entry point)
readelf -l binary              # Segments
readelf -S binary              # Sections
readelf -s binary              # Symboles
readelf -d binary              # Dynamic (libraries)

# PE (Windows)
objdump -x binary.exe          # Headers
python -c "import pefile; pe=pefile.PE('binary.exe'); print(pe.dump_info())"

# Mach-O (macOS)
otool -h binary                # Header
otool -l binary                # Load commands
otool -L binary                # Libraries
```

### 1.3 Sécurité et Protections

```bash
# Linux - checksec (pwntools ou checksec.sh)
checksec --file=binary
# RELRO, Stack Canary, NX, PIE, FORTIFY

# Ou avec pwntools
python3 -c "from pwn import *; print(ELF('binary').checksec())"

# Détection de packer
die binary                     # Detect It Easy
rabin2 -I binary              # radare2
```

### 1.4 Checklist Triage

```
[ ] Format: ELF / PE / Mach-O / autre
[ ] Architecture: x86 / x64 / ARM / ARM64 / autre
[ ] Linkage: static / dynamic
[ ] Stripped: oui / non (symboles présents?)
[ ] Protections: NX, PIE, Canary, RELRO
[ ] Packé/Obfusqué: oui / non
[ ] Libraries: libc, libcrypto, réseau...
[ ] Strings intéressantes: flags, URLs, messages d'erreur
```

---

## Phase 2: Analyse Statique

### Objectif
Comprendre la structure et la logique du programme sans l'exécuter.

### 2.1 Chargement dans un Désassembleur

**Cutter (gratuit, recommandé - GUI de radare2)**

Cutter est l'interface graphique officielle de radare2. Open source, multi-plateforme, avec décompilateur intégré (Ghidra ou r2dec).

```
Installation:
- macOS: brew install --cask cutter
- Linux: AppImage depuis https://cutter.re ou package manager
- Windows: Installer depuis https://cutter.re

Utilisation:
1. File > Open > sélectionner le binaire
2. Options d'analyse: cocher "Analysis: aa" ou "Deep analysis: aaa"
3. Cliquer "OK" et attendre l'analyse
4. Interface: Désassembleur au centre, fonctions à gauche, décompilé à droite
```

**Raccourcis Cutter essentiels:**
| Raccourci | Action |
|-----------|--------|
| `G` | Go to address |
| `N` | Rename (fonction/variable) |
| `X` | Cross-references |
| `;` | Add comment |
| `Tab` | Switch asm/décompilé |
| `Space` | Graph view |
| `/` | Search |

**radare2 (CLI, même moteur que Cutter)**
```bash
r2 -A binary                   # Ouvrir avec analyse automatique
aaa                            # Analyse approfondie
afl                            # Lister les fonctions
s main                         # Aller à main
pdf                            # Désassembler la fonction courante
```

**Autres outils (référence)**
| Outil | Prix | Notes |
|-------|------|-------|
| Ghidra | Gratuit | NSA, bon décompilateur |
| IDA Pro | $$$$ | Standard industrie |
| Binary Ninja | $$ | Moderne, bonne API |

### 2.2 Localiser le Point d'Entrée

```bash
# Entry point
readelf -h binary | grep Entry
# Entry point address: 0x401050

# Dans Cutter: touche G > taper "entry0" ou "main"
# Dans r2: s entry0 && pdf
```

**Flux typique d'un programme C:**
```
_start → __libc_start_main → main → votre code
```

### 2.3 Identifier les Fonctions Clés

**Recherche par strings:**
```bash
# Trouver où sont utilisées les strings intéressantes
strings -t x binary | grep -i "password\|flag\|correct\|wrong"

# Dans Cutter:
# - Onglet "Strings" (panneau gauche) ou Windows > Strings
# - Double-click sur une string pour voir où elle est utilisée
# - Clic droit > "Show X-Refs" pour les références croisées
```

**Recherche par imports:**
```bash
# Fonctions importées (indices sur le comportement)
objdump -T binary | grep -E "strcmp|memcmp|crypt|socket|fopen"

# Dans Cutter:
# - Onglet "Imports" (panneau gauche)
# - Filtrer avec la barre de recherche
# - Double-click pour voir où la fonction est appelée
```

**Fonctions courantes à surveiller:**

| Catégorie | Fonctions |
|-----------|-----------|
| Comparaison | `strcmp`, `strncmp`, `memcmp`, `bcmp` |
| Crypto | `MD5`, `SHA`, `AES`, `encrypt`, `decrypt` |
| I/O | `fopen`, `fread`, `fwrite`, `read`, `write` |
| Réseau | `socket`, `connect`, `send`, `recv` |
| Mémoire | `malloc`, `free`, `mmap`, `memcpy` |
| Process | `fork`, `exec`, `system`, `popen` |

### 2.4 Comprendre la Logique

**Renommer au fur et à mesure:**
```
# Dans Cutter:
# - Sélectionner fonction/variable
# - Touche N ou clic droit > Rename
# - Les noms sont synchronisés avec le décompilé

# Dans r2: afn nouveau_nom @ adresse

# Exemple de renommage:
fcn.00401234 → check_password
obj.00404000 → encrypted_flag
var_18h → user_input
```

**Identifier les structures de contrôle:**

```c
// Pattern IF-ELSE (assembleur x64)
cmp rax, rbx
jne else_branch
; code if true
jmp end_if
else_branch:
; code if false
end_if:
```

```c
// Pattern BOUCLE FOR
mov ecx, 0          ; i = 0
loop_start:
cmp ecx, 10         ; i < 10
jge loop_end
; corps de boucle
inc ecx             ; i++
jmp loop_start
loop_end:
```

```c
// Pattern SWITCH (jump table)
cmp eax, 5
ja default_case
jmp [jump_table + rax*8]
```

### 2.5 Analyse du Décompilé

**Dans Cutter:**

Cutter intègre plusieurs décompilateurs (configurable dans Preferences > Decompiler):
- **Ghidra** (r2ghidra) - Recommandé, meilleure qualité
- **r2dec** - Plus rapide, moins précis
- **pdc** - Basique, intégré r2

```
1. Sélectionner une fonction dans la liste ou le désassembleur
2. Le panneau "Decompiler" (droite) affiche le pseudo-C
3. Cliquer sur une variable dans le décompilé = highlight dans l'asm
4. Clic droit sur variable > "Rename" pour renommer partout
```

**Configuration décompilateur:**
```
Edit > Preferences > Decompiler
- Sélectionner "Ghidra" pour meilleure qualité
- Ou "r2dec" si r2ghidra n'est pas installé
```

**Tips décompilation:**
- Renommer les variables pour clarifier (touche N)
- Ajouter des commentaires (touche `;`)
- Utiliser Tab pour switch entre asm et décompilé
- Le décompilé n'est pas parfait, toujours vérifier l'assembleur
- Les types peuvent être incorrects, analyser le contexte

---

## Phase 3: Analyse Dynamique

### Objectif
Observer le comportement réel du programme en l'exécutant de manière contrôlée.

### 3.1 Environnement Sécurisé

```bash
# TOUJOURS analyser dans un environnement isolé!

# Option 1: VM (VirtualBox, VMware, UTM)
# Option 2: Container Docker
docker run -it --rm -v $(pwd):/work ubuntu:22.04

# Option 3: Sandbox (pour malware)
# Cuckoo, Any.run, VirusTotal
```

### 3.2 Exécution Initiale

```bash
# Observer le comportement normal
./binary

# Avec arguments
./binary arg1 arg2

# Tracer les appels système
strace ./binary 2>&1 | head -100
strace -f ./binary                 # Suivre les forks
strace -e open,read,write ./binary # Filtrer

# Tracer les appels de bibliothèque
ltrace ./binary

# macOS
dtruss ./binary                    # Équivalent strace
```

### 3.3 Debugging avec GDB

```bash
# Lancer en debug
gdb ./binary

# Configuration initiale
(gdb) set disassembly-flavor intel
(gdb) break main
(gdb) run

# Avec pwndbg/GEF (recommandé)
# Affichage amélioré automatique
```

**Workflow debugging typique:**

```gdb
# 1. Breakpoint sur main
break main
run

# 2. Identifier la fonction de vérification
# (via analyse statique préalable)
break check_password

# 3. Exécuter jusqu'au breakpoint
continue

# 4. Examiner les arguments
info args
x/s $rdi          # Premier argument (string)
x/20x $rsp        # Stack

# 5. Step through
ni                # Next instruction
si                # Step into
finish            # Sortir de la fonction

# 6. Examiner le résultat
print $rax        # Valeur de retour

# 7. Modifier si besoin
set $rax = 1      # Forcer le retour
```

### 3.4 Debugging avec radare2

```bash
r2 -d ./binary

# Breakpoints
db main           # Breakpoint sur main
db 0x401234       # Breakpoint sur adresse

# Exécution
dc                # Continue
ds                # Step
dso               # Step over

# Registres et mémoire
dr                # Registres
drr               # Registres avec références
pxq @ rsp         # Stack
```

### 3.5 Techniques Avancées

**Hooking avec Frida:**
```bash
# Installation
pip install frida-tools

# Script basique
frida -l script.js ./binary
```

```javascript
// script.js - Hook strcmp
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        console.log("strcmp(" +
            Memory.readUtf8String(args[0]) + ", " +
            Memory.readUtf8String(args[1]) + ")");
    },
    onLeave: function(retval) {
        console.log("  -> " + retval);
    }
});
```

**Émulation avec Unicorn/Qiling:**
```python
from qiling import Qiling

ql = Qiling(["./binary"], "rootfs/x8664_linux")
ql.run()
```

---

## Phase 4: Techniques Spécifiques

### 4.1 Cracking de Vérification Simple

**Pattern typique:**
```c
if (check_password(input) == 0) {
    printf("Access denied\n");
} else {
    printf("Access granted\n");
}
```

**Approches:**

1. **Trouver le bon input** (analyse statique)
   - Comprendre l'algorithme de vérification
   - Reverse l'algorithme pour trouver l'input

2. **Patcher le binaire**
   ```bash
   # Changer JE en JNE (ou vice versa)
   # Dans r2:
   r2 -w binary
   s 0x401234         # Aller à l'instruction
   wa jne 0x401250    # Remplacer
   ```

3. **Modifier en runtime**
   ```gdb
   # Dans GDB, après le cmp
   set $eflags |= (1 << 6)    # Set ZF
   # Ou
   set $rax = 1               # Forcer le retour
   ```

### 4.2 Reverse d'Algorithme de Chiffrement

**Étapes:**
1. Identifier l'algorithme (XOR, AES, custom?)
2. Localiser la clé
3. Comprendre le mode (ECB, CBC?)
4. Implémenter le déchiffrement

**Exemple XOR simple:**
```python
# Si encrypted = data XOR key, alors:
# data = encrypted XOR key

encrypted = bytes.fromhex("...")
key = b"secret"

decrypted = bytes([e ^ key[i % len(key)] for i, e in enumerate(encrypted)])
print(decrypted)
```

### 4.3 Unpacking

**Signes d'un binaire packé:**
- Peu de strings lisibles
- Entropie élevée (>7.5)
- Sections avec noms bizarres (UPX0, .packed)
- Peu d'imports

**Approche générique:**
1. Identifier le packer (DIE, PEiD)
2. Si packer connu: utiliser l'unpacker
3. Sinon: dump mémoire après exécution

```bash
# UPX (courant)
upx -d packed_binary -o unpacked_binary

# Dump mémoire avec gdb
gdb ./packed
break *entry_point_original
run
dump memory unpacked.bin 0x400000 0x500000
```

### 4.4 Analyse de Malware (bases)

**ATTENTION: Toujours en VM isolée!**

```bash
# 1. Snapshot VM avant analyse

# 2. Surveillance réseau
sudo tcpdump -i eth0 -w capture.pcap &

# 3. Surveillance filesystem
inotifywait -m -r /tmp /etc /home

# 4. Exécuter et observer
./malware

# 5. Analyser les résultats
```

---

## Outils par Catégorie

### Désassembleurs / Décompilateurs

| Outil | Prix | Plateformes | Notes |
|-------|------|-------------|-------|
| **Cutter** | Gratuit | All | GUI radare2, décompilateur Ghidra intégré, recommandé |
| **radare2** | Gratuit | All | CLI puissant, scriptable, base de Cutter |
| **Ghidra** | Gratuit | All | NSA, bon décompilateur standalone |
| **IDA Pro** | $$$$ | All | Standard industrie, Hex-Rays |
| **IDA Free** | Gratuit | x86/x64 | Version limitée, cloud |
| **Binary Ninja** | $$ | All | Moderne, bonne API Python |
| **Hopper** | $$ | macOS/Linux | Léger, bon pour macOS |
| **RetDec** | Gratuit | All | Décompilateur en ligne/CLI |

### Debuggers

| Outil | Plateforme | Notes |
|-------|------------|-------|
| **GDB** | Linux/macOS | Standard, utiliser avec pwndbg/GEF |
| **LLDB** | macOS/Linux | Par défaut sur macOS |
| **x64dbg** | Windows | Open source, moderne |
| **WinDbg** | Windows | Microsoft, kernel debugging |
| **OllyDbg** | Windows | Classique, x86 uniquement |

### Instrumentation Dynamique

| Outil | Usage |
|-------|-------|
| **Frida** | Hooking runtime (mobile, desktop) |
| **DynamoRIO** | Instrumentation binaire |
| **Intel PIN** | Instrumentation x86/x64 |
| **Qiling** | Émulation + instrumentation |
| **Unicorn** | Émulation CPU légère |

### Analyse Automatisée

| Outil | Usage |
|-------|-------|
| **angr** | Exécution symbolique, solver |
| **Triton** | Exécution symbolique/concolique |
| **Manticore** | Analyse symbolique |
| **KLEE** | Exécution symbolique (LLVM) |

### Utilitaires

| Outil | Usage |
|-------|-------|
| **binwalk** | Analyse firmware, extraction |
| **strings** | Extraction strings |
| **file** | Identification format |
| **objdump** | Désassemblage basique |
| **readelf/otool** | Analyse headers |
| **nm** | Symboles |
| **ldd** | Dépendances |
| **strace/ltrace** | Traçage appels |
| **checksec** | Vérification protections |

---

## Workflow Pratique - Exemple CTF

### Scénario
Binary qui demande un password et affiche "Correct!" ou "Wrong!".

### Étape 1: Reconnaissance (2 min)
```bash
file crackme
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

checksec --file=crackme
# No PIE, No canary, NX enabled

strings crackme | grep -i "correct\|wrong\|password\|flag"
# Enter password:
# Correct!
# Wrong!
```

### Étape 2: Analyse Statique (10-15 min)
```
# Ouvrir dans Cutter:
# 1. File > Open > crackme, cocher "aaa" analysis
# 2. Dans Functions (gauche), double-click sur "main"
# 3. Regarder le décompilé (panneau droit):

# Pseudo-code (décompilé par Cutter):
int main() {
    char input[64];
    printf("Enter password: ");
    fgets(input, 64, stdin);
    if (check_password(input) != 0) {
        puts("Correct!");
    } else {
        puts("Wrong!");
    }
}

# 4. Double-click sur check_password() pour l'analyser:
int check_password(char *input) {
    char expected[] = "encrypted_string";
    for (int i = 0; i < strlen(input); i++) {
        if ((input[i] ^ 0x42) != expected[i]) {
            return 0;
        }
    }
    return 1;
}

# 5. Dans le désassembleur, sélectionner "expected"
#    -> voir les bytes dans le panneau Hexdump
```

### Étape 3: Résolution
```python
# XOR inverse
# Extraire les bytes depuis Cutter (Hexdump ou clic droit > Copy bytes)
expected = bytes.fromhex("...")
password = bytes([b ^ 0x42 for b in expected])
print(password.decode())
```

### Étape 4: Vérification
```bash
echo "found_password" | ./crackme
# Correct!
```

---

## Tips et Bonnes Pratiques

### Productivité

1. **Raccourcis clavier** - Apprendre les raccourcis de votre outil
2. **Scripts** - Automatiser les tâches répétitives
3. **Templates** - Avoir des scripts prêts (Frida hooks, GDB scripts)
4. **Notes** - Documenter au fur et à mesure

### Analyse

1. **Commencer simple** - D'abord les strings, imports, exports
2. **Top-down** - main → fonctions appelées
3. **Diviser** - Analyser fonction par fonction
4. **Hypothèses** - "Cette fonction semble faire X, vérifions"
5. **Cross-références** - Qui appelle cette fonction? Qui utilise cette variable?

### Debugging

1. **Breakpoints stratégiques** - Pas trop, pas trop peu
2. **Conditions** - `break func if $rax > 100`
3. **Logging** - Plutôt que step manuel
4. **Snapshots** - Sauvegarder l'état pour revenir en arrière

### Erreurs Courantes

1. **Se perdre dans les détails** - Garder l'objectif en tête
2. **Ignorer l'analyse statique** - Balance statique/dynamique
3. **Oublier l'environnement** - Variables, arguments, fichiers
4. **Ne pas prendre de notes** - On oublie vite

---

## Ressources d'Apprentissage

### CTF et Challenges

| Ressource | Niveau | Description |
|-----------|--------|-------------|
| [crackmes.one](https://crackmes.one) | Tous | Challenges de cracking |
| [reversing.kr](http://reversing.kr) | Moyen-Avancé | Challenges variés |
| [pwnable.kr](http://pwnable.kr) | Tous | PWN + RE |
| [root-me.org](https://root-me.org) | Tous | Section Cracking |
| [picoCTF](https://picoctf.org) | Débutant | CTF éducatif |
| [Microcorruption](https://microcorruption.com) | Moyen | RE embarqué |

### Cours et Tutoriels

- [Cutter Documentation](https://cutter.re/docs/) - Documentation officielle Cutter
- [radare2 Book](https://book.rada.re/) - Guide complet radare2/Cutter
- [Nightmare](https://guyinatuxedo.github.io/) - Cours RE/PWN complet
- [LiveOverflow](https://www.youtube.com/c/LiveOverflow) - Vidéos RE/PWN
- [MalwareTech](https://www.malwaretech.com/) - Analyse malware
- [OpenSecurityTraining2](https://opensecuritytraining.info/) - Cours gratuits

### Livres

- *Practical Reverse Engineering* - Dang, Gazet, Bachaalany
- *Reversing: Secrets of Reverse Engineering* - Eilam
- *The IDA Pro Book* - Eagle
- *Blue Fox: ARM Assembly Internals and Reverse Engineering* - Markstedter
- *Practical Malware Analysis* - Sikorski, Honig

### Communautés

- [r/ReverseEngineering](https://reddit.com/r/ReverseEngineering)
- [r/netsec](https://reddit.com/r/netsec)
- Discord: Reverse Engineering, CTF servers
- [0x00sec](https://0x00sec.org/)

---

## Checklist Récapitulative

```
PHASE 1 - TRIAGE
[ ] file, strings, checksec
[ ] Format et architecture identifiés
[ ] Protections notées
[ ] Strings intéressantes extraites

PHASE 2 - ANALYSE STATIQUE (Cutter)
[ ] Binaire chargé (File > Open, analyse "aaa")
[ ] Entry point et main localisés (Functions panel)
[ ] Fonctions clés identifiées (X-refs sur strings)
[ ] Imports/exports analysés (Imports panel)
[ ] Fonctions renommées (touche N)
[ ] Logique comprise (décompilé annoté)

PHASE 3 - ANALYSE DYNAMIQUE
[ ] Environnement sécurisé
[ ] Comportement normal observé
[ ] Breakpoints placés
[ ] Variables/registres critiques surveillés
[ ] Hypothèses vérifiées

PHASE 4 - RÉSOLUTION
[ ] Solution trouvée et testée
[ ] Documentation complète
[ ] Writeup si CTF
```
