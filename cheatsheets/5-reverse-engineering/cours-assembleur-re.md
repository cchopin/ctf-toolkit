# Cours d'assembleur x86-64 pour le reverse engineering

**Objectif** : apprendre à lire l'assembleur pour analyser des binaires et des malwares.
**Plateforme** : Mac M2 (avec solutions de compatibilité pour x86-64)
**Prérequis** : connaissances de base en C, curiosité
**Durée estimée** : 8-12 semaines à raison de 5-10h/semaine

---

## Architecture du cours

| Module | Contenu | Durée |
|--------|---------|-------|
| 0 | Environnement et outils | 1 semaine |
| 1 | Fondamentaux : registres et mémoire | 1-2 semaines |
| 2 | Instructions de base | 2 semaines |
| 3 | Flux de contrôle | 2 semaines |
| 4 | Fonctions et pile | 2 semaines |
| 5 | Introduction à Ghidra | 1-2 semaines |
| 6 | Premiers challenges | continu |

---

# Module 0 : environnement et outils

## Pourquoi x86-64 sur un Mac M2 ?

Ton Mac M2 utilise une architecture ARM, mais 95% des malwares Windows/Linux sont en x86-64. Pour le reverse engineering, tu dois donc apprendre x86-64.

**Bonne nouvelle** : Ghidra fonctionne nativement sur Mac et peut analyser des binaires x86-64 sans problème. Tu n'as pas besoin d'exécuter le code, juste de le lire.

## Installation des outils

### 1. Homebrew (si pas déjà installé)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. Outils de base

```bash
# NASM : assembleur pour écrire du code x86
brew install nasm

# Radare2 : désassembleur en ligne de commande
brew install radare2

# GDB (via binutils) ou LLDB (natif sur Mac)
# LLDB est déjà installé avec Xcode Command Line Tools
xcode-select --install
```

### 3. Ghidra (outil principal)

```bash
# Installer Java (requis par Ghidra)
brew install openjdk@17

# Ajouter Java au PATH (ajouter dans ~/.zshrc)
echo 'export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Télécharger Ghidra depuis https://ghidra-sre.org/
# Décompresser et lancer avec ./ghidraRun
```

### 4. VM Windows (optionnel mais recommandé)

Pour exécuter et debugger des binaires Windows, installe UTM (gratuit, optimisé Apple Silicon) :

```bash
brew install --cask utm
```

Puis télécharge une ISO Windows 11 ARM ou utilise les images prêtes à l'emploi sur le site UTM.

### 5. Compiler Explorer (en ligne, pas d'installation)

https://godbolt.org permet de voir instantanément le code assembleur généré par du code C.
C'est l'outil parfait pour apprendre la correspondance C → assembleur.

---

**Vidéo recommandée** :
- "you can mass-analyze binaries with ghidra scripting" - Low Level (8 min)
  https://www.youtube.com/watch?v=6zRN-s4g_5M
  (Montre l'installation et l'interface de Ghidra)

---

## Exercice 0.1 : vérifier l'installation

```bash
# Vérifie que NASM fonctionne
nasm -v

# Vérifie que radare2 fonctionne
r2 -v

# Vérifie Java pour Ghidra
java -version
```

## Exercice 0.2 : premier contact avec Compiler Explorer

1. Va sur https://godbolt.org
2. Sélectionne le langage C et le compilateur "x86-64 gcc"
3. Tape ce code :

```c
int add(int a, int b) {
    return a + b;
}
```

4. Observe le code assembleur généré à droite
5. Change les options de compilation : ajoute `-O0` (pas d'optimisation) puis `-O2` (optimisé)
6. Compare les deux résultats

**Question** : combien d'instructions génère la version non optimisée vs optimisée ?

---

# Module 1 : fondamentaux - registres et mémoire

## 1.1 Qu'est-ce qu'un registre ?

Un registre est une petite zone de mémoire ultra-rapide directement dans le CPU. Pense aux registres comme des variables intégrées au processeur.

En x86-64, il y a 16 registres généraux de 64 bits :

| Registre | Usage courant | Taille |
|----------|---------------|--------|
| RAX | Valeur de retour, accumulateur | 64 bits |
| RBX | Base (usage général) | 64 bits |
| RCX | Compteur de boucles | 64 bits |
| RDX | Données, I/O | 64 bits |
| RSI | Source index (copie de données) | 64 bits |
| RDI | Destination index | 64 bits |
| RBP | Base pointer (frame de pile) | 64 bits |
| RSP | Stack pointer (sommet de la pile) | 64 bits |
| R8-R15 | Registres additionnels x86-64 | 64 bits |
| RIP | Instruction pointer (adresse courante) | 64 bits |

## 1.2 Sous-registres

Chaque registre peut être utilisé en parties plus petites :

```
RAX (64 bits) : |XXXXXXXX|XXXXXXXX|XXXXXXXX|XXXXXXXX|XXXXXXXX|XXXXXXXX|XXXXXXXX|XXXXXXXX|
                                                    |       EAX (32 bits)              |
                                                                        |   AX (16)    |
                                                                        | AH  |   AL   |
                                                                          8b     8b
```

Exemple pratique :
- `RAX` = registre complet 64 bits
- `EAX` = 32 bits inférieurs de RAX
- `AX` = 16 bits inférieurs de EAX
- `AL` = 8 bits inférieurs de AX
- `AH` = 8 bits supérieurs de AX

**Pourquoi c'est important ?** En reverse engineering, tu verras souvent du code qui manipule `EAX` au lieu de `RAX`. Ça signifie que le programme travaille avec des valeurs 32 bits.

---

**Vidéo recommandée** :
- "you can mass-analyze binaries with ghidra scripting" - Low Level (8 min)
  https://www.youtube.com/watch?v=oGhfv7rJgjs
  (Explication claire des registres x86)

- "Assembly Language in 100 Seconds" - Fireship (2 min)
  https://www.youtube.com/watch?v=4gwYkEK0gOk
  (Vue d'ensemble ultra-rapide)

---

## 1.3 La mémoire et les adresses

La mémoire est un grand tableau d'octets. Chaque octet a une adresse unique.

```
Adresse     Contenu
0x0000      [XX]
0x0001      [XX]
...
0x7FFF      [XX]  ← zone utilisateur
...
0xFFFF...   [XX]  ← zone kernel (inaccessible)
```

**Little-endian** : sur x86, les octets sont stockés à l'envers !

Exemple : la valeur `0x12345678` est stockée comme :
```
Adresse:  0x100  0x101  0x102  0x103
Contenu:   78     56     34     12
```

C'est contre-intuitif mais tu t'y habitueras. En RE, c'est crucial de le savoir.

## 1.4 Modes d'adressage

En assembleur, tu peux accéder à la mémoire de plusieurs façons :

| Syntaxe | Signification |
|---------|---------------|
| `mov rax, 42` | Valeur immédiate : rax = 42 |
| `mov rax, rbx` | Registre à registre : rax = rbx |
| `mov rax, [rbx]` | Indirection : rax = valeur à l'adresse dans rbx |
| `mov rax, [rbx+8]` | Base + déplacement |
| `mov rax, [rbx+rcx*4]` | Base + index * échelle |
| `mov rax, [rbx+rcx*4+16]` | Complet : base + index*scale + displacement |

Les crochets `[]` signifient "va chercher la valeur à cette adresse".

---

## Exercice 1.1 : registres dans Compiler Explorer

Sur https://godbolt.org, compile ce code :

```c
int example() {
    int a = 10;
    int b = 20;
    int c = a + b;
    return c;
}
```

Questions :
1. Quels registres sont utilisés ?
2. Où sont stockées les variables locales ?
3. Quel registre contient la valeur de retour ?

## Exercice 1.2 : little-endian

Si tu vois en mémoire les octets `41 42 43 44` à partir de l'adresse `0x1000`, quelle est la valeur 32 bits stockée ?

<details>
<summary>Réponse</summary>

En little-endian, c'est `0x44434241`.
En ASCII, ces octets correspondent à "ABCD" (0x41='A', 0x42='B', etc.)
</details>

---

# Module 2 : instructions de base

## 2.1 L'instruction MOV

`MOV` est l'instruction la plus courante. Elle copie une valeur d'un endroit à un autre.

```asm
mov rax, 42         ; rax = 42
mov rbx, rax        ; rbx = rax
mov rcx, [rax]      ; rcx = valeur à l'adresse contenue dans rax
mov [rax], rcx      ; valeur à l'adresse rax = rcx
```

**Attention** : on ne peut pas faire `mov [rax], [rbx]` (mémoire vers mémoire). Il faut passer par un registre.

## 2.2 Instructions arithmétiques

| Instruction | Opération | Exemple |
|-------------|-----------|---------|
| `add dst, src` | dst = dst + src | `add rax, 5` |
| `sub dst, src` | dst = dst - src | `sub rax, rbx` |
| `inc dst` | dst = dst + 1 | `inc rcx` |
| `dec dst` | dst = dst - 1 | `dec rcx` |
| `mul src` | rdx:rax = rax * src | `mul rbx` |
| `imul` | multiplication signée | `imul rax, rbx` |
| `div src` | rax = rdx:rax / src | `div rcx` |
| `neg dst` | dst = -dst | `neg rax` |

## 2.3 Instructions logiques

| Instruction | Opération | Exemple |
|-------------|-----------|---------|
| `and dst, src` | ET bit à bit | `and rax, 0xFF` |
| `or dst, src` | OU bit à bit | `or rax, rbx` |
| `xor dst, src` | XOR bit à bit | `xor rax, rax` (= 0) |
| `not dst` | NON bit à bit | `not rax` |
| `shl dst, n` | Décalage gauche | `shl rax, 2` (× 4) |
| `shr dst, n` | Décalage droite | `shr rax, 1` (÷ 2) |

**Astuce RE** : `xor rax, rax` est la façon idiomatique de mettre un registre à zéro (plus rapide que `mov rax, 0`).

## 2.4 Instructions de comparaison

```asm
cmp rax, rbx        ; Compare rax et rbx (fait rax - rbx sans stocker)
test rax, rax       ; ET logique sans stocker (souvent pour tester si = 0)
```

Ces instructions mettent à jour les FLAGS (registre spécial) :
- **ZF** (Zero Flag) : résultat = 0
- **SF** (Sign Flag) : résultat négatif
- **CF** (Carry Flag) : dépassement non signé
- **OF** (Overflow Flag) : dépassement signé

---

**Vidéo recommandée** :
- "Comparing C to machine language" - Ben Eater (10 min)
  https://www.youtube.com/watch?v=yOyaJXpAYZQ
  (Excellent pour comprendre le lien C → assembleur)

---

## Exercice 2.1 : traduire en assembleur (mental)

Sans compiler, devine ce que fait ce code assembleur :

```asm
mov rax, 10
mov rbx, 3
add rax, rbx
sub rax, 1
```

<details>
<summary>Réponse</summary>

rax = 10
rbx = 3
rax = 10 + 3 = 13
rax = 13 - 1 = 12

Résultat final : rax = 12
</details>

## Exercice 2.2 : reconnaissance de patterns

Que fait ce code ?

```asm
xor eax, eax
mov ecx, 10
.loop:
    add eax, ecx
    dec ecx
    jnz .loop
```

<details>
<summary>Réponse</summary>

C'est une boucle qui calcule la somme de 10 à 1 : 10+9+8+7+6+5+4+3+2+1 = 55
- `xor eax, eax` : eax = 0
- `mov ecx, 10` : ecx = compteur = 10
- boucle : eax += ecx, ecx--, si ecx ≠ 0 recommence
</details>

## Exercice 2.3 : Compiler Explorer avancé

Sur godbolt.org, écris une fonction C qui :
1. Prend deux entiers
2. Retourne le plus grand

```c
int max(int a, int b) {
    if (a > b) return a;
    else return b;
}
```

Observe le code généré. Tu devrais voir `cmp` et des sauts conditionnels.

---

# Module 3 : flux de contrôle

## 3.1 Les sauts inconditionnels

```asm
jmp label           ; Saute toujours à label
```

Équivalent C : `goto label;`

## 3.2 Les sauts conditionnels

Après un `cmp` ou `test`, on peut sauter conditionnellement :

| Instruction | Condition | Usage typique |
|-------------|-----------|---------------|
| `je` / `jz` | ZF=1 (égal / zéro) | `if (a == b)` |
| `jne` / `jnz` | ZF=0 (différent / non-zéro) | `if (a != b)` |
| `jg` / `jnle` | SF=OF et ZF=0 (greater, signé) | `if (a > b)` signé |
| `jge` / `jnl` | SF=OF (greater or equal) | `if (a >= b)` signé |
| `jl` / `jnge` | SF≠OF (less, signé) | `if (a < b)` signé |
| `jle` / `jng` | SF≠OF ou ZF=1 | `if (a <= b)` signé |
| `ja` / `jnbe` | CF=0 et ZF=0 (above, non-signé) | `if (a > b)` non-signé |
| `jae` / `jnb` | CF=0 | `if (a >= b)` non-signé |
| `jb` / `jnae` | CF=1 (below, non-signé) | `if (a < b)` non-signé |
| `jbe` / `jna` | CF=1 ou ZF=1 | `if (a <= b)` non-signé |

**Astuce mnémotechnique** :
- **g/l** (greater/less) = comparaison signée
- **a/b** (above/below) = comparaison non-signée

## 3.3 Pattern : if-else

Code C :
```c
if (a > b) {
    // bloc if
} else {
    // bloc else
}
```

Assembleur typique :
```asm
    cmp eax, ebx        ; compare a et b
    jle else_block      ; si a <= b, saute à else
    ; bloc if ici
    jmp end_if
else_block:
    ; bloc else ici
end_if:
```

## 3.4 Pattern : boucle while

Code C :
```c
while (i < 10) {
    // corps
    i++;
}
```

Assembleur typique :
```asm
loop_start:
    cmp ecx, 10         ; i < 10 ?
    jge loop_end        ; si i >= 10, sort
    ; corps de la boucle
    inc ecx             ; i++
    jmp loop_start
loop_end:
```

## 3.5 Pattern : boucle for

Code C :
```c
for (int i = 0; i < 10; i++) {
    // corps
}
```

C'est identique au while, avec initialisation avant la boucle.

---

**Vidéo recommandée** :
- "how mass satisfies a relation in assembly" - Low Level (6 min)
  https://www.youtube.com/watch?v=TPhF2X1qPao
  (Explication des sauts conditionnels)

---

## Exercice 3.1 : identifier le type de boucle

```asm
    mov ecx, 0
.L1:
    cmp ecx, 100
    jge .L2
    ; ... code ...
    add ecx, 1
    jmp .L1
.L2:
```

Quel est l'équivalent C ?

<details>
<summary>Réponse</summary>

```c
for (int i = 0; i < 100; i++) {
    // ... code ...
}
```
</details>

## Exercice 3.2 : réécrire en C

```asm
    mov eax, [rdi]      ; premier argument
    mov ebx, [rsi]      ; deuxième argument
    cmp eax, ebx
    jle .less_or_equal
    mov eax, 1
    jmp .end
.less_or_equal:
    cmp eax, ebx
    jl .less
    mov eax, 0
    jmp .end
.less:
    mov eax, -1
.end:
    ret
```

<details>
<summary>Réponse</summary>

```c
int compare(int a, int b) {
    if (a > b) return 1;
    else if (a == b) return 0;
    else return -1;
}
```
</details>

---

# Module 4 : fonctions et pile

## 4.1 La pile (stack)

La pile est une zone mémoire qui grandit vers le bas (adresses décroissantes).

```
Adresses hautes
    ↑
    |  [anciennes données]
    |  [return address]     ← après CALL
    |  [saved RBP]          ← prologue
    |  [variables locales]  ← RSP pointe ici
    ↓
Adresses basses
```

**RSP** (Stack Pointer) pointe toujours sur le sommet de la pile.

## 4.2 Instructions de pile

```asm
push rax            ; RSP -= 8, puis stocke rax à [RSP]
pop rbx             ; charge [RSP] dans rbx, puis RSP += 8
```

## 4.3 Convention d'appel (calling convention) - System V AMD64

Sur Linux/macOS x86-64, les arguments sont passés dans cet ordre :

| Argument | Registre |
|----------|----------|
| 1er | RDI |
| 2e | RSI |
| 3e | RDX |
| 4e | RCX |
| 5e | R8 |
| 6e | R9 |
| 7e+ | sur la pile |

**Valeur de retour** : RAX (ou RAX:RDX pour 128 bits)

**Registres préservés** (callee-saved) : RBX, RBP, R12-R15
**Registres non préservés** (caller-saved) : RAX, RCX, RDX, RSI, RDI, R8-R11

## 4.4 Prologue et épilogue de fonction

Quand une fonction est appelée :

**Prologue** (début de fonction) :
```asm
push rbp            ; sauvegarde l'ancien frame pointer
mov rbp, rsp        ; nouveau frame pointer = sommet actuel
sub rsp, 32         ; réserve espace pour variables locales
```

**Épilogue** (fin de fonction) :
```asm
mov rsp, rbp        ; restaure le stack pointer
pop rbp             ; restaure l'ancien frame pointer
ret                 ; retourne à l'appelant
```

Ou version courte :
```asm
leave               ; équivalent à mov rsp, rbp + pop rbp
ret
```

## 4.5 Pattern : appel de fonction

Code C :
```c
int result = add(5, 3);
```

Assembleur :
```asm
mov edi, 5          ; premier argument
mov esi, 3          ; deuxième argument
call add            ; appelle la fonction
; résultat dans eax
mov [result], eax   ; stocke le résultat
```

---

**Vidéo recommandée** :
- "The Call Stack" - CS 61C (UC Berkeley, 12 min)
  https://www.youtube.com/watch?v=Q2sFmqvpBe0
  (Excellente visualisation de la pile)

---

## Exercice 4.1 : identifier les arguments

```asm
func:
    push rbp
    mov rbp, rsp
    mov eax, edi        ; ???
    add eax, esi        ; ???
    imul eax, edx       ; ???
    pop rbp
    ret
```

Questions :
1. Combien d'arguments prend cette fonction ?
2. Qu'est-ce qu'elle calcule ?

<details>
<summary>Réponse</summary>

1. 3 arguments (dans EDI, ESI, EDX)
2. Elle calcule (arg1 + arg2) * arg3
   En C : `int func(int a, int b, int c) { return (a + b) * c; }`
</details>

## Exercice 4.2 : lire un stack frame

```asm
mystery:
    push rbp
    mov rbp, rsp
    sub rsp, 16
    mov dword [rbp-4], edi      ; var1
    mov dword [rbp-8], 0        ; var2
.loop:
    mov eax, [rbp-8]
    cmp eax, [rbp-4]
    jge .end
    add dword [rbp-8], 1
    jmp .loop
.end:
    mov eax, [rbp-8]
    leave
    ret
```

Que fait cette fonction ?

<details>
<summary>Réponse</summary>

```c
int mystery(int n) {
    int i = 0;
    while (i < n) {
        i++;
    }
    return i;
}
```
Autrement dit, elle retourne simplement n (de façon très inefficace).
</details>

---

# Module 5 : introduction à Ghidra

## 5.1 Premier lancement

1. Lance Ghidra : `./ghidraRun` dans le dossier d'installation
2. Crée un nouveau projet : File → New Project → Non-Shared Project
3. Importe un binaire : File → Import File
4. Double-clique sur le fichier pour l'ouvrir dans CodeBrowser
5. Clique "Yes" pour lancer l'analyse automatique

## 5.2 Interface principale

```
┌─────────────┬──────────────────────┬─────────────────┐
│ Program     │ Listing              │ Decompiler      │
│ Trees       │ (vue assembleur)     │ (pseudo-C)      │
├─────────────┤                      │                 │
│ Symbol Tree │                      │                 │
│             │                      │                 │
├─────────────┤                      │                 │
│ Data Type   │                      │                 │
│ Manager     │                      │                 │
└─────────────┴──────────────────────┴─────────────────┘
```

## 5.3 Navigation de base

| Action | Raccourci |
|--------|-----------|
| Aller à une adresse | G |
| Renommer | L |
| Changer le type | T |
| Références croisées (qui appelle ça?) | X |
| Chercher une chaîne | Search → For Strings |
| Chercher dans le code | Search → Memory |
| Commenter | ; |
| Undo | Ctrl+Z |

## 5.4 Workflow typique

1. **Trouver le point d'entrée** : cherche `main` ou `entry` dans Symbol Tree
2. **Identifier les fonctions intéressantes** : regarde les imports (printf, strcmp, socket...)
3. **Suivre le flux** : double-clique sur les appels de fonction
4. **Renommer les variables** : rends le code lisible
5. **Annoter** : ajoute des commentaires

## 5.5 Exercice Ghidra : premier crackme

Télécharge un crackme simple sur https://crackmes.one (difficulté 1.0).

Mot de passe des archives : `crackmes.one`

Étapes :
1. Importe le binaire dans Ghidra
2. Trouve la fonction `main`
3. Cherche les chaînes de caractères (Search → For Strings)
4. Trouve la condition de validation
5. Détermine le mot de passe

---

**Vidéo recommandée** :
- Cours Hackaday "Introduction to Reverse Engineering with Ghidra" (4 sessions)
  https://www.youtube.com/watch?v=d4Pgi5XML8E (session 1, 1h30)
  (Le cours de référence, très complet)

- "Ghidra quickstart & tutorial: Solving a simple crackme" - stacksmashing (15 min)
  https://www.youtube.com/watch?v=fTGTnrgjuGA
  (Plus court, directement applicable)

---

# Module 6 : challenges progressifs

## Niveau 1 : crackmes.one (difficulté 1.0)

1. Va sur https://crackmes.one
2. Filtre : Difficulty 1.0, Language C/C++, Platform Linux
3. Télécharge 3 crackmes et résous-les avec Ghidra

**Objectif** : trouver le mot de passe ou la clé de validation.

## Niveau 2 : TryHackMe

Crée un compte gratuit sur https://tryhackme.com et fais ces rooms dans l'ordre :

1. **CC: Ghidra** - Introduction à l'outil
   https://tryhackme.com/room/ccghidra

2. **Basic Malware RE** - Premiers pas en analyse
   https://tryhackme.com/room/basicmalwarere

3. **REloaded** - Niveau intermédiaire
   https://tryhackme.com/room/dvagstfhg

## Niveau 3 : HackTheBox

Challenges de reverse engineering (nécessite un compte gratuit) :

1. **Find The Easy Pass** - Très facile
2. **Impossible Password** - Facile
3. **Bypass** - Facile (.NET)

Pack complet : https://ctf.hackthebox.com/pack/malware-reversing-essentials

## Niveau 4 : pwn.college

https://pwn.college/computing-101/assembly-crash-course/

Challenges interactifs pour apprendre l'assembleur. Gratuit, excellente pédagogie.

---

# Aide-mémoire : instructions essentielles

## Transfert de données
```
mov dst, src        - Copie src vers dst
lea dst, [addr]     - Charge l'adresse (pas la valeur)
push src            - Empile src
pop dst             - Dépile vers dst
xchg a, b           - Échange a et b
```

## Arithmétique
```
add dst, src        - dst += src
sub dst, src        - dst -= src
inc dst             - dst++
dec dst             - dst--
mul src             - rdx:rax = rax * src (non-signé)
imul dst, src       - dst *= src (signé)
div src             - rax = rdx:rax / src
neg dst             - dst = -dst
```

## Logique
```
and dst, src        - dst &= src
or dst, src         - dst |= src
xor dst, src        - dst ^= src
not dst             - dst = ~dst
shl dst, n          - dst <<= n
shr dst, n          - dst >>= n (logique)
sar dst, n          - dst >>= n (arithmétique)
```

## Comparaison et sauts
```
cmp a, b            - Compare a et b (flags)
test a, b           - a & b (flags)
jmp label           - Saut inconditionnel
je/jz               - Jump if equal/zero
jne/jnz             - Jump if not equal/not zero
jg/jl               - Jump if greater/less (signé)
ja/jb               - Jump if above/below (non-signé)
```

## Fonctions
```
call addr           - Appelle fonction (push RIP, jmp addr)
ret                 - Retour (pop RIP)
leave               - mov rsp, rbp + pop rbp
```

---

# Ressources complémentaires

## Livres gratuits
- **Reverse Engineering for Beginners** (Dennis Yurichev) - https://beginners.re
  Version française disponible, 1000+ pages, LA référence gratuite

- **PC Assembly Language** (Paul Carter) - https://pacman128.github.io/static/pcasm-book-french.pdf
  Traduction française, orienté apprentissage

## Sites de référence
- **Compiler Explorer** : https://godbolt.org
- **x86 Instruction Reference** : https://www.felixcloutier.com/x86/
- **Ghidra Cheat Sheet** : https://ghidra-sre.org/CheatSheet.html

## Chaînes YouTube (anglais, mais très visuelles)
- **Low Level Learning** - Explications claires et courtes
- **LiveOverflow** - Spécialiste RE et CTF
- **John Hammond** - CTF et malware analysis
- **stacksmashing** - Hardware et reverse engineering

## Communautés
- **Root-Me** : https://www.root-me.org (challenges en français)
- **NewbieContest** : https://www.newbiecontest.org (français)
- **Discord "Hack The Box"** : communauté active

---

# Planning suggéré (12 semaines)

| Semaine | Module | Objectif |
|---------|--------|----------|
| 1 | 0 | Installer les outils, premier contact |
| 2-3 | 1 | Maîtriser registres et mémoire |
| 4-5 | 2 | Savoir lire les instructions de base |
| 6-7 | 3 | Comprendre les boucles et conditions |
| 8-9 | 4 | Comprendre les fonctions et la pile |
| 10-11 | 5 | Utiliser Ghidra efficacement |
| 12+ | 6 | Pratiquer sur des challenges |

**Conseil** : ne pas avoir peur de bloquer. Le reverse engineering demande de la patience. Reviens sur les concepts quand tu bloques sur un challenge.

---

Bonne chance ! 🐐
