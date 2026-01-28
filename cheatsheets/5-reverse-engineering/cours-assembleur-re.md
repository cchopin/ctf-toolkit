# Cours d'assembleur x86-64 pour le reverse engineering

**Objectif** : apprendre à lire l'assembleur pour analyser des binaires et des malwares.  
**Plateforme** : Mac M2 (avec solutions de compatibilité pour x86-64)  
**Prérequis** : connaissances de base en C  


---


# Module 0 : environnement et outils

## Pourquoi x86-64 sur un Mac M2 ?

Les Mac M2 utilisent une architecture ARM, mais 95% des malwares Windows/Linux sont en x86-64. Pour le reverse engineering, il est donc nécessaire d'apprendre x86-64.

Point positif : Cutter fonctionne nativement sur Mac et peut analyser des binaires x86-64 sans problème. Il n'est pas nécessaire d'exécuter le code, seulement de le lire.

## Installation des outils

### 1. Homebrew (si non installé)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. Outils de base

```bash
# NASM : assembleur pour écrire du code x86
brew install nasm

# Rizin : framework d'analyse (successeur de Radare2, base de Cutter)
brew install rizin

# LLDB (natif sur Mac, installé avec Xcode Command Line Tools)
xcode-select --install
```

### 3. Cutter (outil principal)

Cutter est une interface graphique libre et open source pour le reverse engineering, basée sur Rizin. Elle intègre un décompilateur (Ghidra ou Jsdec) et offre une expérience utilisateur moderne.

```bash
# Installation via Homebrew
brew install --cask cutter
```

Alternativement, télécharger la dernière version depuis https://cutter.re/

### 4. VM Windows (optionnel mais recommandé)

Pour exécuter et debugger des binaires Windows, installer UTM (gratuit, optimisé Apple Silicon) :

```bash
brew install --cask utm
```

Puis télécharger une ISO Windows 11 ARM ou utiliser les images prêtes à l'emploi sur le site UTM.

### 5. Compiler Explorer (en ligne, sans installation)

https://godbolt.org permet de voir instantanément le code assembleur généré par du code C. C'est l'outil idéal pour apprendre la correspondance C vers assembleur.

---

**Ressource recommandée** :
- Documentation officielle Cutter : https://cutter.re/docs/
- Chaîne YouTube Rizin : https://www.youtube.com/@RizinOrg

---

## Exercice 0.1 : vérifier l'installation

```bash
# Vérifier que NASM fonctionne
nasm -v

# Vérifier que Rizin fonctionne
rizin -v

# Lancer Cutter
open -a Cutter
```

## Exercice 0.2 : premier contact avec Compiler Explorer

1. Accéder à https://godbolt.org
2. Sélectionner le langage C et le compilateur "x86-64 gcc"
3. Saisir ce code :

```c
int add(int a, int b) {
    return a + b;
}
```

4. Observer le code assembleur généré à droite
5. Modifier les options de compilation : ajouter `-O0` (pas d'optimisation) puis `-O2` (optimisé)
6. Comparer les deux résultats

**Question** : combien d'instructions génère la version non optimisée vs optimisée ?

---

# Module 1 : fondamentaux - registres et mémoire

## 1.1 Qu'est-ce qu'un registre ?

Un registre est une petite zone de mémoire ultra-rapide directement dans le CPU. Les registres peuvent être considérés comme des variables intégrées au processeur.

En x86-64, il existe 16 registres généraux de 64 bits :

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

**Importance en reverse engineering** : du code manipulant `EAX` au lieu de `RAX` indique que le programme travaille avec des valeurs 32 bits.

---

**Vidéo recommandée** :
- "Assembly Language in 100 Seconds" - Fireship (2 min)
  https://www.youtube.com/watch?v=4gwYkEK0gOk
  (Vue d'ensemble rapide)

---

## 1.3 La mémoire et les adresses

La mémoire est un grand tableau d'octets. Chaque octet possède une adresse unique.

```
Adresse     Contenu
0x0000      [XX]
0x0001      [XX]
...
0x7FFF      [XX]  <- zone utilisateur
...
0xFFFF...   [XX]  <- zone kernel (inaccessible)
```

**Little-endian** : sur x86, les octets sont stockés en ordre inversé.

Exemple : la valeur `0x12345678` est stockée comme :
```
Adresse:  0x100  0x101  0x102  0x103
Contenu:   78     56     34     12
```

Cette particularité est contre-intuitive mais essentielle à connaître en reverse engineering.

## 1.4 Modes d'adressage

En assembleur, l'accès à la mémoire peut se faire de plusieurs façons :

| Syntaxe | Signification |
|---------|---------------|
| `mov rax, 42` | Valeur immédiate : rax = 42 |
| `mov rax, rbx` | Registre à registre : rax = rbx |
| `mov rax, [rbx]` | Indirection : rax = valeur à l'adresse dans rbx |
| `mov rax, [rbx+8]` | Base + déplacement |
| `mov rax, [rbx+rcx*4]` | Base + index * échelle |
| `mov rax, [rbx+rcx*4+16]` | Complet : base + index*scale + displacement |

Les crochets `[]` signifient "récupérer la valeur à cette adresse".

---

## Exercice 1.1 : registres dans Compiler Explorer

Sur https://godbolt.org, compiler ce code :

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

Si les octets `41 42 43 44` apparaissent en mémoire à partir de l'adresse `0x1000`, quelle est la valeur 32 bits stockée ?

<details>
<summary>Réponse</summary>

En little-endian, la valeur est `0x44434241`.
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

**Attention** : l'instruction `mov [rax], [rbx]` (mémoire vers mémoire) n'est pas valide. Il faut passer par un registre.

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
| `shl dst, n` | Décalage gauche | `shl rax, 2` (x 4) |
| `shr dst, n` | Décalage droite | `shr rax, 1` (/ 2) |

**Pattern courant en RE** : `xor rax, rax` est la façon idiomatique de mettre un registre à zéro (plus rapide que `mov rax, 0`).

## 2.4 Instructions de comparaison

```asm
cmp rax, rbx        ; Compare rax et rbx (effectue rax - rbx sans stocker)
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
  (Lien C vers assembleur)

---

## Exercice 2.1 : traduire en assembleur (mental)

Sans compiler, déterminer ce que fait ce code assembleur :

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

Il s'agit d'une boucle qui calcule la somme de 10 à 1 : 10+9+8+7+6+5+4+3+2+1 = 55
- `xor eax, eax` : eax = 0
- `mov ecx, 10` : ecx = compteur = 10
- boucle : eax += ecx, ecx--, si ecx != 0 recommence
</details>

## Exercice 2.3 : Compiler Explorer avancé

Sur godbolt.org, écrire une fonction C qui :
1. Prend deux entiers
2. Retourne le plus grand

```c
int max(int a, int b) {
    if (a > b) return a;
    else return b;
}
```

Observer le code généré. Les instructions `cmp` et les sauts conditionnels devraient être visibles.

---

# Module 3 : flux de contrôle

## 3.1 Les sauts inconditionnels

```asm
jmp label           ; Saute toujours à label
```

Équivalent C : `goto label;`

## 3.2 Les sauts conditionnels

Après un `cmp` ou `test`, il est possible de sauter conditionnellement :

| Instruction | Condition | Usage typique |
|-------------|-----------|---------------|
| `je` / `jz` | ZF=1 (égal / zéro) | `if (a == b)` |
| `jne` / `jnz` | ZF=0 (différent / non-zéro) | `if (a != b)` |
| `jg` / `jnle` | SF=OF et ZF=0 (greater, signé) | `if (a > b)` signé |
| `jge` / `jnl` | SF=OF (greater or equal) | `if (a >= b)` signé |
| `jl` / `jnge` | SF!=OF (less, signé) | `if (a < b)` signé |
| `jle` / `jng` | SF!=OF ou ZF=1 | `if (a <= b)` signé |
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

Structure identique au while, avec initialisation avant la boucle.

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
    |
    |  [anciennes données]
    |  [return address]     <- après CALL
    |  [saved RBP]          <- prologue
    |  [variables locales]  <- RSP pointe ici
    v
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
  (Visualisation de la pile)

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

# Module 5 : introduction à Cutter

## 5.1 Présentation de Cutter

Cutter est une plateforme libre et open source de reverse engineering. Elle est basée sur Rizin (un fork de Radare2) et offre une interface graphique moderne et intuitive.

**Avantages de Cutter** :
- Interface graphique native et réactive
- Intégration du décompilateur Ghidra ou Jsdec
- Graphes de flux de contrôle interactifs
- Débogueur intégré
- Scripting Python
- Multiplateforme (Linux, macOS, Windows)
- Entièrement gratuit et open source

## 5.2 Premier lancement

1. Lancer Cutter depuis le dossier Applications ou via le terminal
2. Cliquer sur "Open File" et sélectionner un binaire à analyser
3. Dans la fenêtre d'options, conserver les paramètres par défaut
4. Cocher "Analyze all referenced code" pour une analyse complète
5. Cliquer sur "OK" pour lancer l'analyse

## 5.3 Interface principale

```
+-------------+----------------------+-----------------+
| Fonctions   | Désassembleur        | Décompilateur   |
|             | (vue assembleur)     | (pseudo-C)      |
+-------------+                      |                 |
| Imports     |                      |                 |
|             |                      |                 |
+-------------+                      |                 |
| Strings     |                      |                 |
|             |                      |                 |
+-------------+----------------------+-----------------+
| Console Rizin                                        |
+------------------------------------------------------+
```

**Panneaux principaux** :
- **Fonctions** : liste des fonctions détectées
- **Imports** : fonctions importées depuis des bibliothèques
- **Strings** : chaînes de caractères trouvées dans le binaire
- **Désassembleur** : code assembleur avec possibilité de vue graphique
- **Décompilateur** : code pseudo-C généré automatiquement
- **Console** : accès aux commandes Rizin

## 5.4 Navigation de base

| Action | Raccourci |
|--------|-----------|
| Aller à une adresse | G |
| Renommer une fonction/variable | N |
| Ajouter un commentaire | ; |
| Basculer vue graphique/linéaire | Espace |
| Références croisées (xrefs) | X |
| Chercher une chaîne | Ctrl+Shift+F |
| Undo | Ctrl+Z |
| Afficher le décompilateur | Tab |

## 5.5 Workflow typique

1. **Identifier le point d'entrée** : chercher `main` ou `entry` dans la liste des fonctions
2. **Explorer les imports** : identifier les fonctions système utilisées (printf, strcmp, socket, etc.)
3. **Analyser les strings** : les chaînes de caractères révèlent souvent le comportement du programme
4. **Suivre le flux** : double-cliquer sur les appels de fonction pour naviguer
5. **Renommer les éléments** : améliorer la lisibilité en donnant des noms explicites
6. **Annoter** : ajouter des commentaires pour documenter l'analyse

## 5.6 Vue graphique

La vue graphique (activée avec Espace) affiche le flux de contrôle sous forme de blocs connectés :
- Les blocs verts indiquent un saut conditionnel pris (true)
- Les blocs rouges indiquent un saut conditionnel non pris (false)
- Les flèches montrent les transitions entre blocs

Cette vue est particulièrement utile pour comprendre les boucles et les conditions.

## 5.7 Utilisation du décompilateur

Le décompilateur génère du pseudo-code C à partir de l'assembleur. Pour l'utiliser :

1. Sélectionner une fonction dans le panneau de gauche
2. Le code décompilé apparaît dans le panneau de droite
3. Les variables peuvent être renommées directement dans cette vue
4. Les types peuvent être modifiés pour améliorer la lisibilité

**Note** : le code décompilé est une approximation. Il peut contenir des erreurs ou des constructions inhabituelles. Toujours vérifier avec le code assembleur en cas de doute.

## 5.8 Exercice Cutter : premier crackme

Télécharger un crackme simple sur https://crackmes.one (difficulté 1.0).

Mot de passe des archives : `crackmes.one`

Étapes :
1. Importer le binaire dans Cutter
2. Localiser la fonction `main`
3. Examiner les chaînes de caractères (panneau Strings)
4. Identifier la condition de validation dans le décompilateur
5. Déterminer le mot de passe attendu

---

**Ressources Cutter** :
- Documentation officielle : https://cutter.re/docs/
- GitHub : https://github.com/rizinorg/cutter

---

# Module 6 : challenges progressifs

## Niveau 1 : crackmes.one (difficulté 1.0)

1. Accéder à https://crackmes.one
2. Filtrer : Difficulty 1.0, Language C/C++, Platform Linux
3. Télécharger 3 crackmes et les résoudre avec Cutter

**Objectif** : trouver le mot de passe ou la clé de validation.

## Niveau 2 : TryHackMe

Créer un compte gratuit sur https://tryhackme.com et suivre ces rooms dans l'ordre :

1. **Basic Malware RE** - Premiers pas en analyse
   https://tryhackme.com/room/basicmalwarere

2. **Reversing ELF** - Analyse de binaires Linux
   https://tryhackme.com/room/reverselfiles

3. **REloaded** - Niveau intermédiaire
   https://tryhackme.com/room/dvagstfhg

## Niveau 3 : HackTheBox

Challenges de reverse engineering (compte gratuit requis) :

1. **Find The Easy Pass** - Très facile
2. **Impossible Password** - Facile
3. **Bypass** - Facile (.NET)

Pack complet : https://ctf.hackthebox.com/pack/malware-reversing-essentials

## Niveau 4 : pwn.college

https://pwn.college/computing-101/assembly-crash-course/

Challenges interactifs pour apprendre l'assembleur. Gratuit, pédagogie de qualité.

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
  Version française disponible, 1000+ pages, référence gratuite majeure

- **PC Assembly Language** (Paul Carter) - https://pacman128.github.io/static/pcasm-book-french.pdf
  Traduction française, orienté apprentissage

## Sites de référence
- **Compiler Explorer** : https://godbolt.org
- **x86 Instruction Reference** : https://www.felixcloutier.com/x86/
- **Cutter Documentation** : https://cutter.re/docs/
- **Rizin Book** : https://book.rizin.re/

## Chaînes YouTube (anglais, contenu visuel)
- **Low Level Learning** - Explications claires et courtes
- **LiveOverflow** - Spécialiste RE et CTF
- **John Hammond** - CTF et malware analysis
- **stacksmashing** - Hardware et reverse engineering

## Communautés
- **Root-Me** : https://www.root-me.org (challenges en français)
- **NewbieContest** : https://www.newbiecontest.org (français)
- **Discord Rizin** : communauté active autour de Cutter/Rizin

---

# Planning suggéré (12 semaines)

| Semaine | Module | Objectif |
|---------|--------|----------|
| 1 | 0 | Installer les outils, premier contact |
| 2-3 | 1 | Maîtriser registres et mémoire |
| 4-5 | 2 | Savoir lire les instructions de base |
| 6-7 | 3 | Comprendre les boucles et conditions |
| 8-9 | 4 | Comprendre les fonctions et la pile |
| 10-11 | 5 | Utiliser Cutter efficacement |
| 12+ | 6 | Pratiquer sur des challenges |

**Conseil** : 
le reverse engineering demande de la patience. 
Il est normal de bloquer régulièrement. 
Revenir sur les concepts fondamentaux aide souvent à débloquer une situation.

---
