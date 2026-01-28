# Hunting License - Write-up HackTheBox

![HTB Hunting License](https://img.shields.io/badge/HackTheBox-Hunting_License-green)![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen)![Category](https://img.shields.io/badge/Category-Reversing-blue)

## Résumé

| Info | Valeur |
|------|--------|
| **Flag** | `HTB{XXXXXXXXXXXXXXXXXXXXXXX}` |
| **Vulnérabilité** | Mots de passe faiblement protégés |
| **Techniques** | Stockage en clair, inversion de chaîne, chiffrement XOR |
| **Outils** | strings, radare2/Cutter, file, ldd |

---

## Table des matières

1. [Introduction](#introduction)
2. [Prérequis](#prérequis)
3. [Tutoriel assembleur x86-64](#tutoriel-assembleur-x86-64)
4. [Méthodologie d'analyse](#méthodologie-danalyse)
5. [Analyse du challenge](#analyse-du-challenge)
6. [Commandes radare2 essentielles](#commandes-radare2-essentielles)
7. [Ressources](#ressources)

---

## Introduction

Ce challenge d'introduction au reverse engineering présente un binaire Linux qui demande trois mots de passe successifs. Chaque mot de passe utilise une technique de protection différente, ce qui en fait un excellent exercice pédagogique pour apprendre les bases de l'analyse de binaires.

---

## Prérequis

### Outils nécessaires

- **strings** : extraction des chaînes de caractères lisibles d'un binaire
- **file** : identification du format d'un fichier
- **ldd** : liste des bibliothèques dynamiques liées
- **radare2** ou **Cutter** : désassembleur et débogueur
- **Ghidra** (optionnel) : décompilateur avancé

### Environnement

Le binaire est un exécutable Linux ELF 64-bit. Sur macOS ou Windows, un environnement Linux est nécessaire (VM, Docker, ou Exegol).

---

## Tutoriel assembleur x86-64

### Les registres

#### Concept

La RAM (mémoire vive) représente l'entrepôt : beaucoup de place, mais un temps d'accès non négligeable. Les registres sont des petits casiers directement dans le processeur : peu nombreux, mais accès instantané.

Un processeur x86-64 dispose d'une quinzaine de registres principaux. Chacun peut stocker un nombre sur 64 bits.

#### Registres principaux et leur rôle

| Registre | Rôle | Exemple d'utilisation |
|----------|------|----------------------|
| RAX | Valeur de retour | Après `call strlen`, RAX contient la longueur |
| RBX | Usage général | Stockage temporaire |
| RCX | 4e argument | `xor(_, _, _, cle)` → clé dans RCX |
| RDX | 3e argument | `xor(_, _, longueur, _)` → longueur dans RDX |
| RSI | 2e argument | `xor(_, source, _, _)` → source dans RSI |
| RDI | 1er argument | `xor(dest, _, _, _)` → dest dans RDI |
| RBP | Base de la pile | Repère pour les variables locales |
| RSP | Sommet de la pile | Pointe vers le haut de la pile |

#### Les sous-registres

Chaque registre 64 bits peut être accédé en morceaux plus petits :

```
RAX (64 bits) - Le registre complet
┌────────────────────────────────────────────────────────────────┐
│                              RAX                               │
│  (64 bits = 8 octets)                                          │
└────────────────────────────────────────────────────────────────┘

Accès à la moitié basse (32 bits) :
┌────────────────────────────────┬───────────────────────────────┐
│      (partie haute 32 bits)    │             EAX               │
│         (pas de nom)           │    (32 bits = 4 octets)       │
└────────────────────────────────┴───────────────────────────────┘

Accès aux 16 bits les plus bas :
┌────────────────────────────────────────────────┬───────────────┐
│              (partie haute)                    │      AX       │
│                                                │  (16 bits)    │
└────────────────────────────────────────────────┴───────────────┘

Accès aux 8 bits les plus bas (AL) ou les 8 bits juste au-dessus (AH) :
┌────────────────────────────────────────────────┬───────┬───────┐
│                                                │  AH   │  AL   │
│                                                │(8bits)│(8bits)│
└────────────────────────────────────────────────┴───────┴───────┘
```

#### Tableau récapitulatif des sous-registres

| 64 bits | 32 bits | 16 bits | 8 bits (bas) | 8 bits (haut) |
|---------|---------|---------|--------------|---------------|
| RAX | EAX | AX | AL | AH |
| RBX | EBX | BX | BL | BH |
| RCX | ECX | CX | CL | CH |
| RDX | EDX | DX | DL | DH |
| RSI | ESI | SI | SIL | - |
| RDI | EDI | DI | DIL | - |
| RBP | EBP | BP | BPL | - |
| RSP | ESP | SP | SPL | - |

#### Règle simple

- **R**XX = 64 bits (le R vient de "Register" étendu pour 64 bits)
- **E**XX = 32 bits (le E vient de "Extended" pour 32 bits)
- XX = 16 bits (format original des anciens processeurs)
- XL = 8 bits bas ("Low")
- XH = 8 bits haut ("High") - seulement pour A, B, C, D

### Convention d'appel System V AMD64

Sous Linux x86-64, les arguments des fonctions sont passés dans cet ordre :

1. RDI (1er argument)
2. RSI (2e argument)
3. RDX (3e argument)
4. RCX (4e argument)
5. R8 (5e argument)
6. R9 (6e argument)
7. Arguments suivants sur la pile

### Instructions essentielles

#### MOV : déplacement de données

```asm
mov rax, rbx        ; Copie rbx dans rax
mov rax, 0x13       ; Met la valeur 0x13 (19) dans rax
mov rax, [rbx]      ; Charge la valeur pointée par rbx dans rax
mov [rax], rbx      ; Stocke rbx à l'adresse pointée par rax
```

Les crochets `[]` indiquent un accès mémoire (déréférencement de pointeur).

#### LEA : chargement d'adresse

```asm
lea rax, [var_38h]  ; Charge l'ADRESSE de var_38h dans rax (pas sa valeur)
```

#### La pile (stack)

La pile fonctionne selon le principe LIFO : Last In, First Out (dernier arrivé, premier sorti). Elle grandit vers le bas (vers les adresses basses).

```
Adresses hautes
    ┌─────────────────┐
    │ Données plus    │
    │ anciennes       │
    ├─────────────────┤
    │ Variable locale │
    ├─────────────────┤
    │ Autre variable  │
    ├─────────────────┤
    │ Encore une      │ ← RSP pointe ici (sommet de la pile)
    └─────────────────┘
Adresses basses (la pile grandit vers ici)
```

#### PUSH et POP

```asm
push rbp            ; Empile la valeur de rbp (sauvegarde)
                    ; RSP diminue de 8 (64 bits = 8 octets)

pop rbp             ; Dépile dans rbp (restauration)
                    ; RSP augmente de 8
```

### Structure d'une fonction

#### Le prologue (début de fonction)

```asm
push rbp            ; 1. Sauvegarde l'ancien "repère" de pile
mov rbp, rsp        ; 2. Établit un nouveau repère (base pointer)
sub rsp, 0x30       ; 3. Réserve 0x30 (48) octets pour les variables locales
```

#### L'épilogue (fin de fonction)

```asm
leave               ; Équivalent à : mov rsp, rbp; pop rbp
ret                 ; Retourne à l'appelant
```

### Variables locales

Dans les outils comme radare2 ou Cutter, les variables locales sont nommées automatiquement :

```
[rbp - 0x8]   →  var_8h
[rbp - 0x10]  →  var_10h
[rbp - 0x38]  →  var_38h
```

### XOR : opération fondamentale pour ce challenge

Le XOR est une opération logique bit à bit :

```
0 XOR 0 = 0
0 XOR 1 = 1
1 XOR 0 = 1
1 XOR 1 = 0
```

La propriété clé du XOR : **il est réversible avec la même clé**.

```
Message:     01001000  (lettre 'H' en binaire, code ASCII 72)
Clé:         00010011  (19 en binaire)
             ────────
Chiffré:     01011011  (résultat du XOR = 91)

Pour déchiffrer, on refait XOR avec la même clé :

Chiffré:     01011011  (91)
Clé:         00010011  (19)
             ────────
Déchiffré:   01001000  (72 = 'H')
```

### CMP, TEST et sauts conditionnels

```asm
cmp rax, rbx        ; Compare rax et rbx (fait rax - rbx sans stocker)
test eax, eax       ; Vérifie si eax est zéro

je  0x401333        ; Jump if Equal (saute si ZF = 1)
jne 0x401333        ; Jump if Not Equal (saute si ZF = 0)
jmp 0x401272        ; Jump inconditionnel
```

Pattern courant pour vérifier un mot de passe :

```asm
call strcmp         ; Compare deux chaînes, retourne 0 si égales
test eax, eax       ; Est-ce que eax est zéro ?
je  0x4012c9        ; Si oui (chaînes égales), saute vers le succès
```

---

## Méthodologie d'analyse

### Étape 1 : identification du binaire

```bash
file binaire
```

Questions à se poser :
- Quel est le format du fichier ? (ELF, PE, Mach-O...)
- Quelle architecture ? (x86, x86-64, ARM...)
- Est-il strippé ? (symboles de debug supprimés ou non)

### Étape 2 : extraction des chaînes

```bash
strings binaire | head -50
strings binaire | grep -i password
```

Éléments à rechercher :
- Messages affichés à l'utilisateur
- Chaînes suspectes (mots de passe potentiels)
- Noms de fonctions et bibliothèques

### Étape 3 : identification des bibliothèques

```bash
ldd binaire
```

### Étape 4 : analyse statique

Avec un désassembleur (radare2, Cutter, Ghidra) :

1. Lister les fonctions (`afl` dans r2)
2. Identifier les fonctions intéressantes (main, fonctions personnalisées)
3. Analyser le flux de contrôle
4. Comprendre la logique des comparaisons

### Étape 5 : analyse dynamique (optionnel)

Exécuter le programme et observer son comportement avec `ltrace` ou `strace`.

---

## Analyse du challenge

### Reconnaissance initiale

L'identification du binaire et l'extraction des chaînes révèlent :
- Des messages de bienvenue et des prompts
- Des chaînes qui ressemblent à des mots de passe ou des données encodées
- Des noms de fonctions personnalisées

### Premier mot de passe : stockage en clair

Le premier mot de passe est décrit comme "not even hidden". En analysant la sortie de `strings` ou le code désassemblé, une chaîne est directement comparée avec l'entrée utilisateur via `strcmp`.

### Deuxième mot de passe : inversion

Le message d'erreur pour le second mot de passe contient un indice : "backwards".

L'analyse du code révèle :
- Une fonction nommée `reverse`
- Une chaîne stockée dans le binaire
- Un appel à `reverse` suivi d'un `strcmp`

Le programme inverse une chaîne stockée, puis compare avec l'entrée utilisateur. Il faut donc trouver la chaîne stockée et l'inverser :

```bash
echo "chaine_trouvee" | rev
```

### Troisième mot de passe : chiffrement XOR

Le troisième mot de passe est décrit comme "most protected". L'analyse révèle :
- Une fonction nommée `xor`
- Une chaîne encodée
- Une clé de chiffrement

#### Analyse de la fonction XOR

La fonction `sym.xor` contient une boucle qui :
1. Lit chaque octet de la chaîne source
2. Applique XOR avec une clé
3. Stocke le résultat

#### Identification des paramètres

Avant l'appel à `xor`, les instructions `mov` préparent les arguments :
- Le registre ECX contient la clé (4e argument)
- Le registre EDX contient la longueur (3e argument)
- Le registre ESI contient l'adresse de la chaîne encodée (2e argument)

#### Déchiffrement

Une fois la clé trouvée, l'appliquer à chaque octet de la chaîne encodée :

```python
chaine_encodee = [...]  # Octets de la chaîne
cle = ...               # Valeur trouvée dans ECX

for octet in chaine_encodee:
    print(chr(octet ^ cle), end='')
```

Pour voir les octets bruts dans radare2 :

```
px <longueur> @<adresse>
```

---

## Commandes radare2 essentielles

### Ouverture et analyse

```bash
r2 -A ./binaire       # Ouvre avec analyse automatique
```

### Navigation

```
afl                   # Liste toutes les fonctions
s main                # Se déplacer vers main
s 0x401172            # Se déplacer vers une adresse
```

### Désassemblage

```
pdf                   # Print Disassemble Function (fonction courante)
pdf @main             # Désassembler main
pdf @sym.xor          # Désassembler la fonction xor
```

### Affichage mémoire

```
px 32 @0x404070       # Affiche 32 octets en hex à l'adresse donnée
ps @0x402170          # Affiche la chaîne à cette adresse
```

### Décompilation (si r2ghidra est installé)

```
pdg @main             # Décompile main en pseudo-code C
```

---

## Utilisation de Cutter

1. **Ouvrir un fichier** : File > Open
2. **Analyser** : Cutter analyse automatiquement à l'ouverture
3. **Liste des fonctions** : panneau "Fonctions" à gauche
4. **Désassemblage** : panneau central
5. **Décompilation** : onglet "Décompileur" en bas

Pour trouver les paramètres d'un appel de fonction, remonter depuis l'instruction `call` et identifier les `mov` qui préparent les registres RDI, RSI, RDX, RCX.

---

## Leçons apprises

Ce challenge illustre trois niveaux de "protection" de mots de passe :

1. **Aucune protection** : stockage en clair
2. **Obfuscation simple** : inversion de chaîne
3. **Chiffrement basique** : XOR avec clé fixe

Ces techniques sont considérées comme très faibles en sécurité réelle, mais constituent une excellente introduction aux concepts fondamentaux du reverse engineering.

---

## Ressources

- [x86-64 Assembly Guide](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf)
- [Radare2 Book](https://book.rada.re/)
- [Ghidra Documentation](https://ghidra-sre.org/)
- [CyberChef](https://gchq.github.io/CyberChef/) pour les transformations de données

---

## Glossaire

| Terme | Définition |
|-------|------------|
| ELF | Executable and Linkable Format, format binaire standard sous Linux |
| Désassembleur | Outil qui convertit le code machine en assembleur lisible |
| Décompilateur | Outil qui reconstruit du pseudo-code haut niveau depuis le binaire |
| XOR | Opération logique "ou exclusif", réversible |
| Stack | Pile mémoire utilisée pour les variables locales et appels de fonctions |
| Registre | Emplacement mémoire rapide dans le processeur |
| Prologue | Code d'initialisation au début d'une fonction |
| Épilogue | Code de nettoyage à la fin d'une fonction |
