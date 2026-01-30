# Shattered Tablet - Write-up HackTheBox

![HTB Shattered Tablet](https://img.shields.io/badge/HackTheBox-Shattered__Tablet-green)![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen)![Category](https://img.shields.io/badge/Category-Reverse-blue)

## Résumé

| Info | Valeur |
|------|--------|
| **Flag** | `HTB{XXXXXXXXXXXXXXXXXXXXXXX}` |
| **Vulnérabilité** | Comparaisons caractère par caractère dans le binaire |
| **Contrainte** | Les caractères sont vérifiés dans un ordre non-séquentiel |
| **Technique** | Extraction des comparaisons via désassemblage et reconstruction du flag |

---

## Table des matières

1. [Introduction pour les débutants](#introduction-pour-les-débutants)
2. [Outils nécessaires](#outils-nécessaires)
3. [Étape 1 : Reconnaissance du fichier](#étape-1--reconnaissance-du-fichier)
4. [Étape 2 : Exécution du programme](#étape-2--exécution-du-programme)
5. [Étape 3 : Analyse des chaînes de caractères](#étape-3--analyse-des-chaînes-de-caractères)
6. [Étape 4 : Identifier les fonctions](#étape-4--identifier-les-fonctions)
7. [Étape 5 : Désassembler le programme](#étape-5--désassembler-le-programme)
8. [Étape 6 : Comprendre le mécanisme de vérification](#étape-6--comprendre-le-mécanisme-de-vérification)
9. [Crash course : Comprendre les comparaisons en assembleur](#crash-course--comprendre-les-comparaisons-en-assembleur)
10. [Étape 7 : Extraire les comparaisons](#étape-7--extraire-les-comparaisons)
11. [Étape 8 : Extraire et reconstruire le flag](#étape-8--extraire-et-reconstruire-le-flag)
12. [Leçons apprises](#leçons-apprises)

---

## Introduction pour les débutants

### C'est quoi un challenge "Reverse Engineering" ?

Le reverse engineering (ou "rétro-ingénierie") consiste à analyser un programme compilé pour comprendre son fonctionnement sans avoir accès au code source original. Dans ce challenge, on va :

1. Analyser un binaire qui demande un mot de passe
2. Comprendre comment il vérifie ce mot de passe
3. Extraire le mot de passe correct (le flag) directement depuis le code

### Pourquoi c'est possible ?

Quand un programme compare ton entrée avec un mot de passe, les valeurs de comparaison sont souvent **codées en dur** dans le binaire. En désassemblant le programme, on peut voir ces valeurs et reconstituer le mot de passe.

### C'est quoi la "stack" (pile) ?

La stack est une zone mémoire utilisée par les programmes pour stocker temporairement des données : variables locales, adresses de retour, etc. Elle fonctionne comme une pile d'assiettes : on pose dessus (push) et on retire du dessus (pop).

Dans ce challenge, notre entrée est stockée sur la stack, et le programme compare chaque caractère à une position spécifique.

---

## Outils nécessaires

### Installation

```bash
# Sur Ubuntu/Debian
sudo apt update
sudo apt install binutils file

# Python pour le script d'extraction
# (déjà installé sur la plupart des systèmes)
```

### Outils optionnels mais recommandés

```bash
# Cutter (désassembleur graphique basé sur Rizin)
# Télécharger depuis : https://cutter.re/

# Ou Ghidra (désassembleur de la NSA, gratuit)
# Télécharger depuis : https://ghidra-sre.org/
```

### Explication des outils

#### `file` - Identifier le type de fichier

**C'est quoi ?** Une commande qui analyse les premiers bytes d'un fichier pour déterminer son type.

```bash
file tablet
# Résultat : ELF 64-bit LSB pie executable, x86-64...
```

---

#### `strings` - Extraire les chaînes de caractères

**C'est quoi ?** Une commande qui parcourt un fichier binaire et affiche toutes les séquences de caractères lisibles.

**Pourquoi c'est utile ?** Les programmes contiennent souvent des messages, des indices, parfois même des mots de passe en clair.

```bash
strings tablet | head -20
```

---

#### `nm` - Lister les symboles

**C'est quoi ?** `nm` affiche la table des symboles d'un binaire : noms des fonctions, variables globales, etc.

```bash
nm tablet | grep " T "
```

---

#### `objdump` - Désassembler le code

**C'est quoi ?** Un outil qui convertit le code machine en instructions assembleur lisibles.

```bash
objdump -d -M intel tablet | less
```

**Options importantes :**
| Option | Effet |
|--------|-------|
| `-d` | Désassembler les sections de code |
| `-M intel` | Syntaxe Intel (plus lisible que AT&T) |

---

#### Cutter/Ghidra - Désassembleurs graphiques

**C'est quoi ?** Des outils qui offrent une interface graphique pour analyser des binaires, avec des fonctionnalités avancées comme la décompilation (conversion en pseudo-code C).

**Pourquoi c'est utile ?** Ils permettent de visualiser le flux du programme sous forme de graphe, ce qui facilite la compréhension de la logique.

---

## Étape 1 : Reconnaissance du fichier

### Commande

```bash
file tablet
```

### Résultat

```
tablet: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, not stripped
```

### Explication détaillée

| Terme | Signification |
|-------|---------------|
| **ELF** | Format de fichier exécutable pour Linux |
| **64-bit** | Programme pour processeur 64 bits |
| **LSB** | Little-endian (ordre des bytes) |
| **pie executable** | Position Independent Executable |
| **x86-64** | Architecture Intel/AMD 64 bits |
| **dynamically linked** | Utilise des bibliothèques externes |
| **not stripped** | Les symboles sont conservés (noms des fonctions visibles) |

**Point clé** : "not stripped" signifie qu'on pourra voir les noms des fonctions, ce qui facilite l'analyse.

---

## Étape 2 : Exécution du programme

### Test initial

```bash
chmod +x tablet
./tablet
```

### Résultat

```
Hmmmm... I think the tablet says:
test_input
Wrong!
```

Le programme attend une entrée et affiche "Wrong!" si ce n'est pas le bon mot de passe.

### Ce qu'on apprend

1. Le programme lit une entrée utilisateur
2. Il la compare avec quelque chose
3. Il affiche "Wrong!" si ça ne correspond pas

**Objectif** : Trouver quelle valeur le programme attend.

---

## Étape 3 : Analyse des chaînes de caractères

### Commande

```bash
strings tablet | grep -i "wrong\|right\|flag\|correct"
```

### Résultat

```
Wrong!
```

### Analyse complète

```bash
strings tablet
```

### Résultat (extraits)

```
Hmmmm... I think the tablet says:
Wrong!
/lib64/ld-linux-x86-64.so.2
__isoc99_scanf
puts
__libc_start_main
libc.so.6
```

### Ce qu'on apprend

1. **Pas de flag en clair** dans les strings (ce serait trop facile !)
2. Le programme utilise `scanf` pour lire l'entrée
3. Il utilise `puts` pour afficher des messages

**Conclusion** : Le flag n'est pas stocké comme une simple chaîne. Il est probablement vérifié caractère par caractère.

---

## Étape 4 : Identifier les fonctions

### Commande

```bash
nm tablet | grep " T "
```

### Résultat

```
0000000000001169 T main
```

### Ce qu'on apprend

Le binaire est simple : il n'y a qu'une fonction `main`. Toute la logique de vérification est dedans.

---

## Étape 5 : Désassembler le programme

### Avec objdump

```bash
objdump -d -M intel tablet | grep -A 200 "<main>:"
```

### Avec un désassembleur graphique (Cutter)

En ouvrant le binaire dans Cutter, on observe la fonction `main` sous forme de graphe avec **38-40 blocs** de comparaison.

### Structure observée

```
┌─────────────────────────────────────────────────────────────┐
│                    STRUCTURE DU MAIN                        │
├─────────────────────────────────────────────────────────────┤
│  1. Affiche "Hmmmm... I think the tablet says:"             │
│  2. Lit l'entrée utilisateur avec scanf                     │
│  3. Série de ~40 comparaisons caractère par caractère       │
│  4. Si TOUTES les comparaisons réussissent → succès         │
│  5. Si UNE comparaison échoue → "Wrong!"                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Étape 6 : Comprendre le mécanisme de vérification

### Analyse d'un bloc de comparaison

Chaque bloc de comparaison ressemble à ceci (syntaxe AT&T par défaut) :

```asm
movzbl -0x40(%rbp),%eax    # Charge le caractère à l'offset 0x40 de rbp
cmp    $0x48,%al           # Compare avec 0x48 (= 'H' en ASCII)
jne    <wrong>             # Si différent, saute vers "Wrong!"
```

Ou en syntaxe Intel (plus lisible) :

```asm
movzx  eax, BYTE PTR [rbp-0x40]   # Charge le caractère à rbp-0x40
cmp    al, 0x48                    # Compare avec 0x48 ('H')
jne    wrong                       # Saute si différent
```

### Explication détaillée

| Instruction | Signification |
|-------------|---------------|
| `movzbl -0x40(%rbp),%eax` | Charge 1 byte depuis l'adresse `rbp - 0x40` dans `eax`, avec extension à zéro |
| `cmp $0x48,%al` | Compare le byte bas de `eax` avec la valeur `0x48` |
| `jne <wrong>` | "Jump if Not Equal" : saute vers le code d'erreur si les valeurs sont différentes |

### Le buffer d'entrée sur la stack

Notre entrée est stockée sur la stack à partir de `rbp - 0x40` :

```
Adresse stack        Position dans le buffer
─────────────────────────────────────────────
rbp - 0x40     →     position 0  (1er caractère)
rbp - 0x3f     →     position 1  (2ème caractère)
rbp - 0x3e     →     position 2  (3ème caractère)
...
rbp - 0x19     →     position 39 (40ème caractère)
```

**Formule** : `position = 0x40 - offset`

Exemple : offset `0x3f` → position = `0x40 - 0x3f` = `1` (2ème caractère)

### L'astuce anti-reverse

**Observation importante** : Les comparaisons ne sont PAS dans l'ordre séquentiel !

Le programme vérifie d'abord le caractère à la position 5, puis celui à la position 23, puis celui à la position 0, etc. C'est une technique basique d'anti-reverse engineering pour rendre l'extraction plus difficile.

---

## Crash course : Comprendre les comparaisons en assembleur

### L'instruction `movzbl` / `movzx`

```asm
movzbl -0x40(%rbp), %eax     # Syntaxe AT&T
movzx  eax, BYTE PTR [rbp-0x40]  # Syntaxe Intel
```

**Décomposition de `movzbl` :**
- `mov` : déplacer/copier
- `z` : avec extension à zéro (zero-extend)
- `b` : depuis un byte (8 bits)
- `l` : vers un long (32 bits)

Cette instruction :
1. Lit 1 byte à l'adresse `rbp - 0x40`
2. L'étend à 32 bits en ajoutant des zéros
3. Stocke le résultat dans `eax`

### L'instruction `cmp`

```asm
cmp $0x48, %al      # Syntaxe AT&T
cmp al, 0x48        # Syntaxe Intel
```

`cmp` compare deux valeurs en effectuant une soustraction **sans** stocker le résultat. Elle met à jour les "flags" du processeur :
- **ZF** (Zero Flag) : mis à 1 si les valeurs sont égales
- **SF** (Sign Flag) : mis à 1 si le résultat est négatif

### L'instruction `jne` / `jnz`

```asm
jne wrong_label     # Jump if Not Equal
jnz wrong_label     # Jump if Not Zero (équivalent)
```

Saute à l'adresse spécifiée si le Zero Flag n'est PAS mis (donc si les valeurs comparées sont différentes).

### Conversion ASCII

Les valeurs hexadécimales dans les comparaisons représentent des caractères ASCII :

| Hex | Décimal | Caractère |
|-----|---------|-----------|
| 0x48 | 72 | H |
| 0x54 | 84 | T |
| 0x42 | 66 | B |
| 0x7B | 123 | { |
| 0x7D | 125 | } |

**Table ASCII rapide pour les caractères courants :**

```
0x30-0x39 : '0'-'9' (chiffres)
0x41-0x5A : 'A'-'Z' (majuscules)
0x61-0x7A : 'a'-'z' (minuscules)
0x5F      : '_' (underscore)
0x7B      : '{' (accolade ouvrante)
0x7D      : '}' (accolade fermante)
```

---

## Étape 7 : Extraire les comparaisons

### Méthode manuelle avec objdump

```bash
objdump -d tablet | grep -B1 "cmp.*\$0x"
```

### Résultat (extrait)

```
movzbl -0x40(%rbp),%eax
cmp    $0x48,%al           # position 0 = 'H' (0x48)
--
movzbl -0x3f(%rbp),%eax
cmp    $0x54,%al           # position 1 = 'T' (0x54)
--
movzbl -0x3e(%rbp),%eax
cmp    $0x42,%al           # position 2 = 'B' (0x42)
--
movzbl -0x3d(%rbp),%eax
cmp    $0x7b,%al           # position 3 = '{' (0x7B)
```

### Méthode avec Cutter/Ghidra

1. Ouvrir le binaire dans Cutter
2. Aller dans la fonction `main`
3. Passer en vue "Graph" pour voir le flux de comparaisons
4. Pour chaque bloc, noter :
   - L'offset dans `movzbl -0xNN(%rbp)`
   - La valeur comparée dans `cmp $0xNN`

### Structure des données extraites

Pour chaque comparaison, on récupère :
1. **L'offset** : la position dans le buffer (ex: `0x40`, `0x3f`, etc.)
2. **La valeur** : le caractère attendu en hexadécimal (ex: `0x48`)

---

## Étape 8 : Extraire et reconstruire le flag

### Extraction des comparaisons

```bash
objdump -d tablet | grep -B1 "cmp.*\$0x"
```

### Résultat (extrait)

```
  126e:	0f b6 45 c0          	movzbl -0x40(%rbp),%eax
  1272:	3c 48                	cmp    $0x48,%al
--
  11ea:	0f b6 45 c1          	movzbl -0x3f(%rbp),%eax
  11ee:	3c 54                	cmp    $0x54,%al
--
  134a:	0f b6 45 c2          	movzbl -0x3e(%rbp),%eax
  134e:	3c 42                	cmp    $0x42,%al
...
```

### Méthode de reconstruction

1. Pour chaque paire `movzbl`/`cmp`, extraire l'offset et la valeur
2. Trier par offset décroissant (0x40 = premier caractère, 0x19 = dernier)
3. Convertir chaque valeur hexadécimale en caractère ASCII
4. Assembler le flag

### Tableau de correspondance (extraits)

| Offset | Valeur hex | Caractère |
|--------|------------|-----------|
| 0x40 | 0x48 | H |
| 0x3f | 0x54 | T |
| 0x3e | 0x42 | B |
| 0x3d | 0x7b | { |
| ... | ... | ... |
| 0x19 | 0x7d | } |

### Vérification

```bash
./tablet
HTB{br0k3n_4p4rt...}
```

Si le flag est correct, le programme ne devrait plus afficher "Wrong!".

---

## Comparaison des approches

| Approche | Avantages | Inconvénients |
|----------|-----------|---------------|
| **objdump + grep** | Rapide, pas d'installation | Sortie brute, demande du parsing |
| **Cutter** | Visuel, décompilation | Installation nécessaire |
| **Script Python** | Automatisé, reproductible | Nécessite d'écrire le script |

---

## Ressources pour aller plus loin

| Ressource | Description | Lien |
|-----------|-------------|------|
| **Cutter** | Désassembleur graphique open-source | [cutter.re](https://cutter.re/) |
| **Table ASCII** | Référence des caractères ASCII | [asciitable.com](https://www.asciitable.com/) |
| **x86-64 Assembly** | Tutoriel assembleur | [cs.lmu.edu](https://cs.lmu.edu/~ray/notes/x86assembly/) |
| **RE101** | Cours d'introduction au reverse | [malwareunicorn.org](https://malwareunicorn.org/workshops/re101.html) |

---

## Fichiers

- `tablet` : binaire du challenge

---

## Points clés à retenir

```
┌─────────────────────────────────────────────────────────────┐
│                    RÉSUMÉ DU CHALLENGE                      │
├─────────────────────────────────────────────────────────────┤
│  1. Le binaire compare l'entrée caractère par caractère     │
│  2. Chaque comparaison révèle un caractère du flag          │
│  3. Les offsets permettent de calculer la position          │
│  4. Position = 0x40 - offset (pour ce binaire)              │
│  5. On trie par position et on assemble le flag             │
└─────────────────────────────────────────────────────────────┘
```

---
