# White-Box AES - Write-up Root-Me

![Root-Me ch34](https://img.shields.io/badge/RootMe-ch34-orange)![Difficulty](https://img.shields.io/badge/Difficulty-Hard-red)![Category](https://img.shields.io/badge/Category-Cracking-blue)

## Résumé

| Info | Valeur |
|------|--------|
| **Flag** | `XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` |
| **Vulnérabilité** | Implémentation White-Box AES vulnérable à l'attaque DFA |
| **Technique** | Differential Fault Analysis avec swap d'entrées T-tables |
| **Outils** | GDB, Python, phoenixAES |

---

## Table des matières

1. [Qu'est-ce que le White-Box AES ?](#quest-ce-que-le-white-box-aes-)
2. [Reconnaissance](#reconnaissance)
3. [Reverse engineering du main](#reverse-engineering-du-main)
4. [Patching du binaire](#patching-du-binaire)
5. [Identification de la structure White-Box](#identification-de-la-structure-white-box)
6. [DFA - Differential Fault Analysis](#dfa---differential-fault-analysis)
7. [Extraction de la clé](#extraction-de-la-clé)
8. [Vérification](#vérification)
9. [Points clés à retenir](#points-clés-à-retenir)

---

## Qu'est-ce que le White-Box AES ?

Le **White-Box AES** est une technique de protection cryptographique conçue pour résister aux attaques dans un environnement où l'attaquant a un accès total au binaire et peut l'analyser, le modifier ou l'exécuter à volonté (contrairement à un HSM ou une carte à puce).

### Principe de Chow et al. (2002)

L'implémentation White-Box la plus connue encode les opérations AES dans des **T-tables** (lookup tables) qui fusionnent :
- La substitution S-box
- Le mélange MixColumns
- Les clés de ronde

```
┌─────────────────────────────────────────────────────────────┐
│              AES CLASSIQUE vs WHITE-BOX                     │
├─────────────────────────────────────────────────────────────┤
│  AES Standard :                                             │
│    - Clé stockée en mémoire en clair                        │
│    - Opérations (SubBytes, ShiftRows, MixColumns) séparées  │
│    - Vulnérable à la lecture directe de la clé              │
│                                                             │
│  White-Box AES :                                            │
│    - Clé "cachée" dans des tables précompilées              │
│    - Toutes les opérations fusionnées dans des T-tables     │
│    - Encodages non-linéaires pour masquer les valeurs       │
└─────────────────────────────────────────────────────────────┘
```

### Structure des T-tables

Dans l'implémentation Chow, chaque ronde utilise 16 T-tables (une par octet du state) :
- **Type II T-tables** : 256 entrées × 4 octets = 1024 octets par table
- Ces tables combinent SubBytes + partie de MixColumns + clé de ronde
- Des **tables XOR** supplémentaires combinent les sorties avec des encodages

---

## Reconnaissance

Le challenge fournit un fichier `ch34.xz` qui, une fois décompressé, donne un binaire ELF massif.

```bash
$ file ch34
ch34: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

| Caractéristique | Observation |
|-----------------|-------------|
| Taille | 29 Mo (typique pour White-Box avec tables) |
| Stripped | Pas de symboles (reverse plus difficile) |
| Statically linked | libssl incluse dans le binaire |

### Comportement

Le binaire demande un input de 32 caractères hexadécimaux, le passe dans une fonction cryptographique, et compare le résultat à une valeur fixe.

---

## Reverse engineering du main

La fonction `main` se trouve à l'adresse `0x4d54b5`. Voici son flux d'exécution :

### Structure du programme

```
┌─────────────────────────────────────────────────────────────┐
│                    FLUX DU MAIN                             │
├─────────────────────────────────────────────────────────────┤
│  1. Intégrité : 3 vérifications SHA256 sur les données      │
│  2. Anti-debug : ptrace(PTRACE_TRACEME)                     │
│  3. Piège I/O : lit depuis fd=1 (stdout) au lieu de stdin!  │
│  4. Validation : vérifie 32 chars hex lowercase             │
│  5. Chiffrement : appelle la fonction WB-AES à 0x401189     │
│  6. Comparaison : compare avec le ciphertext attendu        │
│  7. Output : si match, affiche le message de succès         │
└─────────────────────────────────────────────────────────────┘
```

### Données extraites du binaire

| Donnée | Valeur | Rôle |
|--------|--------|------|
| Ciphertext attendu | `56c339dc4d5e1126452ab34b92269fb9` | WB-AES(input) doit égaler cette valeur |
| XOR key 1 | `8adf2bc11f6586f8b8666baf1176f568` | Transformation de l'input |
| XOR key 2 | `af97110b3e3800668efcfab5763c9fd3` | Transformation de l'input |
| XOR key 3 | `e39ec14e31d39b0acbc178300568a791` | Transformation de l'input |

### Piège anti-analyse : fd=1

Le programme lit l'input depuis **fd=1** (stdout) au lieu de fd=0 (stdin). C'est un piège classique anti-analyse : si vous lancez le binaire normalement et tapez du texte, ça ne fonctionne pas !

---

## Patching du binaire

Pour utiliser le binaire comme **oracle WB-AES** (lui envoyer des inputs et observer les outputs), j'ai créé une version patchée `ch34_patched` :

| Patch | Adresse | Octets | Description |
|-------|---------|--------|-------------|
| NOP ×6 | `0x4d55df` | `90 90 90 90 90 90` | Bypass ptrace anti-debug |
| NOP ×6 | `0x4d5500` | `90 90 90 90 90 90` | Bypass SHA256 check #1 |
| NOP ×6 | `0x4d5551` | `90 90 90 90 90 90` | Bypass SHA256 check #2 |
| NOP ×6 | `0x4d55a2` | `90 90 90 90 90 90` | Bypass SHA256 check #3 |
| NOP ×5 | `0x4d572f` | `90 90 90 90 90` | Bypass comparaison résultat |
| `0x01→0x00` | `0x4d561b` | `00` | Changer read(fd=1) en read(fd=0) |

### Utilisation de l'oracle

```bash
# Envoyer un plaintext et récupérer le ciphertext WB-AES
echo -n "00000000000000000000000000000000" | ./ch34_patched | xxd
# Les octets 8-23 de la sortie = WB-AES(plaintext)
```

---

## Identification de la structure White-Box

### Sections de données

L'analyse des données révèle la structure typique d'une implémentation Chow :

| Section | Adresse | Taille | Contenu |
|---------|---------|--------|---------|
| data1 | `0x4d8148` | 147 456 octets | T-tables rondes 1-9 |
| data2 | `0x4fc148` | 28 311 552 octets | Tables XOR (Chow) + ronde 10 |
| data3 (BSS) | `0x1ffc148` | 8 192 octets | 2 S-box AES (leurres) |

### Calcul de la taille data1

```
9 rondes × 16 tables × 256 entrées × 4 octets = 147 456 octets ✓
```

C'est exactement la taille de data1, ce qui confirme une implémentation **Chow Type II**.

### Confirmation de la structure AES

La relation `InvShiftRows(output[0x1ffe1dc]) = output[0x1ffe1ec]` confirme la structure AES interne. Les S-box trouvées en BSS sont des **leurres** (decoys) : les mettre à zéro ne change rien au résultat.

---

## DFA - Differential Fault Analysis

### Qu'est-ce que la DFA ?

La **Differential Fault Analysis** est une attaque par canaux auxiliaires qui consiste à :
1. Injecter des **fautes** dans l'exécution cryptographique
2. Comparer les sorties correctes et fautées
3. Exploiter les différences pour retrouver la clé

```
┌───────────────────────────────────────────────────────────┐
│                   PRINCIPE DE LA DFA                      │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  Exécution normale :                                      │
│  Plaintext ──► [R1-8] ──► R9 ──► R10 ──► Ciphertext       │
│                           │                               │
│                         Faute                             │
│                           ▼                               │
│  Exécution fautée :                                       │
│  Plaintext ──► [R1-8] ──► R9' ─► R10 ──► Ciphertext'      │
│                                                           │
│  Analyse : (Ciphertext XOR Ciphertext') révèle K10        │
└───────────────────────────────────────────────────────────┘
```

### Étape 1 : Identification des tables de la ronde 9

J'ai scanné les 144 tables de data1 (9 blocs × 16 tables) en mettant chaque table à zéro et en observant l'impact sur la sortie.

**Critère** : une table de la ronde 9 cause exactement **4 octets de changement** dans la sortie (une colonne AES après ShiftRows).

Résultat : **16 tables identifiées**, réparties de façon **non séquentielle** :

| Colonne | Positions ciphertext | Tables (offset fichier) |
|---------|---------------------|-------------------------|
| 0 | [0, 7, 10, 13] | `0xd8948`, `0xde548`, `0xe4548`, `0xed148` |
| 1 | [1, 4, 11, 14] | `0xdd548`, `0xe2d48`, `0xec948`, `0xf3d48` |
| 2 | [2, 5, 8, 15] | `0xd8148`, `0xea548`, `0xf3548`, `0xf9548` |
| 3 | [3, 6, 9, 12] | `0xdc948`, `0xdd148`, `0xebd48`, `0xf0548` |

### Étape 2 : Échec du zeroing classique

Mettre une T-table entière à zéro crée une faute **arbitraire**, pas une faute structurée MixColumns `(2e, 3e, e, e)`.

**Pourquoi ?** La valeur 0 passe par les tables XOR encodées de Chow et produit une contribution valide mais non contrôlée.

`phoenixAES` ne trouve aucune solution avec ces fautes.

### Étape 3 : Technique du swap d'entrées (clé du challenge)

**L'insight** : au lieu de mettre une entrée à zéro, on **échange deux entrées** de la T-table.

Les deux valeurs sont validement encodées → les tables XOR les décodent correctement → la différence conserve la **structure MixColumns**.

**Procédure** :

```
┌─────────────────────────────────────────────────────────────┐
│              TECHNIQUE DU SWAP D'ENTRÉES                    │
├─────────────────────────────────────────────────────────────┤
│  1. Binary search (8 itérations) pour trouver l'entrée      │
│     accédée pour le plaintext 00...00                       │
│                                                             │
│  2. Swap de cette entrée avec 20 autres entrées             │
│     → génère 320 fautes structurées                         │
│                                                             │
│  3. Chaque faute produit 4 octets de changement avec la     │
│     structure MixColumns attendue                           │
└─────────────────────────────────────────────────────────────┘
```

**Binary search pour trouver l'entrée accédée** :

```python
# Binary search : zeroing de la moitié haute/basse de la table
# et observation du changement dans la sortie
for step in range(8):
    mid = (lo + hi) // 2
    # Zero entries lo..mid-1
    if output_changed:
        hi = mid   # l'entrée accédée est dans [lo, mid)
    else:
        lo = mid   # l'entrée accédée est dans [mid, hi)
```

**Génération des fautes par swap** :

```python
# Swap fault : échanger l'entrée accédée avec une autre
orig_accessed = table[accessed_idx]
orig_other = table[other_idx]
table[accessed_idx] = orig_other  # l'oracle va lire cette valeur
table[other_idx] = orig_accessed
# → faute MixColumns structurée
```

---

## Extraction de la clé

### Résultat de phoenixAES

Avec les 320 fautes structurées, `phoenixAES` trouve immédiatement la clé de la ronde 10 :

```
K10 = A727004B8BE6002B8E7FEBB95BC5ADB0
```

### Inversion du key schedule AES-128

L'algorithme de key schedule AES-128 est réversible. À partir de K10, on remonte :

```
K 0 = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX   ← CLÉ AES (FLAG)
K 1 = d56f3463f3473accb08766724e0f25da
K 2 = a150634c52175980e2903ff2ac9f1a28
...
K10 = a727004b8be6002b8e7febb95bc5adb0
```

---

## Vérification

### Test de l'oracle

```python
# La clé retrouvée chiffre correctement 00...00
AES_encrypt(0x00...00, K0) = 189cc5e50f6da74629e4543efa928e4d

# Comparaison avec l'oracle patché
echo -n "00000000000000000000000000000000" | ./ch34_patched
# Output bytes 8-23 = 189cc5e50f6da74629e4543efa928e4d ✓
```

### Déchiffrement de la cible

```python
# Trouver l'input qui donne le ciphertext attendu
AES_decrypt(0x56c339dc4d5e1126452ab34b92269fb9, K0)
    = 867684b2fc6de308e96859c5c718f929  # = input correct
```

### Validation finale

```bash
$ echo -n "867684b2fc6de308e96859c5c718f929" | ./ch34_patched | xxd
# Output: "The flag is the AES key (32 lowercase hex chars)"
```

---

## Points clés à retenir

```
┌─────────────────────────────────────────────────────────────┐
│                    RÉSUMÉ DU CHALLENGE                      │
├─────────────────────────────────────────────────────────────┤
│  1. fd=1 trick : le binaire lit depuis stdout, pas stdin    │
│  2. Les S-box dans le BSS sont des LEURRES inutilisés       │
│  3. Les T-tables de ronde 9 sont MÉLANGÉES dans data1       │
│  4. Le ZEROING de tables ne fonctionne PAS pour DFA Chow    │
│  5. La technique du SWAP préserve la structure MixColumns   │
└─────────────────────────────────────────────────────────────┘
```

### Outils utilisés

| Outil | Usage |
|-------|-------|
| GDB | Reverse engineering, identification des adresses |
| Python | Patching binaire, automatisation des fautes |
| phoenixAES | Résolution des équations DFA pour extraire K10 |

### Ressources

- [Chow et al. - White-Box Cryptography and an AES Implementation (2002)](https://www.scs.stanford.edu/~dm/home/papers/ches02.pdf)
- [phoenixAES](https://github.com/SideChannelMarvels/Deadpool/tree/master/wbs_aes_ches2016/DFA) - Outil DFA pour AES
- [Differential Fault Analysis on White-box AES](https://eprint.iacr.org/2016/794.pdf)

---

## Fichiers

- `ch34.xz` : archive du challenge
- `ch34` : binaire original
- `ch34_patched` : binaire patché pour utilisation comme oracle
- `solve.py` : script de résolution DFA

---
