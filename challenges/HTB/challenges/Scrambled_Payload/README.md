# Scrambled Payload - Write-up HackTheBox

![HTB Scrambled Payload](https://img.shields.io/badge/HackTheBox-Scrambled__Payload-green)![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen)![Category](https://img.shields.io/badge/Category-Reversing-blue)

## Resume

| Info | Valeur |
|------|--------|
| **Flag** | `HTB{XXXXXXXXXXXXXXXXXXXXXXX}` |
| **Technique** | Deobfuscation multi-couches de VBScript |
| **Mecanisme** | Validation du flag via regex sur le ComputerName encode en base64 |
| **Outils** | Python, strings |

---

## Table des matieres

1. [Contexte](#contexte)
2. [Fichiers fournis](#fichiers-fournis)
3. [Reconnaissance](#reconnaissance)
4. [Couche 0 : Structure VBScript et base64](#couche-0--structure-vbscript-et-base64)
5. [Couche 1 : Decodage base64 et boucles Array](#couche-1--decodage-base64-et-boucles-array)
6. [Couches 2+ : Desobfuscation recursive](#couches-2--desobfuscation-recursive)
7. [Analyse du payload final](#analyse-du-payload-final)
8. [Extraction du flag](#extraction-du-flag)
9. [Script de decodage](#script-de-decodage)
10. [Points cles a retenir](#points-cles-a-retenir)

---

## Contexte

On nous fournit un fichier `payload.vbs` obfusque. Le VBScript utilise plusieurs couches d'obfuscation imbriquees pour masquer sa logique. L'objectif est de desobfusquer le code pour comprendre ce qu'il fait et trouver le flag.

---

## Fichiers fournis

- `payload.vbs` : script VBScript fortement obfusque

---

## Reconnaissance

### Premier apercu

```bash
strings payload.vbs
```

Le fichier contient une unique ligne de VBScript extremement longue. On y repere immediatement :

- Des appels `CreateObject(...)` avec des `Chr((X*Y)mod 256)` concatenes
- Un attribut `A.text = "..."` contenant une longue chaine base64
- Aucun texte lisible directement

### Identification des patterns d'obfuscation

Trois types d'operations sont utilises pour masquer le code :

| Pattern | Operation |
|---------|-----------|
| `Chr((X*Y)mod 256)` | Multiplication modulo 256 -> caractere ASCII |
| `Array(...)(i)+N)mod 256` | Addition d'un offset modulo 256 |
| `Array(...)(i)*N)mod 256` | Multiplication par un facteur modulo 256 |
| `Array(...)(i)xor N)mod 256` | XOR avec une valeur modulo 256 |

---

## Couche 0 : Structure VBScript et base64

### Decodage du CreateObject

Le premier `CreateObject` est construit par concatenation de `Chr()` :

```vbscript
Set A = CreateObject(Chr((211*95)mod 256)&Chr((187*169)mod 256)&...)
```

En evaluant chaque expression :

```
(211*95) mod 256 = 77  -> 'M'
(187*169) mod 256 = 115 -> 's'
(152*21) mod 256 = 120 -> 'x'
...
```

**Resultat** : `Msxml2.DOMDocument.3.0`

### Les autres elements resolus

| Expression obfusquee | Valeur decodee |
|----------------------|----------------|
| `CreateObject(...)` | `Msxml2.DOMDocument.3.0` |
| `.CreateElement(...)` | `base64` |
| `A.dataType = ...` | `bin.base64` |

### Mecanisme

Le script cree un objet XML DOM pour decoder du base64. C'est une technique classique en VBScript malveillant : utiliser le parser XML integre a Windows comme decodeur base64.

```vbscript
Set A = CreateObject("Msxml2.DOMDocument.3.0").CreateElement("base64")
A.dataType = "bin.base64"
A.text = "<longue chaine base64>"
```

---

## Couche 1 : Decodage base64 et boucles Array

Le decodage du base64 revele du code VBScript contenant **8 boucles `Execute`** successives. Chacune suit le meme schema :

```vbscript
d="":for i=0 to N:d=d+Chr((Array(v1,v2,...)(i)+OFFSET)mod 256):Next:Execute d
```

### Principe

1. Un tableau de valeurs numeriques est defini via `Array(...)`
2. Chaque valeur est transformee par une operation arithmetique (`+`, `*`, ou `xor`) avec un offset
3. Le resultat modulo 256 donne un code ASCII
4. Les caracteres sont concatenes pour former du code VBScript
5. `Execute d` interprete ce code dynamiquement

### Vue d'ensemble des couches

| Couche | Taille | Operation | Offset | Contenu decode |
|--------|--------|-----------|--------|----------------|
| 1 | 268 | `+` | 196 | Creation de `ADODB.Stream` |
| 2 | 169 | `+` | 241 | `CharSet = us-ascii` |
| 3 | 885 | `*` | 117 | Recuperation du `ComputerName`, encodage base64 |
| 4 | 250 | `*` | 65 | Configuration `bin.base64`, creation `RegExp` |
| 5 | 701 | `*` | 103 | Regex de validation de longueur |
| 6 | 3043 | `xor` | 183 | Regex de validation #1 (par position) |
| 7 | 6612 | `*` | 33 | Regex de validation #2 et #3 |
| 8 | 45 | `*` | 119 | Verification finale |
| 9 | 140 | `*` | 23 | `MsgBox("Correct!")` |

---

## Couches 2+ : Desobfuscation recursive

### Couche 3 : Recuperation du ComputerName

```vbscript
b.Open
b.WriteText(CreateObject("WScript.Network").ComputerName)
b.Position=0
b.Type=1
b.Position=0
Set n=CreateObject("Msxml2.DOMDocument.3.0").CreateElement("base64")
```

Le script :

1. Ouvre un `ADODB.Stream` en mode texte (`Type=2`, charset `us-ascii`)
2. Y ecrit le **nom de l'ordinateur** (`ComputerName`)
3. Bascule en mode binaire (`Type=1`)
4. Encode le contenu en base64 via le DOM XML

### Couche 5 : Verification de la longueur

```vbscript
r.Pattern = ^.....................................$
If Not r.Test(n.text) then WScript.Quit: End If
```

Le base64 du flag doit faire exactement **36 caracteres**.

### Couches 6-7 : Verification caractere par caractere

Trois regex verifient chaque position du base64 avec des ensembles de 3 caracteres possibles :

```
Regex 1: ^[MSy][FfK][ERT][yCM][efI][{31]...[9Sa]$
Regex 2: ^[{Sp][F7H][R1t][CHG][ze5]...[r39]$
Regex 3: ^[WoS][cFe][_yR][CzE][Xce]...[of9]$
```

Chaque position a 3 caracteres possibles dans chaque regex. L'intersection des 3 ensembles donne **un seul caractere valide** par position.

---

## Analyse du payload final

### Schema complet d'execution

```
┌─────────────────────────────────────────────────────────────┐
│                    FLUX D'EXECUTION                         │
├─────────────────────────────────────────────────────────────┤
│  1. Recupere le ComputerName via WScript.Network            │
│  2. Encode le nom en base64 via Msxml2.DOMDocument          │
│  3. Verifie la longueur (36 caracteres base64)              │
│  4. Verifie chaque position via 3 regex complementaires     │
│  5. Si tout passe -> MsgBox("Correct!")                     │
│  6. Sinon -> WScript.Quit                                   │
└─────────────────────────────────────────────────────────────┘
```

### Technique d'obfuscation

Le VBScript utilise une **cascade de `Execute`** : chaque couche decode et execute la suivante. C'est equivalent a une poupee russe de code :

```
Base64 -> Execute(couche1) -> Execute(couche2) -> ... -> Execute(MsgBox)
```

Les operations varient d'une couche a l'autre (`+`, `*`, `xor`) avec des offsets differents pour compliquer l'analyse statique.

---

## Extraction du flag

### Methode : intersection des regex

Chaque position du base64 est contrainte par 3 ensembles de caracteres (un par regex). L'intersection donne un unique caractere :

| Position | Regex 1 | Regex 2 | Regex 3 | Intersection |
|----------|---------|---------|---------|-------------|
| 0 | `MSy` | `{Sp` | `WoS` | **S** |
| 1 | `FfK` | `F7H` | `cFe` | **F** |
| 2 | `ERT` | `R1t` | `_yR` | **R** |
| 3 | `yCM` | `CHG` | `CzE` | **C** |
| ... | ... | ... | ... | ... |
| 35 | `9Sa` | `r39` | `of9` | **9** |

### Resultat

```
Base64 : SFRCe1NjUjRNQkwzRF9WQl9TY3IxUFQxTkd9
Decode : HTB{XXXXXXXXXXXXXXXXXXXXXXX}
```

### Verification

Le flag decode correspond au nom du challenge en leet speak, coherent avec le theme "Scrambled VB Scripting".

---

## Script de decodage

```python
import base64, re

with open("payload.vbs") as f:
    vbs = f.read()

# Etape 1 : Extraire et decoder le base64
b64 = re.search(r'A\.text\s*=\s*"([^"]+)"', vbs).group(1)
code = base64.b64decode(b64).decode()

def resolve_chr(text):
    """Resoudre Chr((X*Y)mod 256) et Chr(N) puis concatener"""
    text = re.sub(r'Chr\(\((\d+)\*(\d+)\)mod 256\)',
                  lambda m: chr((int(m.group(1)) * int(m.group(2))) % 256), text)
    text = re.sub(r'Chr\((\d+)\)',
                  lambda m: chr(int(m.group(1))), text)
    text = text.replace('"&"', '').replace('&"', '').replace('"&', '')
    text = text.replace('"', '')
    return text

def decode_layers(code, depth=0):
    """Decoder recursivement les couches Array()+offset mod 256"""
    pattern = r'Array\(([\d,]+)\)\(i\)([\+\*]|xor\s*)(\d+)\)mod 256'
    for match in re.finditer(pattern, code):
        arr = list(map(int, match.group(1).split(',')))
        op = match.group(2).strip()
        val = int(match.group(3))
        if op == '+':
            result = ''.join(chr((v + val) % 256) for v in arr)
        elif op == '*':
            result = ''.join(chr((v * val) % 256) for v in arr)
        elif op == 'xor':
            result = ''.join(chr((v ^ val) % 256) for v in arr)
        else:
            continue

        resolved = resolve_chr(result)
        print(f"\n{'=' * 60}")
        print(f"Layer depth={depth} op={op} val={val} len={len(arr)}")
        print(f"{'=' * 60}")
        print(resolved)

        if 'Array(' in result:
            decode_layers(result, depth + 1)

decode_layers(code)
```

### Execution

```bash
python3 decode.py
```

Le script decode recursivement toutes les couches et affiche le code VBScript desobfusque a chaque etape, revelant les regex de validation et le `MsgBox("Correct!")` final.

---

## Points cles a retenir

```
┌─────────────────────────────────────────────────────────────┐
│                    RESUME DU CHALLENGE                      │
├─────────────────────────────────────────────────────────────┤
│  1. L'obfuscation VBS utilise Chr() et Array() en cascade   │
│  2. Execute() permet d'interpreter du code genere a runtime │
│  3. Les operations +, * et xor mod 256 masquent les valeurs │
│  4. L'intersection de regex contraint chaque position a un  │
│     seul caractere valide                                   │
│  5. Le flag est valide via le ComputerName encode en base64 │
└─────────────────────────────────────────────────────────────┘
```

### Techniques d'obfuscation identifiees

| Technique | Description |
|-----------|-------------|
| `Chr((X*Y)mod 256)` | Masque les chaines de caracteres par calcul arithmetique |
| `Array() + Execute` | Genere et execute du code dynamiquement |
| Operations variees | Alterne `+`, `*`, `xor` entre les couches |
| Regex complementaires | Chaque regex individuellement accepte 3 chars, mais l'intersection n'en laisse qu'un |
| XML DOM base64 | Utilise le parser XML de Windows comme encodeur/decodeur |

---

## Fichiers

- `payload.vbs` : script VBScript obfusque du challenge
- `decode.py` : script Python de desobfuscation recursive

---
