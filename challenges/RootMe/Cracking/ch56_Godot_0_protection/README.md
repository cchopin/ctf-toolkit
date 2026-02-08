# Godot - 0 protection - Write-up Root-Me

![Root-Me ch56](https://img.shields.io/badge/RootMe-ch56-orange)![Points](https://img.shields.io/badge/Points-10-brightgreen)![Category](https://img.shields.io/badge/Category-Cracking-blue)

## Resume

| Info | Valeur |
|------|--------|
| **Flag** | `ScriPts1nCl34r` |
| **Vulnerabilite** | Scripts GDScript en clair dans l'archive PCK |
| **Technique** | Extraction archive PCK + dechiffrement XOR |
| **Outils** | strings, grep, python3 |

---

## Table des matieres

1. [Reconnaissance](#reconnaissance)
2. [Analyse](#analyse)
3. [Notions apprises](#notions-apprises)
4. [Solution](#solution)

---

## Reconnaissance

```bash
$ file 0_protection.exe
PE32+ executable (GUI) x86-64 (stripped to external PDB), for MS Windows, 14 sections
```

Fichier de 44 Mo — typique d'un jeu Godot exporte. Le moteur entier est embarque dans l'executable. Le desassemblage classique n'a pas d'interet ici : le code du jeu (GDScript) est empaquete dans une archive `.pck` collee a la fin de l'exe.

---

## Analyse

### Etape 1 : Identifier les fichiers du jeu

```bash
$ strings 0_protection.exe | grep -i "\.gd\|\.tscn\|\.tres"
```

On repere les scripts GDScript du jeu :

```
res://src/FlagLabel.gd
res://src/MainMenu.gd
res://src/Player.gd
res://src/StartButton.gd
```

### Etape 2 : Localiser l'archive PCK

Le format PCK de Godot utilise la signature `GDPC` :

```bash
$ grep -oba "GDPC" 0_protection.exe
33375232:GDPC
44404652:GDPC
```

### Etape 3 : Extraire le PCK

```bash
$ python3 -c "
f=open('0_protection.exe','rb')
f.seek(33375232)
o=open('game.pck','wb')
o.write(f.read())
o.close()
f.close()
"
```

### Etape 4 : Lire le script FlagLabel.gd

Les scripts GDScript sont stockes en clair dans le PCK :

```bash
$ strings game.pck | grep -A 20 "FlagLabel"
```

On trouve le script complet :

```gdscript
extends Label
func _ready():
    var key = [119, 104, 52, 116, 52, 114, 51, 121, 48, 117, 100, 48, 49, 110, 103, 63]
    var enc = [32, 13, 88, 24, 20, 22, 92, 23, 85, 89, 68, 68, 89, 11, 71, 89,
               27, 9, 83, 84, 93, 1, 57, 42, 83, 7, 13, 96, 69, 29, 86, 81, 52, 4, 7, 64, 70]
    text = ""
    for i in range(len(enc)):
        text += char(enc[i] ^ key[i % len(key)])
```

Chiffrement XOR avec cle cyclique (meme principe que ch25).

### Etape 5 : Dechiffrer

```bash
$ python3 -c "
key=[119,104,52,116,52,114,51,121,48,117,100,48,49,110,103,63]
enc=[32,13,88,24,20,22,92,23,85,89,68,68,89,11,71,89,27,9,83,84,93,1,57,42,83,7,13,96,69,29,86,81,52,4,7,64,70]
print(''.join(chr(enc[i]^key[i%len(key)]) for i in range(len(enc))))
"
Well done, the flag is
ScriPts1nCl34r
```

---

## Notions apprises

- **Jeux Godot** : le code GDScript est empaquete dans une archive `.pck`, souvent collee a la fin de l'executable. Inutile de desassembler les 44 Mo du moteur.
- **Signature GDPC** : permet de localiser le debut de l'archive PCK dans le binaire.
- **Scripts en clair** : dans un export Godot sans protection, les scripts `.gd` sont lisibles directement avec `strings`. D'ou le nom du flag...

---

## Solution

**Flag** : `ScriPts1nCl34r`

---
