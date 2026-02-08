# ELF C++ - 0 protection - Write-up Root-Me

![Root-Me ch25](https://img.shields.io/badge/RootMe-ch25-orange)![Points](https://img.shields.io/badge/Points-10-brightgreen)![Category](https://img.shields.io/badge/Category-Cracking-blue)

## Resume

| Info | Valeur |
|------|--------|
| **Flag** | `Here_you_have_to_understand_a_little_C++_stuffs` |
| **Vulnerabilite** | Chiffrement XOR reversible avec cle en dur |
| **Technique** | Breakpoint dynamique apres le dechiffrement XOR |
| **Outils** | GDB (GEF) |

---

## Table des matieres

1. [Reconnaissance](#reconnaissance)
2. [Analyse avec GDB](#analyse-avec-gdb)
3. [Notions apprises](#notions-apprises)
4. [Solution](#solution)

---

## Reconnaissance

```bash
$ file ch25.bin
ELF 32-bit LSB executable, Intel 80386, dynamically linked, not stripped
```

Binaire ELF 32-bit, non strippe. Les symboles sont en C++ (name mangling).

---

## Analyse avec GDB

```bash
$ gdb ./ch25.bin
gef> disas main
```

### Etape 1 : Identifier la comparaison (partir de la fin)

On repere l'appel a `std::operator==` a `main+268` :

```asm
+262: lea eax, [ebp-0x14]              ; argument 1 : resultat de plouf
+265: mov [esp], eax
+256: mov eax, [eax]                    ; argument 2 : argv[1] (notre entree)
+258: mov [esp+0x4], eax
+268: call std::operator==              ; compare les deux
+273: test al, al
+275: je "Password incorrect"
```

### Etape 2 : Remonter la piste de `[ebp-0x14]`

La variable comparee `[ebp-0x14]` est le retour de la fonction `plouf` :

```asm
+122: string str1(0x8048dc4)           ; 1ere chaine (donnees chiffrees)
+159: string str2(0x8048dcc)           ; 2eme chaine (cle)
+198: call plouf(str1, str2)           ; resultat -> [ebp-0x14]
```

### Etape 3 : Comprendre `plouf`

```bash
gef> disas plouf
```

La fonction `plouf` implemente un **chiffrement XOR** :

```python
def plouf(str1, str2):
    result = ""
    for i in range(len(str1)):
        result += chr(str1[i] ^ str2[i % len(str2)])
    return result
```

Elle XOR chaque caractere de `str1` avec un caractere de `str2` (la cle se repete cycliquement).

### Etape 4 : Breakpoint dynamique

Les deux chaines sont des octets non-imprimables — impossible de calculer le XOR de tete. On laisse le programme faire le travail.

On pose un breakpoint juste avant la comparaison, apres que `plouf` ait calcule le resultat :

```
gef> delete
gef> b *0x08048b92
gef> run AAAA
```

A l'arret, GEF affiche le resultat directement dans les registres :

```
$eax : -> "Here_you_have_to_understand_a_little_C++_stuffs"
```

Et sur la pile, on voit les deux arguments de la comparaison :

```
[esp+0x0] -> "Here_you_have_to_understand_a_little_C++_stuffs"  <- resultat de plouf
[esp+0x4] -> "AAAA"                                             <- notre entree
```

---

## Notions apprises

- **Name mangling C++** : les noms de fonctions sont encodes (`_ZSteq...` = `std::operator==`). L'outil `c++filt` permet de les decoder.
- **Analyse dynamique** : quand le mot de passe est calcule a l'execution (XOR, chiffrement...), on ne peut pas le trouver statiquement. On pose un breakpoint et on laisse le programme faire le calcul.
- **Remonter depuis la comparaison** : toujours partir de la fin (le point de decision succes/echec) et remonter vers l'origine des donnees.

---

## Solution

```bash
$ ./ch25.bin Here_you_have_to_understand_a_little_C++_stuffs
Bravo, tu peux valider en utilisant ce mot de passe...
Congratz. You can validate with this password...
```

---
