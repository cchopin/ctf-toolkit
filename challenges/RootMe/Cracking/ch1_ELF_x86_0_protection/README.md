# ELF x86 - 0 protection - Write-up Root-Me

![Root-Me ch1](https://img.shields.io/badge/RootMe-ch1-orange)![Points](https://img.shields.io/badge/Points-5-brightgreen)![Category](https://img.shields.io/badge/Category-Cracking-blue)

## Resume

| Info | Valeur |
|------|--------|
| **Flag** | `123456789` |
| **Vulnerabilite** | Password en clair dans le binaire |
| **Technique** | Lecture directe via `strcmp` + examen memoire GDB |
| **Outils** | GDB (GEF) |

---

## Table des matieres

1. [Reconnaissance](#reconnaissance)
2. [Analyse avec GDB](#analyse-avec-gdb)
3. [Solution](#solution)

---

## Reconnaissance

```bash
$ file ch1.bin
ELF 32-bit LSB executable, Intel 80386, dynamically linked, not stripped
```

Binaire ELF 32-bit, non strippe (les noms de fonctions sont conserves).

---

## Analyse avec GDB

On ouvre le binaire et on desassemble `main` :

```bash
$ gdb ./ch1.bin
gef> disassemble main
```

### Lignes cles du desassemblage

```asm
0x080486ae <+17>:  mov DWORD PTR [ebp-0x8], 0x8048841   ; charge l'adresse du password
...
0x080486eb <+78>:  call getString                         ; lit l'entree utilisateur
0x080486f0 <+83>:  mov [ebp-0xc], eax                    ; stocke l'entree
...
0x080486f6 <+89>:  mov [esp+0x4], [ebp-0x8]              ; arg2 = password
0x080486fd <+96>:  mov [esp], [ebp-0xc]                   ; arg1 = entree
0x08048700 <+99>:  call strcmp                             ; compare les deux
0x08048705 <+104>: test eax,eax                            ; resultat == 0 ?
0x08048707 <+106>: jne 0x804871e                           ; si different -> echec
```

La logique est simple : `strcmp(entree, password)`. Si le resultat est 0 (chaines identiques), on passe.

Le password est stocke en dur a l'adresse `0x8048841` :

```
gef> x/s 0x8048841
0x8048841:    "123456789"
```

---

## Solution

```
$ ./ch1.bin
Veuillez entrer le mot de passe : 123456789
Bien joue, vous pouvez valider l'epreuve avec le pass : 123456789!
```

---
