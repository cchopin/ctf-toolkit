# PE x86 - 0 protection - Write-up Root-Me

![Root-Me ch15](https://img.shields.io/badge/RootMe-ch15-orange)![Points](https://img.shields.io/badge/Points-5-brightgreen)![Category](https://img.shields.io/badge/Category-Cracking-blue)

## Resume

| Info | Valeur |
|------|--------|
| **Flag** | `SPaCIoS` |
| **Vulnerabilite** | Comparaison caractere par caractere avec valeurs en dur |
| **Technique** | Analyse statique avec objdump + radare2 |
| **Outils** | objdump, radare2, wine |

---

## Table des matieres

1. [Reconnaissance](#reconnaissance)
2. [Analyse statique](#analyse-statique)
3. [Solution](#solution)

---

## Reconnaissance

```bash
$ file ch15.exe
PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows, 7 sections
```

Binaire PE32 Windows. GDB ne peut pas le charger directement sur Linux, on utilise `objdump` et `radare2`.

---

## Analyse statique

### Reperage des chaines avec objdump

```bash
$ objdump -s -j .rdata ./ch15.exe
```

Chaines interessantes trouvees dans `.rdata` :

```
404044: "Usage: %s pass"      -> le password se passe en argument
404054: "Gratz man :)"        -> message de succes
404060: "Wrong password"      -> message d'echec
```

### Desassemblage avec radare2

```bash
$ r2 -A ./ch15.exe
[0x004014e0]> s main
[0x004017b8]> pdf
```

Le `main` est simple :
- Verifie qu'un argument est passe en ligne de commande (`argc > 1`)
- Calcule la longueur de l'argument avec `strlen`
- Appelle `fcn.00401726` avec l'argument et sa longueur

### La fonction de verification (`fcn.00401726`)

Pas de `strcmp` ici. Le programme verifie **caractere par caractere** :

```asm
cmp [arg_ch], 7        ; strlen == 7 ? sinon -> echec
cmp [arg+0], 0x53      ; 'S'
cmp [arg+1], 0x50      ; 'P'
cmp [arg+2], 0x61      ; 'a'
cmp [arg+3], 0x43      ; 'C'
cmp [arg+4], 0x49      ; 'I'
cmp [arg+5], 0x6f      ; 'o'
cmp [arg+6], 0x53      ; 'S'
```

Chaque `cmp` est suivi d'un `jne` vers "Wrong password". Si toutes les comparaisons passent, on obtient "Gratz man :)".

| Position | Hex | ASCII |
|----------|-----|-------|
| 0 | 0x53 | S |
| 1 | 0x50 | P |
| 2 | 0x61 | a |
| 3 | 0x43 | C |
| 4 | 0x49 | I |
| 5 | 0x6f | o |
| 6 | 0x53 | S |

---

## Solution

```bash
$ wine ./ch15.exe SPaCIoS 2>/dev/null
Gratz man :)
```

---
