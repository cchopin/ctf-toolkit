# Cracking - Root-Me Write-ups

![Category](https://img.shields.io/badge/Category-Cracking-blue)

## Challenges

| # | Challenge | Points | Validations | Technique principale |
|---|-----------|--------|-------------|----------------------|
| ch1 | [ELF x86 - 0 protection](ch1_ELF_x86_0_protection/) | 5 | 14% | `strcmp` avec password en dur |
| ch2 | [ELF x86 - Basique](ch2_ELF_x86_Basique/) | 5 | 11% | Double `strcmp` (username + password) |
| ch15 | [PE x86 - 0 protection](ch15_PE_x86_0_protection/) | 5 | 7% | Comparaison caractere par caractere |
| ch25 | [ELF C++ - 0 protection](ch25_ELF_Cpp_0_protection/) | 10 | 4% | XOR + breakpoint dynamique |
| ch56 | [Godot - 0 protection](ch56_Godot_0_protection/) | 10 | 1% | Extraction PCK + XOR |

## Outils utilises

| Outil | Challenges |
|-------|------------|
| GDB (GEF) | ch1, ch2, ch25 |
| radare2 | ch15 |
| objdump | ch15 |
| strings | ch56 |
| Python | ch56 |

## Progression

- [x] ch1 - ELF x86 - 0 protection
- [x] ch2 - ELF x86 - Basique
- [x] ch15 - PE x86 - 0 protection
- [x] ch25 - ELF C++ - 0 protection
- [x] ch56 - Godot - 0 protection
