---

## 1. Pair ou impair

**Objectif** : déterminer si un entier stocké dans un registre est pair ou impair, puis afficher le résultat.

**Notions travaillées** : instruction `test` ou `and`, sauts conditionnels (`je`, `jne`), drapeaux ZF.

**Consigne** :
- Place un entier dans `rax` (ou `edi` si tu veux simuler un paramètre).
- Utilise `test rax, 1` pour vérifier le bit de poids faible.
- Si ZF=1 (bit 0 vaut 0), l'entier est pair. Sinon il est impair.
- Affiche "pair" ou "impair" via `sys_write`.

**Indice** : `test` fait un AND logique sans modifier l'opérande, il met juste les drapeaux a jour. C'est plus propre que `and` quand tu veux juste tester sans altérer la valeur.

**Bonus** : fais-le en boucle sur un tableau de plusieurs entiers en mémoire.

---

## 2. Longueur d'une chaine

**Objectif** : parcourir une chaine null-terminated et retourner sa longueur (équivalent de `strlen`).

**Notions travaillées** : adressage indirect (`[rsi]`), incrémentation de pointeur, comparaison avec zéro, boucle avec condition de sortie.

**Consigne** :
- Définis une chaine dans la section `.data` : `msg db "Hello, ASM!", 0`
- Charge l'adresse de la chaine dans `rsi`.
- Initialise un compteur a 0 dans `rcx`.
- Boucle : lis l'octet pointé par `rsi`, compare a 0, si différent incrémente `rcx` et `rsi`, sinon sors de la boucle.
- A la fin, `rcx` contient la longueur.

**Indice** : pour lire un seul octet, utilise `mov al, [rsi]` (registre 8 bits) ou `cmp byte [rsi], 0` directement.

**Bonus** : affiche la longueur en la convertissant en caractère ASCII (fonctionne facilement pour les longueurs < 10, ajoute simplement `'0'` soit 0x30).

---

## 3. Inverser une chaine en place

**Objectif** : retourner une chaine caractère par caractère, sans buffer auxiliaire.

**Notions travaillées** : deux pointeurs (début/fin), swap en mémoire, boucle avec condition d'arrêt sur croisement de pointeurs.

**Consigne** :
- Réutilise ta fonction de longueur de l'exercice 2 pour trouver la fin de la chaine.
- Place un pointeur `rsi` au début et `rdi` sur le dernier caractère (avant le null).
- Tant que `rsi < rdi` :
  - Lis les octets aux deux positions.
  - Echange-les (swap via un registre temporaire ou via `xchg`).
  - Incrémente `rsi`, décrémente `rdi`.
- Affiche la chaine inversée avec `sys_write`.

**Indice** : `xchg` peut swapper un registre avec la mémoire, mais attention, sur mémoire il implique un `lock` implicite (plus lent). Pour un exercice d'apprentissage c'est pas grave, mais le swap via registre temporaire est la méthode "propre" :

```nasm
mov al, [rsi]
mov bl, [rdi]
mov [rsi], bl
mov [rdi], al
```

**Bonus** : gère le cas de la chaine vide et de la chaine d'un seul caractère sans planter.

---

## 4. Conversion majuscules/minuscules

**Objectif** : parcourir une chaine et convertir chaque lettre minuscule en majuscule (ou l'inverse).

**Notions travaillées** : comparaisons chaînées (plage de valeurs), arithmétique sur caractères ASCII, branchements multiples.

**Consigne (version to_upper)** :
- Pour chaque octet de la chaine :
  - Vérifie s'il est dans la plage `'a'` (0x61) a `'z'` (0x7A).
  - Si oui, soustrais 0x20 pour obtenir la majuscule correspondante.
  - Si non, laisse-le tel quel (espaces, chiffres, ponctuation).
- Affiche le résultat.

**Indice** : la vérification de plage se fait avec deux comparaisons :

```nasm
cmp al, 'a'
jb .skip        ; en dessous de 'a', on touche pas
cmp al, 'z'
ja .skip        ; au dessus de 'z', on touche pas
sub al, 0x20    ; conversion min -> maj
.skip:
```

**Bonus** : fais une version qui bascule la casse (toggle case) : les minuscules deviennent majuscules et inversement. Indice : `xor al, 0x20` fait exactement ca sur les lettres ASCII.

---

## 5. Tri a bulles

**Objectif** : trier un tableau d'entiers en mémoire par ordre croissant.

**Notions travaillées** : boucles imbriquées, comparaison et échange en mémoire, flag de modification, adressage indexé.

**Consigne** :
- Définis un tableau dans `.data` : `tableau dd 42, 17, 8, 99, 3, 55, 21` et sa taille.
- Boucle externe : répète tant qu'au moins un swap a eu lieu au tour précédent.
- Boucle interne : parcours le tableau, compare chaque paire d'éléments adjacents.
  - Si `tableau[i] > tableau[i+1]`, échange-les et note qu'un swap a eu lieu.
- Quand un tour complet se passe sans swap, le tableau est trié.

**Indice** : pour l'adressage indexé avec des `dd` (double words, 4 octets) :

```nasm
mov eax, [rbx + rcx*4]       ; tableau[i]
mov edx, [rbx + rcx*4 + 4]   ; tableau[i+1]
cmp eax, edx
jle .pas_de_swap
; swap
mov [rbx + rcx*4], edx
mov [rbx + rcx*4 + 4], eax
mov r8b, 1                    ; flag swap = true
.pas_de_swap:
```

**Bonus** : affiche le tableau trié. Ca demande de convertir chaque entier en chaine de caractères (division successive par 10, stocker les restes en ordre inverse). C'est un exercice a part entière !

---

## Mémo rapide des instructions utiles

| Instruction | Description |
|---|---|
| `test a, b` | AND logique, met les drapeaux sans modifier a |
| `cmp a, b` | Soustraction a-b, met les drapeaux sans modifier a |
| `je` / `jne` | Saut si égal / non égal (ZF) |
| `jb` / `ja` | Saut si inférieur / supérieur (non signé) |
| `jl` / `jg` | Saut si inférieur / supérieur (signé) |
| `mov al, [rsi]` | Lecture d'un octet en mémoire |
| `xchg` | Echange deux valeurs |
| `shr` / `shl` | Décalage a droite / gauche |
| `and` / `or` / `xor` | Opérations logiques bit a bit |

## Squelette minimal NASM (rappel)

```nasm
section .data
    ; tes données ici

section .bss
    ; tes buffers ici (resb, resw, resd, resq)

section .text
    global _start

_start:
    ; ton code ici

    ; exit propre
    mov rax, 60         ; sys_exit
    xor rdi, rdi        ; code retour 0
    syscall
```

Pour afficher une chaine :

```nasm
    mov rax, 1          ; sys_write
    mov rdi, 1          ; stdout
    lea rsi, [msg]      ; adresse de la chaine
    mov rdx, longueur   ; nombre d'octets
    syscall
```
