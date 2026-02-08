# Registres general purpose en x86-64

## Vue d'ensemble

L'architecture x86-64 dispose de **16 registres general purpose** (GPR), chacun de 64 bits. Ils servent a stocker des donnees temporaires, des adresses memoire, des compteurs, et des parametres de fonctions. Bien qu'ils soient "general purpose", plusieurs ont un role conventionnel qu'il est important de connaitre.

Un registre, c'est un petit espace de stockage ultra-rapide directement dans le processeur. Contrairement a la RAM, y acceder ne coute quasiment rien en temps. C'est pour ca qu'on essaie de travailler au maximum avec les registres avant de recourir a la memoire.

---

## Les 8 registres historiques (herites du x86)

Ces registres existaient deja en 32 bits (eax, ebx...) et ont ete etendus a 64 bits avec le prefixe `r`.

---

### rax - Accumulator

Le registre accumulateur. C'est le registre "star" de l'architecture x86. Il est utilise implicitement par de nombreuses instructions et contient la **valeur de retour** des fonctions et des syscalls.

**Utilisations implicites :**
- `mul` et `div` utilisent rax comme operande source et destination
- `syscall` lit le numero du syscall dans rax et y place le resultat
- Les fonctions retournent leur valeur dans rax

```nasm
; Exemple 1 : retour de syscall
mov rax, 60         ; syscall numero 60 = exit
mov rdi, 0          ; code de retour 0
syscall             ; execute le syscall, le resultat serait dans rax

; Exemple 2 : multiplication implicite
mov rax, 5          ; rax = 5
mov rbx, 3
mul rbx             ; rax = rax * rbx = 15 (implicitement, rax est l'operande)
                    ; rdx:rax contient le resultat complet sur 128 bits

; Exemple 3 : valeur de retour d'une fonction
; Apres un call a une fonction, le resultat est dans rax
call maFonction
; rax contient maintenant ce que maFonction a retourne
```

---

### rbx - Base

Registre de base. Il n'a pas de role implicite dans les instructions modernes. C'est un registre "libre" qu'on utilise comme on veut. Sa particularite : il est **callee-saved**, ce qui signifie qu'une fonction appelee doit sauvegarder sa valeur et la restaurer avant de retourner.

En pratique, c'est un bon registre pour stocker une valeur qui doit survivre a un appel de fonction.

```nasm
; Exemple : stocker une valeur persistante
mov rbx, 42         ; on stocke 42 dans rbx
call uneAutreFonction
; rbx vaut toujours 42 ici, car la fonction a du le preserver

; Exemple dans le Fibonacci du cours :
xor rbx, rbx        ; rbx = 0
inc rbx              ; rbx = 1 (nombre courant de la suite)
; rbx sert ici a stocker le nombre de Fibonacci courant
```

---

### rcx - Counter

Le registre compteur. Le "c" vient de "counter". C'est le registre que le processeur utilise implicitement pour compter dans plusieurs situations.

**Utilisations implicites :**
- `loop` : decremente rcx et saute tant que rcx != 0
- `rep`, `repne` : repete une instruction de chaine rcx fois
- `shl reg, cl` / `shr reg, cl` : le nombre de bits a decaler est lu dans cl (partie basse 8 bits de rcx)

```nasm
; Exemple 1 : boucle avec loop
mov rcx, 5          ; on veut 5 iterations
maLoop:
    ; ... instructions de la boucle ...
    loop maLoop      ; rcx-- puis saute a maLoop si rcx != 0
; Quand on arrive ici, rcx vaut 0

; Exemple 2 : decalage variable
mov rax, 1          ; rax = 0000 0001
mov cl, 4           ; on veut decaler de 4 bits
shl rax, cl         ; rax = 0001 0000 = 16 en decimal
                    ; cl (partie basse de rcx) est lu implicitement

; Exemple 3 : copie de chaine avec rep
mov rcx, 10         ; nombre d'octets a copier
mov rsi, source     ; adresse source
mov rdi, dest       ; adresse destination
rep movsb           ; copie rcx octets de rsi vers rdi
```

C'est aussi le **4e argument** d'une fonction en convention d'appel System V (Linux), mais le **4e argument d'un syscall utilise r10** a la place (car `syscall` ecrase rcx).

---

### rdx - Data

Le registre de donnees. Il forme une paire avec rax pour les operations arithmetiques etendues.

**Utilisations implicites :**
- `mul` : le resultat 128 bits est stocke dans rdx:rax (rdx = partie haute, rax = partie basse)
- `div` : le dividende 128 bits est lu depuis rdx:rax, le quotient va dans rax, le reste dans rdx
- `cqo` : etend le signe de rax vers rdx (utile avant une division signee)

```nasm
; Exemple 1 : multiplication qui depasse 64 bits
mov rax, 0xFFFFFFFFFFFFFFFF  ; grand nombre
mov rbx, 2
mul rbx             ; rdx:rax = resultat sur 128 bits
                    ; rdx contient les bits de poids fort
                    ; rax contient les bits de poids faible

; Exemple 2 : division
mov rdx, 0          ; on met rdx a 0 (partie haute du dividende)
mov rax, 100        ; dividende = 100
mov rbx, 7
div rbx             ; rax = 100 / 7 = 14 (quotient)
                    ; rdx = 100 % 7 = 2  (reste)

; Exemple 3 : division signee (il faut etendre le signe)
mov rax, -100       ; dividende negatif
cqo                 ; etend le signe de rax dans rdx
                    ; (rdx devient 0xFFFFFFFFFFFFFFFF)
mov rbx, 7
idiv rbx            ; division signee correcte
```

C'est aussi le **3e argument** des fonctions et syscalls.

---

### rsi - Source Index

Registre d'index source. Le "s" vient de "source". Historiquement concu pour pointer vers la source lors des operations sur les chaines de caracteres.

```nasm
; Exemple 1 : copie de chaine
; rsi pointe vers la source, rdi vers la destination
mov rsi, adresseSource
mov rdi, adresseDest
mov rcx, 50         ; 50 octets a copier
rep movsb           ; copie octet par octet de [rsi] vers [rdi]

; Exemple 2 : comparaison de chaines
mov rsi, chaine1
mov rdi, chaine2
mov rcx, 10
repe cmpsb          ; compare octet par octet tant qu'ils sont egaux

; Exemple 3 : syscall write
mov rax, 1          ; syscall write
mov rdi, 1          ; file descriptor = stdout
mov rsi, message    ; rsi = adresse du buffer a ecrire (2e argument)
mov rdx, 13         ; longueur du message
syscall
```

En convention System V, c'est le **2e argument** des fonctions et syscalls.

---

### rdi - Destination Index

Registre d'index destination. Le "d" vient de "destination". Il est le pendant de rsi pour les operations sur les chaines.

```nasm
; Exemple 1 : remplir un buffer avec une valeur
mov rdi, adresseBuffer  ; destination
mov al, 0               ; valeur a ecrire (0 = on remplit de zeros)
mov rcx, 100            ; 100 octets
rep stosb               ; ecrit al dans [rdi] rcx fois

; Exemple 2 : premier argument d'un syscall
mov rax, 60         ; syscall exit
mov rdi, 0          ; rdi = code de sortie (1er argument)
syscall

; Exemple 3 : scanner un buffer pour trouver un octet
mov rdi, adresseBuffer
mov al, 0x41        ; on cherche 'A'
mov rcx, 256        ; taille max a scanner
repne scasb         ; cherche al dans [rdi], avance tant que different
```

En convention System V, c'est le **1er argument** des fonctions et syscalls.

---

### rbp - Base Pointer

Le pointeur de base de la pile (stack frame pointer). Il sert de point de reference fixe pour acceder aux variables locales et aux arguments d'une fonction.

Quand une fonction est appelee, un "cadre de pile" (stack frame) est cree. rbp pointe vers le debut de ce cadre et ne bouge plus pendant toute la duree de la fonction, contrairement a rsp qui change a chaque push/pop.

```nasm
; Exemple : prologue et epilogue classiques d'une fonction
maFonction:
    push rbp            ; sauvegarder l'ancien rbp (callee-saved)
    mov rbp, rsp        ; rbp = nouveau point de reference

    sub rsp, 16         ; reserver 16 octets pour les variables locales

    ; Acceder aux variables locales via rbp :
    mov qword [rbp-8], 42    ; variable locale 1 = 42
    mov qword [rbp-16], 10   ; variable locale 2 = 10

    ; ... code de la fonction ...

    ; Epilogue : restaurer l'etat
    mov rsp, rbp        ; liberer les variables locales
    pop rbp             ; restaurer l'ancien rbp
    ret                 ; retourner a l'appelant
```

rbp est **callee-saved**. Note : dans du code optimise avec `-O2`, le compilateur peut decider de ne pas utiliser rbp comme frame pointer (option `-fomit-frame-pointer`) et le traiter comme un registre general supplementaire.

---

### rsp - Stack Pointer

Le pointeur de pile. Il pointe **toujours** vers le sommet de la pile, c'est-a-dire l'adresse la plus basse actuellement utilisee. C'est le registre le plus critique : le corrompre entraine un crash immediat.

La pile grandit vers le bas en x86-64 : `push` diminue rsp, `pop` l'augmente.

```nasm
; Exemple 1 : push et pop
mov rax, 42
push rax            ; rsp -= 8, puis ecrit rax a [rsp]
                    ; la pile contient maintenant 42

push rbx            ; rsp -= 8, empile rbx au dessus

pop rbx             ; lit [rsp] dans rbx, puis rsp += 8
pop rax             ; lit [rsp] dans rax, puis rsp += 8
                    ; la pile est revenue a son etat initial

; Exemple 2 : reserver de l'espace sur la pile (sans push)
sub rsp, 32         ; reserver 32 octets pour des variables locales
mov qword [rsp], 1       ; variable a l'adresse rsp
mov qword [rsp+8], 2     ; variable a l'adresse rsp+8
; ...
add rsp, 32         ; liberer l'espace

; Exemple 3 : alignement de la pile
; Avant un call, rsp doit etre aligne sur 16 octets (convention System V)
; Le call lui-meme pousse l'adresse de retour (8 octets)
; Donc avant le call, rsp doit etre un multiple de 16
and rsp, -16        ; forcer l'alignement sur 16 octets
```

**Regle d'or** : a la fin d'une fonction, rsp doit avoir exactement la meme valeur qu'au debut. Chaque `push` doit avoir son `pop`, chaque `sub rsp` doit avoir son `add rsp`.

---

## Les 8 nouveaux registres (ajoutes par x86-64)

Ces registres ont ete introduits avec l'extension 64 bits. Ils sont nommes r8 a r15 et n'ont pas de role historique. Ils sont "vraiment" general purpose, sans aucun usage implicite par des instructions.

| Registre | Convention System V (Linux) | Callee-saved ? |
|----------|---------------------------|----------------|
| r8       | 5e argument de fonction   | Non            |
| r9       | 6e argument de fonction   | Non            |
| r10      | 4e argument de syscall    | Non            |
| r11      | Usage general             | Non            |
| r12      | Usage general             | Oui            |
| r13      | Usage general             | Oui            |
| r14      | Usage general             | Oui            |
| r15      | Usage general             | Oui            |

```nasm
; Exemple 1 : appel de fonction avec 6 arguments
; int resultat = maFonction(1, 2, 3, 4, 5, 6);
mov rdi, 1          ; arg 1
mov rsi, 2          ; arg 2
mov rdx, 3          ; arg 3
mov rcx, 4          ; arg 4
mov r8, 5           ; arg 5
mov r9, 6           ; arg 6
call maFonction     ; resultat dans rax

; Exemple 2 : syscall avec 4+ arguments (r10 remplace rcx)
; mmap(addr=0, len=4096, prot=3, flags=0x22, fd=-1, offset=0)
mov rax, 9          ; syscall mmap
mov rdi, 0          ; addr
mov rsi, 4096       ; length
mov rdx, 3          ; PROT_READ | PROT_WRITE
mov r10, 0x22       ; MAP_PRIVATE | MAP_ANONYMOUS (r10, pas rcx !)
mov r8, -1          ; fd
mov r9, 0           ; offset
syscall

; Exemple 3 : r12-r15 comme stockage persistant
push r12             ; sauvegarder (callee-saved, on doit le restaurer)
push r13

mov r12, [rdi]       ; charger une valeur qu'on veut garder
mov r13, [rsi]       ; une autre valeur persistante

call fonctionQuiModifieTout
; r12 et r13 sont toujours intacts ici
; rax, rcx, rdx, rsi, rdi, r8-r11 ont potentiellement ete ecrases

pop r13              ; restaurer
pop r12
```

**Pourquoi r10 remplace rcx pour les syscalls ?** Parce que l'instruction `syscall` ecrase automatiquement rcx (elle y stocke l'adresse de retour) et r11 (elle y stocke les flags). Ces deux registres ne peuvent donc pas transporter d'arguments pour un syscall.

---

## Sous-registres : acceder a des portions plus petites

Chaque registre 64 bits peut etre accede en tailles plus petites. C'est utile quand on travaille avec des donnees de taille inferieure a 64 bits (caracteres 8 bits, entiers 32 bits, etc.).

Prenons `rax` comme exemple :

```
|<--------------------- rax (64 bits) --------------------->|
                          |<-------- eax (32 bits) -------->|
                                     |<--- ax (16 bits) --->|
                                     |<- ah ->|<-- al ---->|
                                      (8 bits)   (8 bits)
```

### Nomenclature

| Taille   | Registres historiques           | Registres r8-r15        |
|----------|---------------------------------|-------------------------|
| 64 bits  | rax, rbx, rcx, rdx, rsi, rdi   | r8, r9, r10 ... r15     |
| 32 bits  | eax, ebx, ecx, edx, esi, edi   | r8d, r9d, r10d ... r15d |
| 16 bits  | ax, bx, cx, dx, si, di         | r8w, r9w, r10w ... r15w |
| 8 bits (bas)  | al, bl, cl, dl, sil, dil  | r8b, r9b, r10b ... r15b |
| 8 bits (haut) | ah, bh, ch, dh            | (pas d'equivalent)      |

### Comportement important lors de l'ecriture

```nasm
; Ecrire dans un sous-registre 32 bits met a zero les 32 bits superieurs
mov rax, 0xFFFFFFFFFFFFFFFF  ; rax = FFFFFFFFFFFFFFFF
mov eax, 1                   ; rax = 0000000000000001 (bits hauts effaces !)

; Ecrire dans un sous-registre 16 ou 8 bits ne touche PAS le reste
mov rax, 0xFFFFFFFFFFFFFFFF  ; rax = FFFFFFFFFFFFFFFF
mov ax, 1                    ; rax = FFFFFFFFFFFF0001 (seuls les 16 bits bas changent)
mov al, 0x42                 ; rax = FFFFFFFFFFFF0042 (seuls les 8 bits bas changent)
```

Cette difference de comportement entre 32 bits et 16/8 bits est un piege classique. La mise a zero automatique en 32 bits a ete introduite en x86-64 pour eviter les dependances de registres partiels qui ralentissaient le pipeline du processeur.

```nasm
; Astuce : xor eax, eax est la facon la plus efficace de mettre rax a 0
xor eax, eax        ; rax = 0 (les 32 bits hauts sont automatiquement effaces)
                    ; plus compact et plus rapide que mov rax, 0
```

---

## Convention d'appel System V (Linux x86-64)

C'est la convention standard sous Linux. Elle definit comment les arguments sont passes et quels registres doivent etre preserves.

### Passage d'arguments

| Argument  | Registre (fonction) | Registre (syscall) |
|-----------|--------------------|--------------------|
| 1er       | rdi                | rdi                |
| 2e        | rsi                | rsi                |
| 3e        | rdx                | rdx                |
| 4e        | rcx                | r10                |
| 5e        | r8                 | r8                 |
| 6e        | r9                 | r9                 |
| Retour    | rax                | rax                |
| N. syscall| -                  | rax                |

Si une fonction a plus de 6 arguments, les suivants sont passes sur la pile.

### Registres caller-saved vs callee-saved

C'est un concept essentiel pour comprendre quels registres sont "surs" apres un `call`.

**Caller-saved** (l'appelant doit les sauvegarder s'il y tient) : rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11. Ces registres peuvent etre ecrases par la fonction appelee sans avertissement.

**Callee-saved** (la fonction appelee doit les restaurer) : rbx, rbp, r12, r13, r14, r15. Si une fonction veut les utiliser, elle doit les push au debut et les pop a la fin.

```nasm
; Exemple complet : une fonction qui utilise des registres callee-saved
calculer:
    ; Prologue : sauvegarder les registres callee-saved qu'on va utiliser
    push rbx
    push r12

    mov rbx, rdi         ; sauvegarder le 1er argument dans rbx
    mov r12, rsi         ; sauvegarder le 2e argument dans r12

    ; Appeler une sous-fonction
    mov rdi, rbx
    call autreCalcul     ; peut ecraser rax, rcx, rdx, rsi, rdi, r8-r11
                         ; mais rbx et r12 sont toujours intacts

    add rax, r12         ; utiliser r12 qui a survecu au call

    ; Epilogue : restaurer les registres (ordre inverse !)
    pop r12
    pop rbx
    ret
```

---

## Resume rapide

| Registre | Nom               | Role principal                          | Callee-saved |
|----------|-------------------|-----------------------------------------|--------------|
| rax      | Accumulator       | Retour, mul/div implicite               | Non          |
| rbx      | Base              | General, persistant                     | Oui          |
| rcx      | Counter           | Compteur loop/rep, 4e arg fonction      | Non          |
| rdx      | Data              | Paire avec rax pour mul/div, 3e arg     | Non          |
| rsi      | Source Index      | Source chaines, 2e arg                  | Non          |
| rdi      | Destination Index | Dest chaines, 1er arg                   | Non          |
| rbp      | Base Pointer      | Cadre de pile                           | Oui          |
| rsp      | Stack Pointer     | Sommet de pile                          | -            |
| r8-r9    | -                 | 5e et 6e arguments                      | Non          |
| r10      | -                 | 4e arg syscall                          | Non          |
| r11      | -                 | Scratch                                 | Non          |
| r12-r15  | -                 | General, persistants                    | Oui          |
