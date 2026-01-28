# x86/x64 Assembly Instructions Cheatsheet

## Registres

### Registres Généraux x64

| 64-bit | 32-bit | 16-bit | 8-bit (low) | 8-bit (high) | Usage courant           |
|--------|--------|--------|-------------|--------------|-------------------------|
| rax    | eax    | ax     | al          | ah           | Accumulateur, retour    |
| rbx    | ebx    | bx     | bl          | bh           | Base (callee-saved)     |
| rcx    | ecx    | cx     | cl          | ch           | Compteur, arg4 (Win)    |
| rdx    | edx    | dx     | dl          | dh           | Data, arg3 (Win)        |
| rsi    | esi    | si     | sil         | -            | Source, arg2 (Linux)    |
| rdi    | edi    | di     | dil         | -            | Dest, arg1 (Linux)      |
| rbp    | ebp    | bp     | bpl         | -            | Base pointer (stack)    |
| rsp    | esp    | sp     | spl         | -            | Stack pointer           |
| r8     | r8d    | r8w    | r8b         | -            | arg5 (Win) / arg5 (Lin) |
| r9     | r9d    | r9w    | r9b         | -            | arg6 (Win) / arg6 (Lin) |
| r10    | r10d   | r10w   | r10b        | -            | Temporaire              |
| r11    | r11d   | r11w   | r11b        | -            | Temporaire              |
| r12-r15| r12d   | r12w   | r12b        | -            | Callee-saved            |

### Registres Spéciaux

| Registre | Description                                      |
|----------|--------------------------------------------------|
| rip      | Instruction pointer (adresse instruction)        |
| rflags   | Flags (ZF, CF, SF, OF, etc.)                     |
| cs, ds, ss, es, fs, gs | Segment registers              |

### Flags Importants (RFLAGS)

| Flag | Nom           | Description                              |
|------|---------------|------------------------------------------|
| ZF   | Zero Flag     | 1 si résultat = 0                        |
| CF   | Carry Flag    | 1 si carry/borrow (unsigned overflow)    |
| SF   | Sign Flag     | 1 si résultat négatif (bit de poids fort)|
| OF   | Overflow Flag | 1 si signed overflow                     |
| PF   | Parity Flag   | 1 si nombre pair de bits à 1             |
| DF   | Direction     | Direction pour string ops (0=up, 1=down) |

---

## Top 20 Instructions (couvrent ~90% du code)

| Instruction | Description                    | Exemple                    |
|-------------|--------------------------------|----------------------------|
| mov         | Copie valeur                   | `mov rax, rbx`             |
| push        | Empile sur stack               | `push rbp`                 |
| pop         | Dépile du stack                | `pop rbp`                  |
| call        | Appel fonction                 | `call func`                |
| ret         | Retour de fonction             | `ret`                      |
| lea         | Load effective address         | `lea rax, [rbx+rcx*4]`     |
| add         | Addition                       | `add rax, 1`               |
| sub         | Soustraction                   | `sub rsp, 0x20`            |
| xor         | XOR (souvent pour zéro)        | `xor eax, eax`             |
| cmp         | Compare (set flags)            | `cmp rax, 0`               |
| test        | AND logique (set flags)        | `test eax, eax`            |
| jmp         | Saut inconditionnel            | `jmp label`                |
| je/jz       | Jump if equal/zero             | `je equal_label`           |
| jne/jnz     | Jump if not equal/not zero     | `jne loop`                 |
| jl/jb       | Jump if less (signed/unsigned) | `jl negative`              |
| jg/ja       | Jump if greater (signed/unsig) | `ja bigger`                |
| nop         | No operation                   | `nop`                      |
| and         | AND logique                    | `and eax, 0xff`            |
| or          | OR logique                     | `or eax, 1`                |
| shl/shr     | Shift left/right               | `shl eax, 2`               |

---

## Instructions par Catégorie

### Transfert de Données

| Instruction | Description                              | Exemple                      |
|-------------|------------------------------------------|------------------------------|
| mov         | Move data                                | `mov rax, [rbx]`             |
| movzx       | Move with zero-extend                    | `movzx eax, byte [rsi]`      |
| movsx       | Move with sign-extend                    | `movsx rax, eax`             |
| lea         | Load effective address (calcul adresse)  | `lea rax, [rip+0x100]`       |
| xchg        | Exchange values                          | `xchg rax, rbx`              |
| push        | Push onto stack (rsp -= 8)               | `push rax`                   |
| pop         | Pop from stack (rsp += 8)                | `pop rax`                    |
| movabs      | Move 64-bit immediate                    | `movabs rax, 0x123456789`    |

### Arithmétique

| Instruction | Description                    | Flags affectés    |
|-------------|--------------------------------|-------------------|
| add         | dst = dst + src                | CF, ZF, SF, OF    |
| sub         | dst = dst - src                | CF, ZF, SF, OF    |
| inc         | dst = dst + 1                  | ZF, SF, OF        |
| dec         | dst = dst - 1                  | ZF, SF, OF        |
| neg         | dst = -dst (two's complement)  | CF, ZF, SF, OF    |
| mul         | Unsigned multiply (rdx:rax)    | CF, OF            |
| imul        | Signed multiply                | CF, OF            |
| div         | Unsigned divide                | -                 |
| idiv        | Signed divide                  | -                 |

**Division:**
```asm
; div rbx -> rax = rdx:rax / rbx, rdx = remainder
xor rdx, rdx    ; Clear rdx before div
mov rax, 100
mov rbx, 7
div rbx         ; rax = 14, rdx = 2
```

### Logique et Bits

| Instruction | Description                    | Usage courant               |
|-------------|--------------------------------|-----------------------------|
| and         | Bitwise AND                    | Masquer bits                |
| or          | Bitwise OR                     | Activer bits                |
| xor         | Bitwise XOR                    | Toggle bits, zéro rapide    |
| not         | Bitwise NOT                    | Inverser tous les bits      |
| shl/sal     | Shift left (multiply by 2^n)  | `shl eax, 3` = eax * 8      |
| shr         | Shift right logical           | Division unsigned par 2^n   |
| sar         | Shift right arithmetic        | Division signed par 2^n     |
| rol/ror     | Rotate left/right             | Rotation circulaire         |
| bt          | Bit test                       | Test bit spécifique         |
| bts/btr/btc | Bit test and set/reset/compl  | Modifier bit spécifique     |

### Comparaison et Test

| Instruction | Description                              | Utilisation           |
|-------------|------------------------------------------|-----------------------|
| cmp a, b    | Calcule a - b, set flags (pas de store)  | Compare deux valeurs  |
| test a, b   | Calcule a & b, set flags (pas de store)  | Test bits/zéro        |

**Patterns courants:**
```asm
test eax, eax       ; Check if eax == 0 (plus rapide que cmp eax, 0)
cmp eax, 10         ; Compare eax avec 10
test al, 1          ; Check if odd (bit 0)
```

### Sauts Conditionnels

| Instruction | Condition           | Flags testés      | Signed/Unsigned |
|-------------|---------------------|-------------------|-----------------|
| je / jz     | Equal / Zero        | ZF = 1            | Both            |
| jne / jnz   | Not Equal / Not Zero| ZF = 0            | Both            |
| jl / jnge   | Less                | SF != OF          | Signed          |
| jle / jng   | Less or Equal       | ZF=1 or SF!=OF    | Signed          |
| jg / jnle   | Greater             | ZF=0 and SF=OF    | Signed          |
| jge / jnl   | Greater or Equal    | SF = OF           | Signed          |
| jb / jnae   | Below (carry)       | CF = 1            | Unsigned        |
| jbe / jna   | Below or Equal      | CF=1 or ZF=1      | Unsigned        |
| ja / jnbe   | Above               | CF=0 and ZF=0     | Unsigned        |
| jae / jnb   | Above or Equal      | CF = 0            | Unsigned        |
| js          | Sign (negative)     | SF = 1            | -               |
| jns         | Not Sign            | SF = 0            | -               |
| jo          | Overflow            | OF = 1            | -               |
| jno         | Not Overflow        | OF = 0            | -               |

### Contrôle de Flux

| Instruction | Description                              |
|-------------|------------------------------------------|
| jmp         | Saut inconditionnel                      |
| call        | Push rip, jump to function               |
| ret         | Pop rip, return from function            |
| leave       | mov rsp, rbp; pop rbp (épilogue)         |
| loop        | Décrémente rcx, jump si != 0             |
| int         | Software interrupt                        |
| syscall     | System call (x64)                        |
| int 0x80    | System call (x86 legacy)                 |

### Opérations sur Strings

| Instruction | Description                          | Direction (DF) |
|-------------|--------------------------------------|----------------|
| movsb/w/d/q | Move string byte/word/dword/qword    | rsi -> rdi     |
| stosb/w/d/q | Store AL/AX/EAX/RAX to [rdi]         | rdi            |
| lodsb/w/d/q | Load [rsi] to AL/AX/EAX/RAX          | rsi            |
| cmpsb/w/d/q | Compare [rsi] with [rdi]             | rsi, rdi       |
| scasb/w/d/q | Compare AL/AX/EAX/RAX with [rdi]     | rdi            |
| rep         | Repeat while rcx != 0                | -              |
| repe/repz   | Repeat while equal/zero              | -              |
| repne/repnz | Repeat while not equal/not zero      | -              |

**Exemple memset:**
```asm
mov rdi, buffer     ; destination
mov al, 0           ; valeur
mov rcx, 100        ; count
cld                 ; clear direction flag
rep stosb           ; repeat store byte
```

---

## Patterns Communs en Reverse

### Prologue de Fonction
```asm
push rbp            ; Sauvegarder ancien base pointer
mov rbp, rsp        ; Nouveau base pointer
sub rsp, 0x20       ; Allouer espace local
```

### Épilogue de Fonction
```asm
leave               ; mov rsp, rbp; pop rbp
ret                 ; Return
; ou
add rsp, 0x20       ; Libérer espace local
pop rbp
ret
```

### Appel de Fonction (Linux x64)
```asm
mov rdi, arg1       ; 1er argument
mov rsi, arg2       ; 2ème argument
mov rdx, arg3       ; 3ème argument
call function
; Retour dans rax
```

### Boucle For
```c
// for (int i = 0; i < 10; i++)
```
```asm
    xor ecx, ecx        ; i = 0
.loop:
    cmp ecx, 10         ; i < 10 ?
    jge .end            ; si i >= 10, sortir
    ; ... corps de boucle ...
    inc ecx             ; i++
    jmp .loop
.end:
```

### Switch/Case
```asm
cmp eax, 0
je .case_0
cmp eax, 1
je .case_1
cmp eax, 2
je .case_2
jmp .default
```

### Zéro rapide
```asm
xor eax, eax        ; eax = 0 (plus court et rapide que mov eax, 0)
```

### Test si NULL
```asm
test rax, rax       ; Set ZF if rax == 0
jz .is_null
```

### Multiplication par constante
```asm
; x * 5
lea eax, [rax + rax*4]  ; eax = rax + rax*4 = rax*5

; x * 10
lea eax, [rax + rax*4]  ; eax = rax*5
add eax, eax            ; eax = rax*10
```

---

## Encodage des Instructions

### Format ModR/M
```
+---+---+---+---+---+---+---+---+
| 7   6 | 5   4   3 | 2   1   0 |
|  Mod  |    Reg    |    R/M    |
+---+---+---+---+---+---+---+---+

Mod:
  00 = [reg]           (pas de déplacement)
  01 = [reg + disp8]   (déplacement 8-bit)
  10 = [reg + disp32]  (déplacement 32-bit)
  11 = reg             (registre direct)
```

### Préfixes REX (x64)
```
0100 WRXB
W = 64-bit operand size
R = Extension du champ Reg
X = Extension du champ Index (SIB)
B = Extension du champ R/M ou Base
```

---

## Ressources

- [Intel x86/x64 Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [x86 Opcode Reference](http://ref.x86asm.net/)
- [Compiler Explorer](https://godbolt.org/) - Voir le code généré
- [Trail of Bits x86 Cheatsheet](https://trailofbits.github.io/ctf/vulnerabilities/references/X86_Win32_Reverse_Engineering_Cheat_Sheet.pdf)
