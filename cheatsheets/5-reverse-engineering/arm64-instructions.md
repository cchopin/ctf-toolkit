# ARM64 (AArch64) assembly instructions cheatsheet

## Caractéristiques ARM64

- **Architecture RISC** : Instructions simples, taille fixe (4 bytes)
- **Load/Store** : Seules les instructions load/store accèdent à la mémoire
- **31 registres généraux** : x0-x30 (64-bit) / w0-w30 (32-bit)
- **Pas d'accès mémoire direct** dans les opérations arithmétiques

---

## Registres

### Registres généraux

| 64-bit | 32-bit | Usage AAPCS64                              |
|--------|--------|-------------------------------------------|
| x0-x7  | w0-w7  | Arguments et valeurs de retour            |
| x8     | w8     | Indirect result (ou syscall Linux)        |
| x9-x15 | w9-w15 | Temporaires (caller-saved)                |
| x16    | w16    | IP0 - Intra-procedure scratch (syscall macOS) |
| x17    | w17    | IP1 - Intra-procedure scratch             |
| x18    | w18    | Platform register (réservé)               |
| x19-x28| w19-w28| Callee-saved registers                    |
| x29    | w29    | Frame pointer (FP)                        |
| x30    | w30    | Link register (LR) - adresse retour       |
| sp     | wsp    | Stack pointer                             |
| xzr    | wzr    | Zero register (toujours 0)                |
| pc     | -      | Program counter (non accessible direct)   |

### Registres spéciaux

| Registre | Description                              |
|----------|------------------------------------------|
| sp       | Stack pointer                            |
| pc       | Program counter                          |
| xzr/wzr  | Zero register (lecture=0, écriture=NOP)  |
| NZCV     | Condition flags (dans PSTATE)            |

### Condition flags (NZCV)

| Flag | Nom      | Description                          |
|------|----------|--------------------------------------|
| N    | Negative | Résultat négatif (bit 31/63 = 1)     |
| Z    | Zero     | Résultat = 0                         |
| C    | Carry    | Carry out / unsigned overflow        |
| V    | Overflow | Signed overflow                      |

---

## Instructions de base

### Transfert de données

| Instruction | Description                        | Exemple                    |
|-------------|------------------------------------|----------------------------|
| mov         | Move register                      | `mov x0, x1`               |
| mov         | Move immediate (16-bit)            | `mov x0, #42`              |
| movz        | Move wide with zero               | `movz x0, #0x1234`         |
| movk        | Move wide with keep               | `movk x0, #0x5678, lsl #16`|
| movn        | Move wide with NOT                | `movn x0, #0`              |
| mvn         | Bitwise NOT                        | `mvn x0, x1`               |

**Charger une constante 64-bit:**
```asm
movz x0, #0x1234            ; x0 = 0x0000000000001234
movk x0, #0x5678, lsl #16   ; x0 = 0x0000000056781234
movk x0, #0x9abc, lsl #32   ; x0 = 0x00009abc56781234
movk x0, #0xdef0, lsl #48   ; x0 = 0xdef09abc56781234
```

### Load/Store

| Instruction | Description                        | Exemple                    |
|-------------|------------------------------------|----------------------------|
| ldr         | Load register                      | `ldr x0, [x1]`             |
| ldrb        | Load byte (zero-extend)            | `ldrb w0, [x1]`            |
| ldrh        | Load halfword (zero-extend)        | `ldrh w0, [x1]`            |
| ldrsb       | Load byte (sign-extend)            | `ldrsb x0, [x1]`           |
| ldrsh       | Load halfword (sign-extend)        | `ldrsh x0, [x1]`           |
| ldrsw       | Load word (sign-extend to 64)      | `ldrsw x0, [x1]`           |
| str         | Store register                     | `str x0, [x1]`             |
| strb        | Store byte                         | `strb w0, [x1]`            |
| strh        | Store halfword                     | `strh w0, [x1]`            |
| ldp         | Load pair                          | `ldp x0, x1, [sp]`         |
| stp         | Store pair                         | `stp x0, x1, [sp]`         |

### Modes d'adressage

| Mode                    | Syntaxe                  | Effet                          |
|-------------------------|--------------------------|--------------------------------|
| Base                    | `[x0]`                   | addr = x0                      |
| Offset immédiat         | `[x0, #16]`              | addr = x0 + 16                 |
| Pre-index               | `[x0, #16]!`             | x0 += 16, addr = x0            |
| Post-index              | `[x0], #16`              | addr = x0, x0 += 16            |
| Register offset         | `[x0, x1]`               | addr = x0 + x1                 |
| Scaled register         | `[x0, x1, lsl #3]`       | addr = x0 + (x1 << 3)          |
| PC-relative             | `[pc, #offset]` ou label | addr = pc + offset             |

**Exemples:**
```asm
ldr x0, [x1]            ; x0 = *x1
ldr x0, [x1, #8]        ; x0 = *(x1 + 8)
ldr x0, [x1, #8]!       ; x1 += 8; x0 = *x1 (pre-increment)
ldr x0, [x1], #8        ; x0 = *x1; x1 += 8 (post-increment)
ldr x0, [x1, x2]        ; x0 = *(x1 + x2)
ldr x0, [x1, x2, lsl #3]; x0 = *(x1 + x2*8)
```

### Arithmétique

| Instruction | Description                        | Exemple                    |
|-------------|------------------------------------|----------------------------|
| add         | Addition                           | `add x0, x1, x2`           |
| adds        | Addition + set flags               | `adds x0, x1, x2`          |
| adc         | Add with carry                     | `adc x0, x1, x2`           |
| sub         | Subtraction                        | `sub x0, x1, x2`           |
| subs        | Subtraction + set flags            | `subs x0, x1, #1`          |
| sbc         | Subtract with carry                | `sbc x0, x1, x2`           |
| neg         | Negate                             | `neg x0, x1`               |
| mul         | Multiply                           | `mul x0, x1, x2`           |
| madd        | Multiply-add                       | `madd x0, x1, x2, x3`      |
| msub        | Multiply-subtract                  | `msub x0, x1, x2, x3`      |
| smull       | Signed multiply long               | `smull x0, w1, w2`         |
| umull       | Unsigned multiply long             | `umull x0, w1, w2`         |
| sdiv        | Signed divide                      | `sdiv x0, x1, x2`          |
| udiv        | Unsigned divide                    | `udiv x0, x1, x2`          |

**Opérations avec shift/extend:**
```asm
add x0, x1, x2, lsl #2   ; x0 = x1 + (x2 << 2)
add x0, x1, w2, sxtw     ; x0 = x1 + sign_extend(w2)
add x0, x1, w2, uxtw     ; x0 = x1 + zero_extend(w2)
```

### Logique et bits

| Instruction | Description                        | Exemple                    |
|-------------|------------------------------------|----------------------------|
| and         | Bitwise AND                        | `and x0, x1, x2`           |
| ands        | AND + set flags                    | `ands x0, x1, #0xff`       |
| orr         | Bitwise OR                         | `orr x0, x1, x2`           |
| eor         | Bitwise XOR                        | `eor x0, x1, x2`           |
| bic         | Bit clear (AND NOT)                | `bic x0, x1, x2`           |
| orn         | OR NOT                             | `orn x0, x1, x2`           |
| eon         | XOR NOT                            | `eon x0, x1, x2`           |
| lsl         | Logical shift left                 | `lsl x0, x1, #4`           |
| lsr         | Logical shift right                | `lsr x0, x1, #4`           |
| asr         | Arithmetic shift right             | `asr x0, x1, #4`           |
| ror         | Rotate right                       | `ror x0, x1, #4`           |

### Comparaison

| Instruction | Description                        | Exemple                    |
|-------------|------------------------------------|----------------------------|
| cmp         | Compare (sub sans store)           | `cmp x0, x1`               |
| cmn         | Compare negative (add sans store)  | `cmn x0, x1`               |
| tst         | Test bits (and sans store)         | `tst x0, #1`               |

### Branches

| Instruction | Description                        | Exemple                    |
|-------------|------------------------------------|----------------------------|
| b           | Branch unconditional               | `b label`                  |
| bl          | Branch with link (call)            | `bl function`              |
| br          | Branch to register                 | `br x0`                    |
| blr         | Branch with link to register       | `blr x0`                   |
| ret         | Return (br x30)                    | `ret`                      |
| cbz         | Compare and branch if zero         | `cbz x0, label`            |
| cbnz        | Compare and branch if not zero     | `cbnz x0, label`           |
| tbz         | Test bit and branch if zero        | `tbz x0, #5, label`        |
| tbnz        | Test bit and branch if not zero    | `tbnz x0, #5, label`       |

### Branches conditionnelles

| Instruction | Condition              | Flags            |
|-------------|------------------------|------------------|
| b.eq        | Equal                  | Z = 1            |
| b.ne        | Not equal              | Z = 0            |
| b.lt        | Less than (signed)     | N != V           |
| b.le        | Less or equal (signed) | Z=1 or N!=V      |
| b.gt        | Greater than (signed)  | Z=0 and N=V      |
| b.ge        | Greater or equal       | N = V            |
| b.lo / b.cc | Lower (unsigned)       | C = 0            |
| b.ls        | Lower or same          | C=0 or Z=1       |
| b.hi        | Higher (unsigned)      | C=1 and Z=0      |
| b.hs / b.cs | Higher or same         | C = 1            |
| b.mi        | Minus (negative)       | N = 1            |
| b.pl        | Plus (positive/zero)   | N = 0            |
| b.vs        | Overflow set           | V = 1            |
| b.vc        | Overflow clear         | V = 0            |

### Instructions conditionnelles

| Instruction | Description                        | Exemple                    |
|-------------|------------------------------------|----------------------------|
| csel        | Conditional select                 | `csel x0, x1, x2, eq`      |
| csinc       | Conditional select increment       | `csinc x0, x1, x2, ne`     |
| csinv       | Conditional select invert          | `csinv x0, x1, x2, lt`     |
| csneg       | Conditional select negate          | `csneg x0, x1, x2, gt`     |
| cset        | Conditional set                    | `cset x0, eq`              |
| csetm       | Conditional set mask               | `csetm x0, ne`             |

**Exemple: abs(x):**
```asm
cmp x0, #0
csneg x0, x0, x0, ge    ; if (x0 >= 0) x0 = x0 else x0 = -x0
```

### Système

| Instruction | Description                        | Exemple                    |
|-------------|------------------------------------|----------------------------|
| svc         | Supervisor call (syscall)          | `svc #0`                   |
| hvc         | Hypervisor call                    | `hvc #0`                   |
| smc         | Secure monitor call                | `smc #0`                   |
| brk         | Breakpoint                         | `brk #0`                   |
| nop         | No operation                       | `nop`                      |
| mrs         | Move from system register          | `mrs x0, NZCV`             |
| msr         | Move to system register            | `msr NZCV, x0`             |

---

## Patterns communs

### Prologue de fonction
```asm
stp x29, x30, [sp, #-16]!   ; Push FP et LR, sp -= 16
mov x29, sp                  ; Set frame pointer
sub sp, sp, #32              ; Allouer espace local
```

### Épilogue de fonction
```asm
add sp, sp, #32              ; Libérer espace local
ldp x29, x30, [sp], #16      ; Pop FP et LR, sp += 16
ret                          ; Return via x30
```

### Appel de fonction
```asm
mov x0, arg1        ; 1er argument
mov x1, arg2        ; 2ème argument
mov x2, arg3        ; 3ème argument
bl function         ; Appel (sauvegarde PC+4 dans x30)
; Retour dans x0
```

### Boucle
```asm
    mov x0, #0          ; i = 0
.loop:
    cmp x0, #10         ; i < 10 ?
    b.ge .end           ; sortir si >= 10
    ; ... corps ...
    add x0, x0, #1      ; i++
    b .loop
.end:
```

### Syscall Linux ARM64
```asm
mov x8, #64         ; syscall number (write)
mov x0, #1          ; fd = stdout
ldr x1, =msg        ; buffer
mov x2, #14         ; len
svc #0              ; syscall
```

### Syscall macOS ARM64
```asm
mov x16, #4         ; syscall number (write)
mov x0, #1          ; fd = stdout
ldr x1, =msg        ; buffer
mov x2, #14         ; len
svc #0x80           ; syscall
```

---

## Différences Linux vs macOS ARM64

| Aspect              | Linux ARM64          | macOS ARM64          |
|---------------------|----------------------|----------------------|
| Syscall register    | x8                   | x16                  |
| Syscall instruction | `svc #0`             | `svc #0x80`          |
| x18 usage           | Disponible           | Réservé (TLS)        |
| Stack alignment     | 16 bytes             | 16 bytes             |

---

## Adressage PC-relative

### ADRP + ADD pattern
```asm
; Charger l'adresse d'un symbole global
adrp x0, symbol@PAGE        ; x0 = page contenant symbol
add x0, x0, symbol@PAGEOFF  ; x0 += offset dans la page
```

### LDR literal
```asm
ldr x0, =constant    ; Charge adresse/valeur depuis literal pool
ldr x0, label        ; Charge depuis PC + offset
```

---

## Ressources

- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest)
- [ARM64 Cheat Sheet (Swarthmore)](https://www.cs.swarthmore.edu/~kwebb/cs31/resources/ARM64_Cheat_Sheet.pdf)
- [AArch64 Assembly Tutorial](https://mariokartwii.com/armv8/)
- [ARM64 Assembly Guide (modexp)](https://modexp.wordpress.com/2018/10/30/arm64-assembly/)
