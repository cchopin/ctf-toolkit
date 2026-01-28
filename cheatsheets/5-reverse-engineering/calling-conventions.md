# Calling conventions cheatsheet

## Vue d'ensemble

Une **calling convention** définit comment les fonctions reçoivent leurs paramètres, retournent leurs valeurs, et quels registres doivent être préservés.

---

## x86-64 / AMD64

### Linux / Unix / macOS (System V AMD64 ABI)

```
+------------------+------------------------------------------+
| Arguments        | rdi, rsi, rdx, rcx, r8, r9 puis stack    |
| Retour           | rax (128-bit: rax:rdx)                   |
| Caller-saved     | rax, rcx, rdx, rsi, rdi, r8-r11          |
| Callee-saved     | rbx, rbp, r12-r15, rsp                   |
| Stack alignment  | 16 bytes avant CALL                      |
| Red zone         | 128 bytes sous rsp (leaf functions)      |
+------------------+------------------------------------------+
```

**Passage des arguments:**
| # | Integer/Pointer | Float/Double |
|---|-----------------|--------------|
| 1 | rdi             | xmm0         |
| 2 | rsi             | xmm1         |
| 3 | rdx             | xmm2         |
| 4 | rcx             | xmm3         |
| 5 | r8              | xmm4         |
| 6 | r9              | xmm5         |
| 7+| Stack (RTL)     | xmm6-7, stack|

**Red Zone:** Zone de 128 bytes sous rsp utilisable sans ajuster rsp (fonctions feuilles uniquement).

### Windows x64 (Microsoft ABI)

```
+------------------+------------------------------------------+
| Arguments        | rcx, rdx, r8, r9 puis stack              |
| Retour           | rax (128-bit: rax:rdx)                   |
| Caller-saved     | rax, rcx, rdx, r8-r11                    |
| Callee-saved     | rbx, rbp, rdi, rsi, r12-r15, rsp         |
| Stack alignment  | 16 bytes avant CALL                      |
| Shadow space     | 32 bytes obligatoire (home area)         |
+------------------+------------------------------------------+
```

**Passage des arguments:**
| # | Integer/Pointer | Float/Double |
|---|-----------------|--------------|
| 1 | rcx             | xmm0         |
| 2 | rdx             | xmm1         |
| 3 | r8              | xmm2         |
| 4 | r9              | xmm3         |
| 5+| Stack           | Stack        |

**Shadow Space:** L'appelant DOIT allouer 32 bytes (4 x 8) sur la stack même si la fonction a moins de 4 arguments.

### Comparaison Linux vs Windows x64

| Aspect           | Linux (System V)       | Windows (MS x64)        |
|------------------|------------------------|-------------------------|
| Args 1-4         | rdi, rsi, rdx, rcx     | rcx, rdx, r8, r9        |
| Args 5-6         | r8, r9                 | Stack                   |
| Callee-saved     | rbx, r12-r15, rbp      | rbx, r12-r15, rbp, rdi, rsi |
| Shadow space     | Non (red zone)         | Oui (32 bytes)          |
| Red zone         | 128 bytes              | Non                     |

---

## x86 (32-bit)

### cdecl (C Declaration) - Default Linux/GCC

```
+------------------+------------------------------------------+
| Arguments        | Stack (right-to-left)                    |
| Retour           | eax (64-bit: edx:eax)                    |
| Caller-saved     | eax, ecx, edx                            |
| Callee-saved     | ebx, esi, edi, ebp, esp                  |
| Stack cleanup    | Caller                                   |
+------------------+------------------------------------------+
```

```asm
; func(1, 2, 3)
push 3          ; arg3
push 2          ; arg2
push 1          ; arg1
call func
add esp, 12     ; Caller nettoie la stack
```

### stdcall (Windows API)

```
+------------------+------------------------------------------+
| Arguments        | Stack (right-to-left)                    |
| Retour           | eax                                      |
| Stack cleanup    | Callee (via ret N)                       |
+------------------+------------------------------------------+
```

```asm
; MessageBoxA(0, "msg", "title", 0)
push 0          ; uType
push title      ; lpCaption
push msg        ; lpText
push 0          ; hWnd
call MessageBoxA  ; Callee fait ret 16
```

### fastcall (Microsoft)

```
+------------------+------------------------------------------+
| Arguments        | ecx, edx, puis stack                     |
| Retour           | eax                                      |
| Stack cleanup    | Callee                                   |
+------------------+------------------------------------------+
```

### thiscall (C++ methods)

```
+------------------+------------------------------------------+
| this pointer     | ecx (MSVC) ou stack (GCC)                |
| Arguments        | Stack                                    |
| Stack cleanup    | Callee (MSVC) / Caller (GCC)             |
+------------------+------------------------------------------+
```

---

## ARM64 (AArch64)

### AAPCS64 (Linux/Generic)

```
+------------------+------------------------------------------+
| Arguments        | x0-x7 (int), v0-v7 (float)               |
| Retour           | x0 (128-bit: x0:x1)                      |
| Caller-saved     | x0-x18, v0-v7, v16-v31                   |
| Callee-saved     | x19-x28, v8-v15                          |
| Frame pointer    | x29 (FP)                                 |
| Link register    | x30 (LR)                                 |
| Stack alignment  | 16 bytes                                 |
+------------------+------------------------------------------+
```

**Registres spéciaux:**
| Registre | Rôle                          |
|----------|-------------------------------|
| x0-x7    | Arguments / Retour            |
| x8       | Indirect result location      |
| x9-x15   | Temporaires (caller-saved)    |
| x16-x17  | Intra-procedure call (IP0/IP1)|
| x18      | Platform register (réservé)   |
| x19-x28  | Callee-saved                  |
| x29      | Frame pointer                 |
| x30      | Link register (return addr)   |
| sp       | Stack pointer                 |

### Différences macOS ARM64 (Darwin ABI)

| Aspect              | Linux AAPCS64     | macOS Darwin       |
|---------------------|-------------------|--------------------|
| Alignement args     | 8 bytes           | Taille naturelle   |
| x18                 | Disponible        | Réservé (TLS)      |
| Variadic args       | Standard          | Tous sur stack     |

**Exemple alignement macOS:**
```c
// func(char a, short b, int c)
// Linux:  a en x0[0:7], b en x1[0:15], c en x2[0:31]
// macOS:  a en x0[0:7], b aligné 2B, c aligné 4B
```

### Windows ARM64

- Similaire à AAPCS64 avec quelques différences
- **ARM64EC**: Convention pour interop avec x64 emulé
- x18 réservé pour TEB (Thread Environment Block)

---

## ARM32 (AArch32)

### AAPCS (ARM Procedure Call Standard)

```
+------------------+------------------------------------------+
| Arguments        | r0-r3, puis stack                        |
| Retour           | r0 (64-bit: r0:r1)                       |
| Caller-saved     | r0-r3, r12                               |
| Callee-saved     | r4-r11, r13 (sp), r14 (lr)               |
| Frame pointer    | r11 (optionnel)                          |
| Link register    | r14 (LR)                                 |
+------------------+------------------------------------------+
```

---

## Tableau récapitulatif

### Arguments par architecture

| Arch          | Convention    | Arg1 | Arg2 | Arg3 | Arg4 | Arg5 | Arg6 |
|---------------|---------------|------|------|------|------|------|------|
| x64 Linux     | System V      | rdi  | rsi  | rdx  | rcx  | r8   | r9   |
| x64 Windows   | MS x64        | rcx  | rdx  | r8   | r9   | stk  | stk  |
| x86           | cdecl         | stk  | stk  | stk  | stk  | stk  | stk  |
| x86           | fastcall      | ecx  | edx  | stk  | stk  | stk  | stk  |
| ARM64         | AAPCS64       | x0   | x1   | x2   | x3   | x4   | x5   |
| ARM32         | AAPCS         | r0   | r1   | r2   | r3   | stk  | stk  |

### Valeur de retour

| Architecture  | Integer       | Float         | Struct grande    |
|---------------|---------------|---------------|------------------|
| x64 Linux     | rax           | xmm0          | Via pointeur rdi |
| x64 Windows   | rax           | xmm0          | Via pointeur rcx |
| x86 cdecl     | eax           | ST(0)         | Via pointeur     |
| ARM64         | x0            | v0            | Via x8           |
| ARM32         | r0            | s0/d0         | Via r0 (pointeur)|

---

## Stack frame layout

### x64 Linux (System V)
```
High addresses
+------------------+
| ...              |
| Arg 8 (si >6)    | [rbp+24]
| Arg 7 (si >6)    | [rbp+16]
+------------------+
| Return address   | [rbp+8]
+------------------+
| Saved RBP        | [rbp]     <- rbp pointe ici
+------------------+
| Local var 1      | [rbp-8]
| Local var 2      | [rbp-16]
| ...              |
+------------------+
| Red zone (128B)  | <- rsp peut être ici (leaf)
+------------------+
Low addresses
```

### x64 Windows
```
High addresses
+------------------+
| Arg 6+           | [rbp+56]
| Arg 5            | [rbp+48]
+------------------+
| Shadow space     | [rbp+16 to rbp+40]  (32 bytes)
+------------------+
| Return address   | [rbp+8]
+------------------+
| Saved RBP        | [rbp]
+------------------+
| Local vars       |
+------------------+ <- rsp (aligned 16)
Low addresses
```

### ARM64
```
High addresses
+------------------+
| Arg 9+           |
+------------------+
| Saved x30 (LR)   | [sp, #8] après prologue
| Saved x29 (FP)   | [sp, #0] après prologue <- x29
+------------------+
| Local vars       |
| Callee-saved     |
+------------------+ <- sp (aligned 16)
Low addresses
```

---

## Exemples pratiques

### Appel printf Linux x64
```c
printf("Value: %d, %s\n", 42, "hello");
```
```asm
lea rdi, [rel format]   ; 1er arg: format string
mov esi, 42             ; 2ème arg: int
lea rdx, [rel str]      ; 3ème arg: string
xor eax, eax            ; AL = 0 (pas d'args vector)
call printf
```

### Appel Windows API
```c
MessageBoxA(NULL, "Text", "Title", MB_OK);
```
```asm
xor ecx, ecx            ; hWnd = NULL
lea rdx, [rel text]     ; lpText
lea r8, [rel title]     ; lpCaption
xor r9d, r9d            ; uType = MB_OK (0)
sub rsp, 32             ; Shadow space
call MessageBoxA
add rsp, 32
```

---

## Ressources

- [System V AMD64 ABI](https://gitlab.com/x86-psABIs/x86-64-ABI)
- [Microsoft x64 Calling Convention](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [ARM AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
- [Agner Fog's Calling Conventions](https://www.agner.org/optimize/calling_conventions.pdf)
