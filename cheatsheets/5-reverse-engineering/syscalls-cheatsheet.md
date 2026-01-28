# Syscalls cheatsheet - Assembleur multi-architecture

## Comprendre les syscalls

### Qu'est-ce qu'un syscall ?
Un syscall (system call) est une interface entre un programme utilisateur et le noyau du système d'exploitation. Chaque syscall a un numéro unique qui varie selon l'OS et l'architecture.

---

## Convention d'appel par OS/architecture

### Linux x86_64 (64-bit)
```
Instruction: syscall
Numéro:      rax
Arguments:   rdi, rsi, rdx, r10, r8, r9
Retour:      rax
```

### Linux x86 (32-bit)
```
Instruction: int 0x80
Numéro:      eax
Arguments:   ebx, ecx, edx, esi, edi, ebp
Retour:      eax
```

### Linux ARM64 (aarch64)
```
Instruction: svc #0
Numéro:      x8
Arguments:   x0, x1, x2, x3, x4, x5
Retour:      x0
```

### macOS x86_64 (Intel)
```
Instruction: syscall
Numéro:      rax (avec préfixe classe!)
Arguments:   rdi, rsi, rdx, r10, r8, r9
Retour:      rax
```

### macOS ARM64 (Apple Silicon)
```
Instruction: svc #0x80
Numéro:      x16
Arguments:   x0, x1, x2, x3, x4, x5
Retour:      x0
```

### Windows x64
```
Instruction: syscall
Numéro:      rax (varie selon la version Windows!)
Arguments:   rcx, rdx, r8, r9, [stack]
Retour:      rax
Note: Préférer les API Win32 (kernel32, ntdll)
```

---

## Le mystère du 0x2000000 sur macOS

Sur macOS, le numéro de syscall contient une **classe** dans les bits de poids fort:

```
Format: 0xCLASSE_NUMERO

| Classe | Préfixe    | Description           |
|--------|------------|-----------------------|
| 0      | 0x0000000  | Mach traps (invalid)  |
| 1      | 0x1000000  | Mach traps            |
| 2      | 0x2000000  | BSD syscalls          |
| 3      | 0x3000000  | Machine dependent     |
```

**Exemple expliqué:**
```asm
mov rax, 0x2000004  ; Classe 2 (BSD) + syscall 4 (write)
                     ; = 0x2000000 + 0x4 = 0x2000004
```

---

## Tableau comparatif des syscalls courants

### Opérations fichiers/IO

| Fonction    | Linux x64 | Linux x86 | Linux ARM64 | macOS (BSD) | macOS (full)  |
|-------------|-----------|-----------|-------------|-------------|---------------|
| read        | 0         | 3         | 63          | 3           | 0x2000003     |
| write       | 1         | 4         | 64          | 4           | 0x2000004     |
| open        | 2         | 5         | -           | 5           | 0x2000005     |
| openat      | 257       | 295       | 56          | 463         | 0x20001CF     |
| close       | 3         | 6         | 57          | 6           | 0x2000006     |
| lseek       | 8         | 19        | 62          | 199         | 0x20000C7     |
| mmap        | 9         | 90        | 222         | 197         | 0x20000C5     |
| munmap      | 11        | 91        | 215         | 73          | 0x2000049     |
| dup         | 32        | 41        | 23          | 41          | 0x2000029     |
| dup2        | 33        | 63        | -           | 90          | 0x200005A     |
| dup3        | 292       | 330       | 24          | -           | -             |
| pipe        | 22        | 42        | -           | 42          | 0x200002A     |
| pipe2       | 293       | 331       | 59          | -           | -             |
| fstat       | 5         | 108       | 80          | 339         | 0x2000153     |
| newfstatat  | 262       | 300       | 79          | -           | -             |

> **Note ARM64:** Linux ARM64 n'a pas `open`, `dup2`, `pipe`, `stat` - utiliser `openat`, `dup3`, `pipe2`, `newfstatat`

### Processus

| Fonction    | Linux x64 | Linux x86 | Linux ARM64 | macOS (BSD) | macOS (full)  |
|-------------|-----------|-----------|-------------|-------------|---------------|
| exit        | 60        | 1         | 93          | 1           | 0x2000001     |
| exit_group  | 231       | 252       | 94          | -           | -             |
| fork        | 57        | 2         | -           | 2           | 0x2000002     |
| clone       | 56        | 120       | 220         | -           | -             |
| execve      | 59        | 11        | 221         | 59          | 0x200003B     |
| getpid      | 39        | 20        | 172         | 20          | 0x2000014     |
| getuid      | 102       | 24        | 174         | 24          | 0x2000018     |
| getgid      | 104       | 47        | 176         | 47          | 0x200002F     |
| kill        | 62        | 37        | 129         | 37          | 0x2000025     |
| wait4       | 61        | 114       | 260         | 7           | 0x2000007     |

> **Note ARM64:** Linux ARM64 n'a pas `fork` - utiliser `clone`

### Réseau

| Fonction    | Linux x64 | Linux x86 | Linux ARM64 | macOS (BSD) | macOS (full)  |
|-------------|-----------|-----------|-------------|-------------|---------------|
| socket      | 41        | 359       | 198         | 97          | 0x2000061     |
| connect     | 42        | 362       | 203         | 98          | 0x2000062     |
| accept      | 43        | 364       | 202         | 30          | 0x200001E     |
| bind        | 49        | 361       | 200         | 104         | 0x2000068     |
| listen      | 50        | 363       | 201         | 106         | 0x200006A     |
| sendto      | 44        | 369       | 206         | 133         | 0x2000085     |
| recvfrom    | 45        | 371       | 207         | 29          | 0x200001D     |
| shutdown    | 48        | 373       | 210         | 134         | 0x2000086     |
| setsockopt  | 54        | 366       | 208         | 105         | 0x2000069     |
| getsockopt  | 55        | 365       | 209         | 118         | 0x2000076     |

### Mémoire

| Fonction    | Linux x64 | Linux x86 | Linux ARM64 | macOS (BSD) | macOS (full)  |
|-------------|-----------|-----------|-------------|-------------|---------------|
| brk         | 12        | 45        | 214         | -           | -             |
| mprotect    | 10        | 125       | 226         | 74          | 0x200004A     |
| msync       | 26        | 144       | 227         | 65          | 0x2000041     |

---

## Exemples complets

### Hello World - Linux x86_64
```asm
section .data
    msg db "Hello, World!", 10
    len equ $ - msg

section .text
    global _start

_start:
    ; write(1, msg, len)
    mov rax, 1          ; syscall: write
    mov rdi, 1          ; fd: stdout
    lea rsi, [rel msg]  ; buffer
    mov rdx, len        ; count
    syscall

    ; exit(0)
    mov rax, 60         ; syscall: exit
    xor rdi, rdi        ; code: 0
    syscall
```

### Hello World - Linux x86 (32-bit)
```asm
section .data
    msg db "Hello, World!", 10
    len equ $ - msg

section .text
    global _start

_start:
    ; write(1, msg, len)
    mov eax, 4          ; syscall: write
    mov ebx, 1          ; fd: stdout
    mov ecx, msg        ; buffer
    mov edx, len        ; count
    int 0x80

    ; exit(0)
    mov eax, 1          ; syscall: exit
    xor ebx, ebx        ; code: 0
    int 0x80
```

### Hello World - Linux ARM64 (aarch64)
```asm
.global _start
.section .text

_start:
    // write(1, msg, len)
    mov x0, #1          // fd: stdout
    ldr x1, =msg        // buffer
    mov x2, #14         // len
    mov x8, #64         // syscall: write
    svc #0

    // exit(0)
    mov x0, #0          // code: 0
    mov x8, #93         // syscall: exit
    svc #0

.section .data
msg: .ascii "Hello, World!\n"
```

**Compilation Linux ARM64:**
```bash
as -o hello.o hello.s
ld -o hello hello.o
```

### Hello World - macOS x86_64 (Intel)
```asm
section .data
    msg db "Hello, World!", 10
    len equ $ - msg

section .text
    global _main

_main:
    ; write(1, msg, len)
    mov rax, 0x2000004  ; syscall: write (BSD class)
    mov rdi, 1          ; fd: stdout
    lea rsi, [rel msg]  ; buffer
    mov rdx, len        ; count
    syscall

    ; exit(0)
    mov rax, 0x2000001  ; syscall: exit (BSD class)
    xor rdi, rdi        ; code: 0
    syscall
```

### Hello World - macOS ARM64 (Apple Silicon)
```asm
.global _main
.align 4

_main:
    ; write(1, msg, len)
    mov x0, #1          ; fd: stdout
    adrp x1, msg@PAGE
    add x1, x1, msg@PAGEOFF
    mov x2, #14         ; len
    mov x16, #4         ; syscall: write
    svc #0x80

    ; exit(0)
    mov x0, #0          ; code: 0
    mov x16, #1         ; syscall: exit
    svc #0x80

.data
msg: .ascii "Hello, World!\n"
```

---

## Windows syscalls (NT API)

**Attention:** Les numéros de syscalls Windows changent entre versions!

### Numéros syscall Windows (exemples - peuvent varier!)

| Fonction          | Win7 x64 | Win10 1909 | Win11    |
|-------------------|----------|------------|----------|
| NtCreateFile      | 0x52     | 0x55       | 0x55     |
| NtReadFile        | 0x03     | 0x06       | 0x06     |
| NtWriteFile       | 0x05     | 0x08       | 0x08     |
| NtClose           | 0x0C     | 0x0F       | 0x0F     |
| NtAllocateVirtualMemory | 0x15 | 0x18     | 0x18     |
| NtProtectVirtualMemory  | 0x4D | 0x50     | 0x50     |
| NtTerminateProcess| 0x29     | 0x2C       | 0x2C     |

### Exemple Windows (via ntdll.dll - méthode recommandée)
```asm
; Windows n'est pas fait pour les syscalls directs
; Utilisez les API Win32 ou ntdll.dll

extern GetStdHandle
extern WriteConsoleA
extern ExitProcess

section .data
    msg db "Hello, World!", 13, 10
    len equ $ - msg

section .text
    global main

main:
    ; GetStdHandle(-11) pour stdout
    mov ecx, -11
    call GetStdHandle

    ; WriteConsoleA(handle, msg, len, &written, NULL)
    sub rsp, 40
    mov rcx, rax
    lea rdx, [rel msg]
    mov r8d, len
    lea r9, [rsp+32]
    mov qword [rsp+32], 0
    call WriteConsoleA
    add rsp, 40

    ; ExitProcess(0)
    xor ecx, ecx
    call ExitProcess
```

---

## Référence rapide - Conversions

### Calcul macOS syscall number
```
macOS_syscall = 0x2000000 + BSD_number
```

### Trouver les syscalls sur votre système

**Linux:**
```bash
# x86_64
cat /usr/include/asm/unistd_64.h | grep __NR_

# x86
cat /usr/include/asm/unistd_32.h | grep __NR_

# ARM64 (aarch64)
cat /usr/include/asm-generic/unistd.h | grep __NR_

# Ou via ausyscall (si disponible)
ausyscall --dump
```

**macOS:**
```bash
# BSD syscalls
cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h | grep SYS_
```

---

## Ressources

- **Linux x64 syscalls:** https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
- **Linux x86 syscalls:** https://syscalls.w3challs.com/?arch=x86
- **Linux ARM64 syscalls:** https://arm64.syscall.sh/
- **Linux multi-arch (JS requis):** https://syscalls.mebeim.net/
- **macOS XNU source (syscalls.master):** https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/syscalls.master
- **macOS syscall list generator:** https://github.com/dyjakan/osx-syscalls-list
- **Windows syscalls:** https://j00ru.vexillium.org/syscalls/nt/64/

---

## Aide-mémoire rapide

```
+------------------+----------+---------+-------------+---------------------------+
|     Système      | Registre | Instr.  | Préfixe     | Arguments                 |
+------------------+----------+---------+-------------+---------------------------+
| Linux x86_64     | rax      | syscall | aucun       | rdi, rsi, rdx, r10, r8, r9|
| Linux x86        | eax      | int 80h | aucun       | ebx, ecx, edx, esi, edi   |
| Linux ARM64      | x8       | svc #0  | aucun       | x0, x1, x2, x3, x4, x5    |
| macOS x86_64     | rax      | syscall | 0x2000000   | rdi, rsi, rdx, r10, r8, r9|
| macOS ARM64      | x16      | svc 80h | aucun       | x0, x1, x2, x3, x4, x5    |
| Windows x64      | rax      | syscall | aucun*      | rcx, rdx, r8, r9, [stack] |
+------------------+----------+---------+-------------+---------------------------+
* Windows: numéros varient selon version, préférer API
```

### Différences clés Linux ARM64 vs macOS ARM64

| Aspect           | Linux ARM64      | macOS ARM64      |
|------------------|------------------|------------------|
| Registre syscall | **x8**           | **x16**          |
| Instruction      | `svc #0`         | `svc #0x80`      |
| Numéros          | Spécifiques ARM  | BSD + préfixe    |
