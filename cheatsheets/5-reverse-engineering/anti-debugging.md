# Anti-Debugging Techniques Cheatsheet

## Vue d'Ensemble

L'anti-debugging regroupe les techniques utilisées pour détecter ou perturber l'analyse d'un programme sous debugger. Comprendre ces techniques est essentiel pour l'analyse de malware.

---

## Windows Anti-Debugging

### 1. IsDebuggerPresent

**Détection:**
```c
if (IsDebuggerPresent()) {
    // Debugger détecté
    exit(1);
}
```

**Assembleur:**
```asm
; Appel API
call IsDebuggerPresent
test eax, eax
jnz debugger_detected

; Accès direct PEB
mov eax, fs:[30h]        ; PEB (32-bit)
mov eax, gs:[60h]        ; PEB (64-bit)
movzx eax, byte [eax+2]  ; BeingDebugged
test eax, eax
jnz debugger_detected
```

**Bypass:**
```
# GDB/pwndbg
set *(char*)($fs_base+0x30+2) = 0

# x64dbg
PEB.BeingDebugged = 0
```

### 2. CheckRemoteDebuggerPresent

**Détection:**
```c
BOOL isDebugged = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
if (isDebugged) exit(1);
```

**Bypass:** Hook la fonction ou modifier la valeur retournée.

### 3. NtQueryInformationProcess

**Détection:**
```c
DWORD debugPort = 0;
NtQueryInformationProcess(
    GetCurrentProcess(),
    ProcessDebugPort,          // 7
    &debugPort,
    sizeof(debugPort),
    NULL
);
if (debugPort != 0) exit(1);

// Ou ProcessDebugObjectHandle (0x1E)
// Ou ProcessDebugFlags (0x1F)
```

**Bypass:** Hook ntdll!NtQueryInformationProcess.

### 4. PEB Flags

**Détection:**
```c
// NtGlobalFlag (offset 0x68 en 32-bit, 0xBC en 64-bit)
DWORD ntGlobalFlag = *(PDWORD)((PBYTE)peb + 0x68);
// FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
if (ntGlobalFlag & 0x70) exit(1);
```

```asm
; 32-bit
mov eax, fs:[30h]
mov eax, [eax+68h]      ; NtGlobalFlag
and eax, 70h
jnz debugger_detected

; 64-bit
mov rax, gs:[60h]
mov eax, [rax+0BCh]
and eax, 70h
jnz debugger_detected
```

**Bypass:** Mettre NtGlobalFlag à 0.

### 5. Heap Flags

**Détection:**
```c
// Le heap alloué sous debugger a des flags spéciaux
PHEAP heap = (PHEAP)GetProcessHeap();
if (heap->Flags & ~HEAP_GROWABLE || heap->ForceFlags) {
    exit(1);  // Debugger détecté
}
```

### 6. Hardware Breakpoints (Debug Registers)

**Détection:**
```c
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
    exit(1);  // Hardware breakpoint détecté
}
```

**Bypass:** Clear les debug registers.

### 7. Software Breakpoints (INT 3)

**Détection:**
```c
// Vérifier la présence de 0xCC dans le code
BYTE* funcAddr = (BYTE*)&SomeFunction;
if (*funcAddr == 0xCC) {
    exit(1);  // Breakpoint détecté
}
```

```c
// Checksum du code
DWORD checksum = CalculateChecksum(codeStart, codeSize);
if (checksum != EXPECTED_CHECKSUM) {
    exit(1);  // Code modifié (breakpoint ou patch)
}
```

### 8. Timing Attacks

**Détection:**
```c
LARGE_INTEGER start, end, freq;
QueryPerformanceFrequency(&freq);
QueryPerformanceCounter(&start);

// Code à protéger
DoSomething();

QueryPerformanceCounter(&end);
double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;

if (elapsed > THRESHOLD_MS) {
    exit(1);  // Exécution trop lente = stepping
}
```

```c
// Ou avec RDTSC
unsigned __int64 start = __rdtsc();
DoSomething();
unsigned __int64 end = __rdtsc();
if (end - start > THRESHOLD_CYCLES) exit(1);
```

**Bypass:** Modifier les valeurs retournées par les fonctions de timing.

### 9. Exceptions

**Détection:**
```c
__try {
    __asm { int 3 }  // Si pas de debugger, exception gérée
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    // Normal: pas de debugger
    return FALSE;
}
// Si on arrive ici, le debugger a "mangé" l'exception
return TRUE;
```

```c
// CloseHandle avec handle invalide
__try {
    CloseHandle((HANDLE)0xDEADBEEF);
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    // Sans debugger: exception
    return FALSE;
}
// Avec debugger: pas d'exception
return TRUE;
```

### 10. Parent Process Check

**Détection:**
```c
// Vérifier si le parent est explorer.exe (normal) ou autre (debugger)
DWORD parentPID = GetParentProcessId();
HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, parentPID);
// Comparer le nom du processus parent avec "explorer.exe"
```

### 11. Window Enumeration

**Détection:**
```c
// Chercher des fenêtres de debuggers connus
if (FindWindowA("OLLYDBG", NULL) ||
    FindWindowA("x64dbg", NULL) ||
    FindWindowA("IDA", NULL)) {
    exit(1);
}
```

---

## Linux Anti-Debugging

### 1. ptrace(PTRACE_TRACEME)

**Détection:**
```c
if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
    // Déjà tracé par un debugger
    exit(1);
}
```

**Bypass:**
```bash
# LD_PRELOAD avec fake ptrace
# Ou patch le binaire

# GDB: catch syscall ptrace, puis return 0
```

### 2. /proc/self/status - TracerPid

**Détection:**
```c
FILE* f = fopen("/proc/self/status", "r");
char line[256];
while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
        int tracerPid = atoi(line + 10);
        if (tracerPid != 0) {
            exit(1);  // Debugger attaché
        }
    }
}
```

**Bypass:** Modifier le fichier status via LD_PRELOAD ou hook open/read.

### 3. /proc/self/exe Symlink

**Détection:**
```c
char buf[PATH_MAX];
ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
// Comparer avec le chemin attendu
// Certains debuggers modifient ce lien
```

### 4. getppid() Parent Check

**Détection:**
```c
pid_t ppid = getppid();
char path[64];
snprintf(path, sizeof(path), "/proc/%d/comm", ppid);
FILE* f = fopen(path, "r");
char comm[256];
fgets(comm, sizeof(comm), f);
// Vérifier si parent est bash/zsh (normal) ou gdb/lldb
```

### 5. Timing (RDTSC, clock_gettime)

**Détection:**
```c
struct timespec start, end;
clock_gettime(CLOCK_MONOTONIC, &start);
// Code sensible
clock_gettime(CLOCK_MONOTONIC, &end);
long diff = (end.tv_sec - start.tv_sec) * 1000000000 +
            (end.tv_nsec - start.tv_nsec);
if (diff > THRESHOLD_NS) exit(1);
```

### 6. Signal Handlers

**Détection:**
```c
void sigtrap_handler(int sig) {
    // Exécuté si pas de debugger
    // Le debugger intercepte SIGTRAP
}

signal(SIGTRAP, sigtrap_handler);
raise(SIGTRAP);
// Si on arrive ici sans passer par handler = debugger
```

### 7. Prctl

**Détection:**
```c
// Empêcher l'attachement futur d'un debugger
prctl(PR_SET_DUMPABLE, 0);

// Plus agressif: tuer si tracé
prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
```

### 8. LD_PRELOAD Detection

**Détection:**
```c
if (getenv("LD_PRELOAD") != NULL) {
    exit(1);  // Possible instrumentation
}
```

---

## macOS Anti-Debugging

### 1. ptrace(PT_DENY_ATTACH)

**Détection:**
```c
ptrace(PT_DENY_ATTACH, 0, 0, 0);
// Après cet appel, tout debugger sera refusé
```

**Bypass:**
```bash
# LLDB: process attach --pid PID --waitfor avant que le check s'exécute
# Ou patcher l'appel ptrace dans le binaire
```

### 2. sysctl

**Détection:**
```c
int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
struct kinfo_proc info;
size_t size = sizeof(info);
sysctl(mib, 4, &info, &size, NULL, 0);
if (info.kp_proc.p_flag & P_TRACED) {
    exit(1);
}
```

### 3. AmIBeingDebugged (via sysctl)

```c
#include <sys/sysctl.h>

int AmIBeingDebugged(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info = {0};
    size_t size = sizeof(info);
    sysctl(mib, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
```

### 4. task_info

**Détection:**
```c
mach_msg_type_number_t count = TASK_DEBUG_INFO_INTERNAL_COUNT;
task_debug_info_internal_t info;
task_info(mach_task_self(), TASK_DEBUG_INFO_INTERNAL, (task_info_t)&info, &count);
// Analyser les informations de debug
```

---

## Techniques Anti-VM/Sandbox

### Détection VM

| Check                     | VMware               | VirtualBox           | Hyper-V             |
|---------------------------|----------------------|----------------------|---------------------|
| MAC address prefix        | 00:0C:29, 00:50:56   | 08:00:27             | 00:15:5D            |
| CPUID (EAX=0)             | "VMwareVMware"       | "VBoxVBoxVBox"       | "Microsoft Hv"      |
| Registry keys             | VMware Tools         | VBoxGuest            | Hyper-V             |
| Processes                 | vmtoolsd.exe         | VBoxService.exe      | vmms.exe            |
| Driver files              | vmhgfs.sys           | VBoxMouse.sys        | -                   |

**CPUID Check:**
```c
int cpuInfo[4];
__cpuid(cpuInfo, 0x40000000);
char vendor[13];
memcpy(vendor, &cpuInfo[1], 4);
memcpy(vendor+4, &cpuInfo[2], 4);
memcpy(vendor+8, &cpuInfo[3], 4);
vendor[12] = 0;
// vendor contient "VMwareVMware", "VBoxVBoxVBox", etc.
```

### Détection Sandbox/Analysis

```c
// Vérifier les usernames courants en sandbox
char username[256];
GetUserNameA(username, &size);
if (strstr(username, "sandbox") ||
    strstr(username, "virus") ||
    strstr(username, "malware")) {
    exit(1);
}

// Vérifier la présence d'outils d'analyse
if (GetModuleHandleA("SbieDll.dll") ||    // Sandboxie
    GetModuleHandleA("dbghelp.dll") ||     // Debugging
    GetModuleHandleA("api_log.dll")) {     // API logging
    exit(1);
}

// Vérifier les ressources système (VM souvent limitées)
MEMORYSTATUSEX mem;
mem.dwLength = sizeof(mem);
GlobalMemoryStatusEx(&mem);
if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {  // < 2GB
    exit(1);
}

// Nombre de CPU
SYSTEM_INFO si;
GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) {
    exit(1);
}
```

---

## Techniques de Bypass Génériques

### 1. Patching Binaire

```bash
# Trouver et patcher les checks anti-debug
# Remplacer les jumps conditionnels par NOPs ou JMP inconditionnels

# Exemple: jnz (75) -> jmp (EB) ou nop nop (90 90)
```

### 2. LD_PRELOAD (Linux)

```c
// fake_ptrace.c
long ptrace(int request, ...) {
    return 0;  // Always succeed
}
```
```bash
gcc -shared -fPIC fake_ptrace.c -o fake_ptrace.so
LD_PRELOAD=./fake_ptrace.so ./binary
```

### 3. GDB Scripts

```gdb
# Bypass IsDebuggerPresent
catch syscall
commands
    if $rax == 0xNN  # syscall number
        set $rax = 0
    end
    continue
end

# Ou définir un hook
define hook-stop
    set *(char*)(PEB+2) = 0
end
```

### 4. x64dbg Plugins

- ScyllaHide: Cache le debugger automatiquement
- TitanHide: Kernel-mode anti-anti-debug
- SharpOD: Anti-anti-debug

### 5. Frida Instrumentation

```javascript
// Bypass ptrace
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        this.request = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (this.request == 0) {  // PTRACE_TRACEME
            retval.replace(0);
        }
    }
});

// Bypass IsDebuggerPresent
Interceptor.attach(Module.findExportByName("kernel32.dll", "IsDebuggerPresent"), {
    onLeave: function(retval) {
        retval.replace(0);
    }
});
```

---

## Ressources

- [Anti-Debug Tricks (checkpoint)](https://anti-debug.checkpoint.com/)
- [al-khaser](https://github.com/LordNoteworthy/al-khaser) - Outil de test anti-debug
- [Unprotect Project](https://unprotect.it/) - Base de données techniques
- [ScyllaHide](https://github.com/x64dbg/ScyllaHide)
