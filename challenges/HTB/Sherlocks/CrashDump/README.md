# CrashDump - Write-up Sherlock

![HTB CrashDump](https://img.shields.io/badge/HackTheBox-CrashDump-green)![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)![Category](https://img.shields.io/badge/Category-Forensics-purple)

## Scénario

Un système Windows a été compromis par un framework C2. Deux fichiers minidump (`.DMP`) sont fournis pour identifier l'intrusion et extraire les indicateurs de compromission (IOC).

## Fichiers fournis

- `notepad.DMP` - Dump du processus injecté (notepad.exe)
- `update.DMP` - Dump du processus malveillant (update.exe)

---

## Qu'est-ce qu'un Minidump ?

Un **minidump** est un fichier de diagnostic Windows contenant un instantané partiel de la mémoire d'un processus. Contrairement à un full dump, il ne contient que les informations essentielles pour le débogage.

### Structures principales d'un minidump

| Stream | Description |
|--------|-------------|
| `SystemInfo` | Version OS, architecture, processeur |
| `ModuleList` | Liste des DLL/EXE chargés avec leurs versions |
| `ThreadList` | Liste des threads avec leur contexte CPU |
| `ThreadInfoList` | Métadonnées des threads (timestamps, priorité) |
| `MemoryList` | Régions mémoire capturées |
| `MemoryInfoList` | Informations sur toutes les régions (permissions, type) |
| `MiscInfo` | PID, timestamps du processus |

### Documentation

- [MSDN - MINIDUMP_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_type)
- [MSDN - Minidump Files](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [minidump (Python)](https://github.com/skelsec/minidump) - Bibliothèque Python pour parser les minidumps

### Installation

```bash
pip install minidump
```

### Exemple de base

```python
from minidump.minidumpfile import MinidumpFile

mf = MinidumpFile.parse('fichier.DMP')

# Informations système
print(f'OS: {mf.sysinfo.OperatingSystem}')
print(f'Version: {mf.sysinfo.MajorVersion}.{mf.sysinfo.MinorVersion}')

# PID du processus
print(f'PID: {mf.misc_info.ProcessId}')

# Modules chargés
for mod in mf.modules.modules:
    print(f'{mod.name}')

# Threads
print(f'Nombre de threads: {len(mf.threads.threads)}')
```

---

## Tâche 1 : Quelle est la version de l'OS ?

**Format attendu** : `X.X.XXXXX.XXXXX`

**Méthode** : L'information de version du système est stockée dans le stream `SystemInfo` du minidump. On peut également l'obtenir via les informations de version des modules système (ntdll.dll, kernel32.dll).

```python
from minidump.minidumpfile import MinidumpFile

mf = MinidumpFile.parse('notepad.DMP')

# Version depuis SystemInfo
si = mf.sysinfo
print(f'OS: {si.OperatingSystem}')
print(f'Version: {si.MajorVersion}.{si.MinorVersion}.{si.BuildNumber}')

# Version complète depuis ntdll.dll
for mod in mf.modules.modules:
    if 'ntdll' in mod.name.lower():
        vi = mod.versioninfo
        major = vi.dwFileVersionMS >> 16
        minor = vi.dwFileVersionMS & 0xFFFF
        build = vi.dwFileVersionLS >> 16
        revision = vi.dwFileVersionLS & 0xFFFF
        print(f'Full version: {major}.{minor}.{build}.{revision}')
```

---

## Tâche 2 : Quel est le nombre de threads du processus malveillant ?

**Méthode** : Le processus malveillant est `update.exe`. On compte les threads dans son minidump.

```python
mf = MinidumpFile.parse('update.DMP')
print(f'Nombre de threads: {len(mf.threads.threads)}')
```

---

## Tâche 3 : Quel processus a été compromis ?

**Méthode** : Analyser les modules chargés dans chaque dump pour identifier le processus légitime utilisé comme cible d'injection.

```python
for mod in mf.modules.modules:
    print(f'{mod.name} - Version: {mod.versioninfo}')
```

Indices :
- Le processus malveillant aura souvent une version `0.0.0.0` (pas de version info)
- Le processus injecté sera un exécutable Windows légitime

---

## Tâche 4 : Quel est le Named Pipe (canal IPC) utilisé ?

**Format attendu** : `****-****-******`

**Méthode** : Les named pipes sont un mécanisme de communication inter-processus utilisé par certains frameworks C2 pour la communication entre le beacon et les processus injectés.

```bash
strings update.DMP | grep -iE 'pipe|MSSE|postex' | grep -v 'api-ms\|Broken'
```

Le pattern `MSSE-XXXX-server` est caractéristique de Cobalt Strike (Microsoft Security Service Emulator).

---

## Tâche 5 : Quel est le PID du processus injecté ?

**Méthode** : Le PID est stocké dans le stream `MiscInfo` du minidump.

```python
mf = MinidumpFile.parse('notepad.DMP')
print(f'PID: {mf.misc_info.ProcessId}')
```

---

## Tâche 6 : Quel est le timestamp du dernier thread créé ?

**Format attendu** : `YYYY-MM-DD hh:mm:ss`

**Méthode** : Les informations de thread incluent le `CreateTime` en format Windows FILETIME (intervalles de 100 nanosecondes depuis le 1er janvier 1601).

```python
from datetime import datetime, timedelta

EPOCH_AS_FILETIME = 116444736000000000

def filetime_to_dt(ft):
    us = (ft - EPOCH_AS_FILETIME) // 10
    return datetime(1970, 1, 1) + timedelta(microseconds=us)

mf = MinidumpFile.parse('notepad.DMP')
for info in mf.thread_info.infos:
    dt = filetime_to_dt(info.CreateTime)
    print(f'Thread {info.ThreadId}: {dt}')
```

Le dernier thread créé est celui avec le timestamp le plus récent.

---

## Tâche 7 : Quelle est la BaseAddress du shellcode injecté ?

**Format attendu** : `XX`XXXXXXXX`

**Méthode** : Le shellcode est généralement placé dans une région mémoire avec les permissions `PAGE_EXECUTE_READWRITE` (RWX) de type `MEM_PRIVATE` - caractéristique d'une allocation suspecte.

```python
mf = MinidumpFile.parse('notepad.DMP')
for mi in mf.memory_info.infos:
    protect = str(mi.Protect)
    mtype = str(mi.Type)
    if 'EXECUTE' in protect and 'IMAGE' not in mtype:
        print(f'Base: 0x{mi.BaseAddress:x}, Size: {mi.RegionSize}')
```

Pour confirmer l'adresse, corréler avec le `StartAddress` des threads - le thread injecté aura son point d'entrée dans cette région.

---

## Tâche 8 : Quelle est l'adresse IP du serveur C2 ?

**Méthode** : Recherche d'adresses IP dans la mémoire du processus injecté.

```bash
strings notepad.DMP | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn
```

Vérifier le contexte des IP suspectes :

```bash
strings notepad.DMP | grep 'IP_SUSPECTE'
```

Indices à rechercher :
- URLs HTTP avec chemins suspects (`/submit.php`, URIs courtes aléatoires)
- Headers HTTP (`Host:`, `GET`, `POST`)
- Ports non-standard

---

## Tâche 9 : Quel framework C2 a été utilisé ?

**Méthode** : Recherche de signatures connues de frameworks C2.

```bash
strings notepad.DMP | grep -iE 'beacon|cobaltstrike|metasploit|meterpreter|sliver|havoc'
```

Indicateurs courants de Cobalt Strike :
- Présence de `beacon.dll` ou `beacon.x64.dll`
- Named pipe `MSSE-XXXX-server`
- Pattern d'URI HTTP caractéristique
- Strings `%s (admin)`, `%s as %s\\%s`

---

## Techniques d'analyse complémentaires

### Extraction de la mémoire du shellcode

```python
# Lire le contenu mémoire à une adresse spécifique
for segment in mf.memory_segments:
    if segment.start_virtual_address == SHELLCODE_BASE:
        data = segment.read(segment.start_virtual_address, segment.size)
        with open('shellcode.bin', 'wb') as f:
            f.write(data)
```

### Détection de process injection

| Indicateur | Description |
|------------|-------------|
| Région RWX | Mémoire avec Execute+Read+Write (suspect) |
| MEM_PRIVATE | Allocation privée (pas un module mappé) |
| Thread StartAddress | Pointe vers une région non-image |
| Module sans version | DLL/EXE avec version 0.0.0.0 |

### Commandes strings utiles

```bash
# Recherche d'URLs
strings dump.DMP | grep -iE 'http://|https://'

# Recherche de chemins Windows
strings dump.DMP | grep -iE 'C:\\Users\\|C:\\Windows\\'

# Recherche de noms de fichiers
strings dump.DMP | grep -iE '\.exe|\.dll|\.bat|\.ps1'

# Recherche de named pipes
strings dump.DMP | grep -i 'pipe'
```

---

## Ressources

- [Cobalt Strike - Indicators of Compromise](https://www.cobaltstrike.com/help-malleable-c2)
- [MITRE ATT&CK - Process Injection](https://attack.mitre.org/techniques/T1055/)
- [Windows Internals - Minidump](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/minidump-files)

---
