# Executable file formats cheatsheet

## Vue d'ensemble

| Format  | Système           | Extension          | Magic bytes              |
|---------|-------------------|--------------------|--------------------------|
| ELF     | Linux, BSD, Unix  | (aucune), .so, .o  | `7F 45 4C 46` (`.ELF`)   |
| PE      | Windows           | .exe, .dll, .sys   | `4D 5A` (`MZ`)           |
| Mach-O  | macOS, iOS        | (aucune), .dylib   | `FE ED FA CE/CF` ou `CA FE BA BE` |

---

## ELF (Executable and Linkable Format)

### Structure générale

```
+------------------+
|    ELF Header    |  <- Identifie le fichier, pointe vers tables
+------------------+
| Program Headers  |  <- Segments (pour le loader)
|    (optional)    |
+------------------+
|                  |
|     Sections     |  <- .text, .data, .rodata, .bss, etc.
|                  |
+------------------+
| Section Headers  |  <- Métadonnées des sections
|    (optional)    |
+------------------+
```

### ELF header (64-bit)

| Offset | Taille | Champ            | Description                        |
|--------|--------|------------------|------------------------------------|
| 0x00   | 4      | e_ident[0-3]     | Magic: `7F 45 4C 46` (.ELF)        |
| 0x04   | 1      | e_ident[4]       | Class: 1=32-bit, 2=64-bit          |
| 0x05   | 1      | e_ident[5]       | Endianness: 1=LE, 2=BE             |
| 0x06   | 1      | e_ident[6]       | ELF version                        |
| 0x07   | 1      | e_ident[7]       | OS/ABI                             |
| 0x10   | 2      | e_type           | Type: 1=reloc, 2=exec, 3=shared    |
| 0x12   | 2      | e_machine        | Architecture (0x3E=x86_64, 0xB7=ARM64) |
| 0x18   | 8      | e_entry          | Entry point address                |
| 0x20   | 8      | e_phoff          | Program header table offset        |
| 0x28   | 8      | e_shoff          | Section header table offset        |
| 0x38   | 2      | e_phentsize      | Program header entry size          |
| 0x3A   | 2      | e_phnum          | Number of program headers          |
| 0x3C   | 2      | e_shentsize      | Section header entry size          |
| 0x3E   | 2      | e_shnum          | Number of section headers          |
| 0x40   | 2      | e_shstrndx       | Section name string table index    |

### Program header types (p_type)

| Valeur | Nom           | Description                           |
|--------|---------------|---------------------------------------|
| 0      | PT_NULL       | Unused                                |
| 1      | PT_LOAD       | Loadable segment                      |
| 2      | PT_DYNAMIC    | Dynamic linking info                  |
| 3      | PT_INTERP     | Interpreter path                      |
| 4      | PT_NOTE       | Auxiliary information                 |
| 6      | PT_PHDR       | Program header table                  |
| 7      | PT_TLS        | Thread-local storage                  |
| 0x6474e550 | PT_GNU_EH_FRAME | Exception handling           |
| 0x6474e551 | PT_GNU_STACK    | Stack executability          |
| 0x6474e552 | PT_GNU_RELRO    | Read-only after relocation   |

### Sections courantes

| Section    | Description                              | Flags |
|------------|------------------------------------------|-------|
| .text      | Code exécutable                          | AX    |
| .rodata    | Données en lecture seule (strings, etc.) | A     |
| .data      | Données initialisées (globales)          | WA    |
| .bss       | Données non-initialisées                 | WA    |
| .plt       | Procedure Linkage Table                  | AX    |
| .got       | Global Offset Table                      | WA    |
| .got.plt   | GOT pour PLT                             | WA    |
| .dynamic   | Dynamic linking info                     | WA    |
| .dynsym    | Dynamic symbol table                     | A     |
| .dynstr    | Dynamic string table                     | A     |
| .symtab    | Symbol table (peut être stripped)        | -     |
| .strtab    | String table                             | -     |
| .rel.plt   | Relocations pour PLT                     | A     |
| .init      | Initialization code                      | AX    |
| .fini      | Termination code                         | AX    |

**Flags:** A=Alloc, W=Write, X=Execute

### Commandes utiles

```bash
# Voir l'ELF header
readelf -h binary

# Voir les program headers (segments)
readelf -l binary

# Voir les section headers
readelf -S binary

# Voir les symboles
readelf -s binary
nm binary

# Voir les relocations
readelf -r binary

# Voir les dynamic dependencies
readelf -d binary
ldd binary

# Désassembler
objdump -d binary
objdump -M intel -d binary    # Syntaxe Intel
```

---

## PE (Portable Executable)

### Structure générale

```
+------------------+
|   DOS Header     |  <- "MZ", e_lfanew pointe vers PE
+------------------+
|   DOS Stub       |  <- "This program cannot be run in DOS mode"
+------------------+
|   PE Signature   |  <- "PE\0\0"
+------------------+
|   COFF Header    |  <- Machine, NumberOfSections, etc.
+------------------+
| Optional Header  |  <- Entry point, ImageBase, sections info
+------------------+
| Section Headers  |  <- .text, .data, .rdata, .rsrc, etc.
+------------------+
|                  |
|    Sections      |
|                  |
+------------------+
```

### DOS Header

| Offset | Taille | Champ      | Description                    |
|--------|--------|------------|--------------------------------|
| 0x00   | 2      | e_magic    | Magic: `4D 5A` ("MZ")          |
| 0x3C   | 4      | e_lfanew   | Offset vers PE header          |

### PE header (COFF)

| Offset | Taille | Champ              | Description                 |
|--------|--------|--------------------|-----------------------------|
| 0x00   | 4      | Signature          | "PE\0\0" (0x50450000)       |
| 0x04   | 2      | Machine            | 0x8664=x64, 0x14c=x86       |
| 0x06   | 2      | NumberOfSections   | Nombre de sections          |
| 0x08   | 4      | TimeDateStamp      | Date de compilation         |
| 0x14   | 2      | SizeOfOptionalHeader| Taille Optional Header     |
| 0x16   | 2      | Characteristics    | Flags (DLL, executable...)  |

### Optional header (PE32+/64-bit)

| Offset | Taille | Champ              | Description                 |
|--------|--------|--------------------|-----------------------------|
| 0x00   | 2      | Magic              | 0x10b=PE32, 0x20b=PE32+     |
| 0x10   | 8      | AddressOfEntryPoint| RVA du point d'entrée       |
| 0x18   | 8      | ImageBase          | Adresse de base préférée    |
| 0x20   | 4      | SectionAlignment   | Alignement en mémoire       |
| 0x24   | 4      | FileAlignment      | Alignement dans le fichier  |
| 0x38   | 8      | SizeOfImage        | Taille en mémoire           |
| 0x3C   | 8      | SizeOfHeaders      | Taille des headers          |
| 0x48   | 4      | Subsystem          | Console, GUI, driver...     |
| 0x58   | 4      | NumberOfRvaAndSizes| Nombre de Data Directories  |
| 0x60   | var    | DataDirectory[16]  | Export, Import, Resources...|

### Data directories

| Index | Nom                    | Description                    |
|-------|------------------------|--------------------------------|
| 0     | Export Table           | Fonctions exportées            |
| 1     | Import Table           | Fonctions importées            |
| 2     | Resource Table         | Ressources (icônes, strings)   |
| 3     | Exception Table        | Exception handlers             |
| 4     | Certificate Table      | Signatures digitales           |
| 5     | Base Relocation Table  | Relocations                    |
| 6     | Debug                  | Debug info                     |
| 9     | TLS Table              | Thread Local Storage           |
| 12    | IAT                    | Import Address Table           |
| 14    | CLR Runtime Header     | .NET metadata                  |

### Sections courantes

| Section   | Description                              |
|-----------|------------------------------------------|
| .text     | Code exécutable                          |
| .rdata    | Données en lecture seule, imports        |
| .data     | Données initialisées                     |
| .bss      | Données non-initialisées                 |
| .rsrc     | Ressources (icons, dialogs, etc.)        |
| .reloc    | Relocations                              |
| .edata    | Export table                             |
| .idata    | Import table                             |
| .tls      | Thread Local Storage                     |
| .pdata    | Exception info (x64)                     |

### Commandes utiles

```powershell
# Windows - dumpbin
dumpbin /headers file.exe
dumpbin /imports file.exe
dumpbin /exports file.dll
dumpbin /disasm file.exe

# Linux - avec wine/objdump
objdump -x file.exe
```

```bash
# Python avec pefile
python -c "import pefile; pe=pefile.PE('file.exe'); print(pe.dump_info())"
```

### Outils GUI

- **PE-bear**: Analyseur PE visuel
- **CFF Explorer**: Édition PE
- **pestudio**: Analyse malware
- **DIE (Detect It Easy)**: Détection packer/compiler

---

## Mach-O (macOS/iOS)

### Structure générale

```
+------------------+
|   Mach-O Header  |  <- Magic, CPU type, filetype
+------------------+
|  Load Commands   |  <- Segments, libraries, entry point
+------------------+
|                  |
|   Segment Data   |  <- __TEXT, __DATA, etc.
|                  |
+------------------+
|   Code Signature |  <- (optionnel)
+------------------+
```

### Fat/universal binary

```
+------------------+
|   Fat Header     |  <- 0xCAFEBABE ou 0xBEBAFECA
+------------------+
|  Fat Arch[0]     |  <- Offset vers Mach-O x86_64
|  Fat Arch[1]     |  <- Offset vers Mach-O ARM64
+------------------+
|   Mach-O x86_64  |
+------------------+
|   Mach-O ARM64   |
+------------------+
```

### Magic numbers

| Magic        | Description                          |
|--------------|--------------------------------------|
| 0xFEEDFACE   | Mach-O 32-bit (little-endian)        |
| 0xFEEDFACF   | Mach-O 64-bit (little-endian)        |
| 0xCEFAEDFE   | Mach-O 32-bit (big-endian)           |
| 0xCFFAEDFE   | Mach-O 64-bit (big-endian)           |
| 0xCAFEBABE   | Fat binary (big-endian)              |
| 0xBEBAFECA   | Fat binary (little-endian)           |

### Mach-O header (64-bit)

| Offset | Taille | Champ      | Description                    |
|--------|--------|------------|--------------------------------|
| 0x00   | 4      | magic      | 0xFEEDFACF                     |
| 0x04   | 4      | cputype    | CPU type (x86_64, ARM64)       |
| 0x08   | 4      | cpusubtype | CPU subtype                    |
| 0x0C   | 4      | filetype   | 1=object, 2=exec, 6=dylib...   |
| 0x10   | 4      | ncmds      | Number of load commands        |
| 0x14   | 4      | sizeofcmds | Size of load commands          |
| 0x18   | 4      | flags      | Flags                          |
| 0x1C   | 4      | reserved   | Reserved (64-bit only)         |

### CPU types

| Valeur     | Architecture |
|------------|--------------|
| 0x01000007 | x86_64       |
| 0x0100000C | ARM64        |
| 0x00000007 | i386         |
| 0x0000000C | ARM          |

### Load commands

| Commande          | Description                           |
|-------------------|---------------------------------------|
| LC_SEGMENT_64     | Définit un segment mémoire            |
| LC_SYMTAB         | Table des symboles                    |
| LC_DYSYMTAB       | Dynamic symbol table                  |
| LC_LOAD_DYLIB     | Charge une bibliothèque dynamique     |
| LC_LOAD_DYLINKER  | Chemin du dynamic linker              |
| LC_MAIN           | Entry point (main())                  |
| LC_UNIXTHREAD     | Entry point (legacy)                  |
| LC_CODE_SIGNATURE | Signature de code                     |
| LC_ENCRYPTION_INFO| Info de chiffrement (iOS)             |
| LC_FUNCTION_STARTS| Adresses des fonctions                |

### Segments courants

| Segment    | Description                              |
|------------|------------------------------------------|
| __PAGEZERO | Page NULL (protection crash)             |
| __TEXT     | Code et données read-only                |
| __DATA     | Données modifiables                      |
| __DATA_CONST | Données constantes après init         |
| __LINKEDIT | Métadonnées de linking                   |
| __OBJC     | Objective-C runtime data                 |

### Sections dans __TEXT

| Section       | Description                    |
|---------------|--------------------------------|
| __text        | Code exécutable                |
| __stubs       | Stubs pour fonctions externes  |
| __stub_helper | Helper pour lazy binding       |
| __cstring     | Strings C                      |
| __const       | Constantes                     |
| __unwind_info | Info pour exceptions           |

### Sections dans __DATA

| Section       | Description                    |
|---------------|--------------------------------|
| __data        | Données initialisées           |
| __bss         | Données non-initialisées       |
| __got         | Global Offset Table            |
| __la_symbol_ptr | Lazy symbol pointers         |
| __nl_symbol_ptr | Non-lazy symbol pointers     |
| __objc_*      | Objective-C metadata           |

### Commandes utiles

```bash
# Voir les headers
otool -h binary
otool -l binary       # Load commands

# Fat binary - lister architectures
lipo -info binary
file binary

# Extraire une architecture
lipo binary -thin arm64 -output binary_arm64

# Symboles
nm binary
otool -I binary       # Indirect symbols

# Désassembler
otool -tv binary      # Text section
otool -tV binary      # Avec symboles

# Libraries liées
otool -L binary

# Code signature
codesign -dv binary
```

---

## Comparaison rapide

| Aspect          | ELF              | PE                | Mach-O            |
|-----------------|------------------|-------------------|-------------------|
| Magic           | `7F ELF`         | `MZ`...`PE\0\0`   | `FEEDFACF`        |
| Segments/Sections| Séparés         | Confondus         | Segments > Sections|
| Entry point     | e_entry          | AddressOfEntryPoint| LC_MAIN          |
| Dynamic linking | .dynamic, .plt   | Import Table      | LC_LOAD_DYLIB     |
| Relocations     | .rel/.rela       | .reloc            | Dans LINKEDIT     |
| Code signing    | Non standard     | Authenticode      | LC_CODE_SIGNATURE |
| Universal binary| Non              | Non               | Fat binary        |

---

## Outils multi-format

| Outil         | ELF | PE | Mach-O | Description               |
|---------------|-----|-----|--------|---------------------------|
| Ghidra        | X   | X   | X      | Décompilation, analyse    |
| IDA Pro       | X   | X   | X      | Désassembleur commercial  |
| radare2       | X   | X   | X      | Framework RE open source  |
| Binary Ninja  | X   | X   | X      | Décompilation moderne     |
| file          | X   | X   | X      | Identification format     |
| binwalk       | X   | X   | X      | Analyse firmware          |

---

## Ressources

- [ELF Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [PE Format (Microsoft)](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Mach-O Format (Apple)](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html)
- [Corkami - Binary Posters](https://github.com/corkami/pics/tree/master/binary)
