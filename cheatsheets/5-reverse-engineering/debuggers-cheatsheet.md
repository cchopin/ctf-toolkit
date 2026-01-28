# Debuggers Cheatsheet (GDB, LLDB, radare2)

## GDB (GNU Debugger)

### Lancement

```bash
gdb program                  # Charger un programme
gdb -p PID                   # Attacher à un processus
gdb program core             # Analyser un core dump
gdb -q program               # Mode silencieux
gdb --args program arg1 arg2 # Avec arguments
```

### Commandes de Base

| Commande            | Raccourci | Description                        |
|---------------------|-----------|-------------------------------------|
| run [args]          | r         | Lancer le programme                 |
| start               |           | Run et s'arrêter à main()           |
| continue            | c         | Continuer l'exécution               |
| next                | n         | Step over (pas dans les fonctions)  |
| step                | s         | Step into (entre dans les fonctions)|
| nexti               | ni        | Next instruction (asm)              |
| stepi               | si        | Step instruction (asm)              |
| finish              | fin       | Exécuter jusqu'à fin de fonction    |
| until [location]    | u         | Continuer jusqu'à location          |
| quit                | q         | Quitter GDB                         |

### Breakpoints

| Commande                    | Description                        |
|-----------------------------|------------------------------------|
| break main                  | Breakpoint sur fonction main       |
| break *0x401234             | Breakpoint sur adresse             |
| break file.c:42             | Breakpoint ligne 42 de file.c      |
| break func if x > 10        | Breakpoint conditionnel            |
| tbreak                      | Temporary breakpoint (une fois)    |
| watch var                   | Watchpoint sur variable            |
| watch *0x601020             | Watchpoint sur adresse             |
| rwatch var                  | Read watchpoint                    |
| catch syscall write         | Break sur syscall                  |
| info breakpoints            | Lister breakpoints                 |
| delete [num]                | Supprimer breakpoint               |
| disable/enable [num]        | Désactiver/activer breakpoint      |

### Affichage

| Commande                    | Description                        |
|-----------------------------|------------------------------------|
| print var                   | Afficher variable                  |
| print $rax                  | Afficher registre                  |
| print/x var                 | Format hex                         |
| print/d var                 | Format décimal                     |
| print/t var                 | Format binaire                     |
| print/c var                 | Format caractère                   |
| print/s ptr                 | Format string                      |
| print *array@10             | Afficher 10 éléments du tableau    |
| x/10x $rsp                  | Examiner 10 words hex depuis rsp   |
| x/20i $rip                  | Examiner 20 instructions           |
| x/s 0x401234                | Examiner string                    |
| x/10gx $rsp                 | 10 giant words (64-bit) hex        |
| display var                 | Afficher var à chaque step         |
| info registers              | Tous les registres                 |
| info registers rax rbx      | Registres spécifiques              |

**Formats x (examine):**
- Taille: b(byte), h(halfword), w(word), g(giant/8 bytes)
- Format: x(hex), d(decimal), u(unsigned), o(octal), t(binary), s(string), i(instruction)

### Stack et Frames

| Commande            | Description                        |
|---------------------|------------------------------------|
| backtrace           | Afficher call stack                |
| bt full             | Backtrace avec variables locales   |
| frame [num]         | Sélectionner stack frame           |
| info frame          | Info sur frame courante            |
| info locals         | Variables locales                  |
| info args           | Arguments de la fonction           |
| up/down             | Naviguer dans les frames           |

### Mémoire et Mappings

| Commande                    | Description                        |
|-----------------------------|------------------------------------|
| info proc mappings          | Memory mappings                    |
| find start, end, pattern    | Chercher en mémoire                |
| set {int}0x601020 = 42      | Modifier mémoire                   |
| dump memory file start end  | Dumper mémoire vers fichier        |

### Désassemblage

| Commande                    | Description                        |
|-----------------------------|------------------------------------|
| disassemble                 | Désassembler fonction courante     |
| disas main                  | Désassembler main                  |
| disas 0x401000, 0x401050    | Désassembler range                 |
| set disassembly-flavor intel| Syntaxe Intel                      |
| layout asm                  | Vue assembleur TUI                 |
| layout regs                 | Vue registres TUI                  |
| layout src                  | Vue source TUI                     |

### GDB + pwndbg/GEF/peda

```bash
# Installation pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# Commandes pwndbg
vmmap                        # Memory mappings
telescope $rsp 20            # Stack avec pointeurs
search -s "flag"             # Chercher string
checksec                     # Security features
rop                          # Gadgets ROP
heap                         # Analyse heap
bins                         # Heap bins
```

### .gdbinit

```bash
# ~/.gdbinit
set disassembly-flavor intel
set pagination off
set follow-fork-mode child
set print pretty on

# Alias utiles
define hook-stop
    x/1i $pc
end
```

---

## LLDB (LLVM Debugger)

### Lancement

```bash
lldb program                 # Charger programme
lldb -p PID                  # Attacher à processus
lldb -- program arg1 arg2    # Avec arguments
```

### Équivalences GDB -> LLDB

| GDB                | LLDB                              |
|--------------------|-----------------------------------|
| run                | process launch / run              |
| continue           | process continue / c              |
| next               | thread step-over / n              |
| step               | thread step-in / s                |
| nexti              | thread step-inst-over / ni        |
| stepi              | thread step-inst / si             |
| finish             | thread step-out / finish          |
| break main         | breakpoint set -n main / b main   |
| break *0x401234    | breakpoint set -a 0x401234        |
| break file.c:42    | breakpoint set -f file.c -l 42    |
| info breakpoints   | breakpoint list                   |
| delete 1           | breakpoint delete 1               |
| watch var          | watchpoint set variable var       |
| print var          | expression var / p var            |
| print/x var        | expression -f x -- var            |
| x/10x $rsp         | memory read -c 10 -f x $rsp       |
| x/s 0x401234       | memory read -f s 0x401234         |
| info registers     | register read                     |
| set $rax = 0       | register write rax 0              |
| backtrace          | thread backtrace / bt             |
| frame 2            | frame select 2                    |
| disassemble        | disassemble -f                    |
| info proc mappings | image list                        |

### Commandes Spécifiques LLDB

| Commande                          | Description                  |
|-----------------------------------|------------------------------|
| settings set target.x86-disassembly-flavor intel | Syntaxe Intel |
| image lookup -a 0x401234          | Info sur adresse             |
| image lookup -n func              | Trouver fonction             |
| image dump symtab                 | Table des symboles           |
| memory find -s "pattern" start end| Chercher en mémoire          |
| script                            | Shell Python                 |
| gui                               | Interface TUI                |

### ~/.lldbinit

```
settings set target.x86-disassembly-flavor intel
settings set stop-disassembly-display always
command alias bpl breakpoint list
command alias bpd breakpoint disable
```

---

## radare2

### Lancement

```bash
r2 binary                    # Ouvrir en lecture
r2 -w binary                 # Mode écriture
r2 -d binary                 # Mode debug
r2 -d -A binary              # Debug + analyse auto
r2 -AA binary                # Analyse approfondie
```

### Navigation

| Commande    | Description                              |
|-------------|------------------------------------------|
| s addr      | Seek to address                          |
| s main      | Seek to main                             |
| s+10        | Seek forward 10 bytes                    |
| s-10        | Seek backward 10 bytes                   |
| ?           | Aide générale                            |
| ?*          | Aide complète                            |
| cmd?        | Aide sur commande                        |

### Analyse

| Commande    | Description                              |
|-------------|------------------------------------------|
| aa          | Analyze all (fonctions, références)      |
| aaa         | Analyse plus approfondie                 |
| aaaa        | Analyse expérimentale                    |
| afl         | List functions                           |
| afl~main    | Filtrer avec grep                        |
| afn name    | Renommer fonction                        |
| axt addr    | Cross-references to addr                 |
| axf addr    | Cross-references from addr               |
| afi         | Function info                            |
| pdf         | Print disassembly function               |
| pdf @ main  | Disassemble main                         |

### Affichage

| Commande    | Description                              |
|-------------|------------------------------------------|
| pd 20       | Disassemble 20 instructions              |
| pD 100      | Disassemble 100 bytes                    |
| px 64       | Hexdump 64 bytes                         |
| pxw 32      | Hexdump 32 bytes as words                |
| ps @ addr   | Print string at addr                     |
| psz @ addr  | Print zero-terminated string             |
| pf          | Print formatted                          |
| pr          | Print raw                                |
| V           | Visual mode                              |
| VV          | Visual graph mode                        |

### Debug Mode (r2 -d)

| Commande    | Description                              |
|-------------|------------------------------------------|
| dc          | Continue                                 |
| ds          | Step                                     |
| dso         | Step over                                |
| dsu addr    | Step until address                       |
| db addr     | Set breakpoint                           |
| db- addr    | Remove breakpoint                        |
| dbi         | List breakpoints                         |
| dr          | Show registers                           |
| dr rax      | Show rax                                 |
| dr rax=42   | Set rax to 42                            |
| drr         | Registers + references                   |
| dbt         | Backtrace                                |
| dm          | Memory maps                              |
| dmi libc    | List symbols in libc                     |
| dp          | List processes/threads                   |
| dk 9        | Send signal 9                            |
| doo args    | Reopen with args                         |
| dcu main    | Continue until main                      |

### Recherche

| Commande    | Description                              |
|-------------|------------------------------------------|
| / string    | Search string                            |
| /x 9090     | Search hex bytes                         |
| /R pop rdi  | Search ROP gadget                        |
| /R/         | List all ROP gadgets                     |
| /a jmp eax  | Search assembly pattern                  |
| /c call     | Search call instructions                 |
| iz          | List strings in data section             |
| izz         | List all strings                         |

### Informations

| Commande    | Description                              |
|-------------|------------------------------------------|
| i           | File info                                |
| ie          | Entry point                              |
| iS          | Sections                                 |
| iS~.text    | Section .text                            |
| is          | Symbols                                  |
| ii          | Imports                                  |
| iE          | Exports                                  |
| il          | Libraries                                |
| ic          | Classes (C++, ObjC)                      |
| ir          | Relocations                              |

### Visual Mode

```
V     - Entrer en visual mode
p/P   - Cycle display modes (hex, disasm, debug, etc.)
c     - Cursor mode (pour édition)
;     - Ajouter commentaire
d     - Define (function, data, etc.)
q     - Quitter visual mode
:cmd  - Exécuter commande r2
?     - Aide visual mode
```

### Visual Graph Mode (VV)

```
VV    - Entrer en graph mode
hjkl  - Navigation
+/-   - Zoom
p     - Cycle modes
g     - Goto node
tab   - Switch between call graph and block graph
q     - Quitter
```

### Scripting (r2pipe)

```python
#!/usr/bin/env python3
import r2pipe

r2 = r2pipe.open("./binary")
r2.cmd("aaa")

# Get functions
funcs = r2.cmdj("aflj")  # JSON output
for f in funcs:
    print(f"{f['name']} @ {hex(f['offset'])}")

# Disassemble main
print(r2.cmd("pdf @ main"))
```

### Configuration (~/.radare2rc)

```
e asm.syntax = intel
e scr.utf8 = true
e asm.bytes = false
e cfg.fortunes = false
```

---

## Comparaison Rapide

| Action              | GDB                  | LLDB                  | radare2          |
|---------------------|----------------------|-----------------------|------------------|
| Run                 | run                  | run                   | dc               |
| Continue            | continue             | continue              | dc               |
| Step                | step                 | step                  | ds               |
| Step over           | next                 | next                  | dso              |
| Step inst           | stepi                | si                    | ds               |
| Breakpoint          | break *0x...         | b -a 0x...            | db 0x...         |
| Registers           | info reg             | register read         | dr               |
| Stack               | x/20x $rsp           | me r -c 20 $rsp       | pxq @ rsp        |
| Disassemble         | disas                | dis                   | pd               |
| Memory map          | info proc map        | image list            | dm               |
| Backtrace           | bt                   | bt                    | dbt              |
| Search              | find                 | memory find           | /                |

---

## Ressources

- [GDB Documentation](https://sourceware.org/gdb/documentation/)
- [pwndbg](https://github.com/pwndbg/pwndbg)
- [GEF](https://github.com/hugsy/gef)
- [LLDB Tutorial](https://lldb.llvm.org/use/tutorial.html)
- [radare2 Book](https://book.rada.re/)
- [radare2 Cheatsheet](https://r2wiki.readthedocs.io/en/latest/home/misc/cheatsheet/)
