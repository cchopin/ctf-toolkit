global _start                   ; point d'entrée pour le linker

  section .data
      msg_pair db "pair", 10      ; message "pair" + saut de ligne (10 = '\n')
      msg_impair db "impair", 10  ; message "impair" + saut de ligne

  section .bss
      input resb 16               ; réserve 16 octets pour l'entrée utilisateur

  section .text
  _start:
      ; --- Lecture de l'entrée ---
      call ask                    ; appelle ask, rax = nombre d'octets lus

      ; --- Trouver le dernier chiffre ---
      mov rbx, rax                ; copie le nombre d'octets dans rbx
      sub rbx, 2                  ; rbx = index du dernier chiffre
                                  ; (on recule de 2 : '\n' + 1 pour le dernier chiffre)
                                  ; ex: "34\n" → rax=3, rbx=1, input[1]='4'

      ; --- Charger et convertir le dernier chiffre ---
      mov al, [input + rbx]       ; charge le dernier chiffre dans al
      sub al, 0x30                ; convertit ASCII → valeur ('4' → 4)
      and al, 1                   ; garde le bit de poids faible
                                  ; al = 0 si pair, al = 1 si impair

      ; --- Branchement conditionnel ---
      cmp al, 0                   ; compare al avec 0
      je est_pair                 ; si al == 0, saute à est_pair

      ; --- Cas impair ---
      mov rsi, msg_impair         ; rsi = adresse de "impair\n"
      mov rdx, 7                  ; rdx = longueur (6 caractères + '\n')
      jmp afficher                ; saute à afficher

  est_pair:
      ; --- Cas pair ---
      mov rsi, msg_pair           ; rsi = adresse de "pair\n"
      mov rdx, 5                  ; rdx = longueur (4 caractères + '\n')

  afficher:
      ; --- Syscall write ---
      mov rax, 1                  ; syscall write = 1
      mov rdi, 1                  ; stdout = 1
      syscall                     ; write(stdout, rsi, rdx)

      ; --- Syscall exit ---
      mov rax, 60                 ; syscall exit = 60
      mov rdi, 0                  ; code retour = 0
      syscall                     ; exit(0)


  ask:
      ; --- Fonction : lecture clavier ---
      mov rax, 0                  ; syscall read = 0
      mov rdi, 0                  ; stdin = 0
      mov rsi, input              ; buffer = input
      mov rdx, 16                 ; max 16 octets
      syscall                     ; read(stdin, input, 16)
                                  ; rax = nombre d'octets lus
      ret                         ; retourne à _start
