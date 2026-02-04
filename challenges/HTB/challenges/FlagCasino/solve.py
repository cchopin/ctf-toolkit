import ctypes

# Charger la libc pour utiliser les mêmes srand/rand que le binaire
libc = ctypes.CDLL("libc.so.6")

# Valeurs attendues extraites avec GDB : x/30dw 0x555555558080
check = [
    608905406, 183990277, 286129175, 128959393,
    1795081523, 1322670498, 868603056, 677741240,
    1127757600, 89789692, 421093279, 1127757600,
    421093279, 1954323550, 255697463, 1633333913,
    1795081523, 1127757600, 255697463, 1795081523,
    1633333913, 677741240, 89789692, 988039572,
    114810857, 1322670498, 214780621, 1473834340,
    1633333913, 585743402
]

flag = ""

# Pour chaque position du flag
for i in range(30):
    valeur_attendue = check[i]

    # Essayer tous les caractères ASCII affichables
    for caractere in range(32, 127):
        libc.srand(caractere)
        resultat = libc.rand()

        if resultat == valeur_attendue:
            flag += chr(caractere)
            break

print(f"Flag : {flag}")
