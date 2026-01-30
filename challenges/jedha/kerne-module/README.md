# Investigate a kernel module - Write-up Jedha

![Jedha](https://img.shields.io/badge/Jedha-SE--Linux-green)![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen)![Category](https://img.shields.io/badge/Category-Linux-blue)

## Résumé

| Info | Valeur |
|------|--------|
| **Flag** | `Jedha{Kernel_modules_treasure_hunt}` |
| **Vulnérabilité** | Module kernel non signé avec paramètre caché |
| **Techniques** | Analyse dmesg, modinfo, extraction de chaînes, paramètres de modules |
| **Outils** | dmesg, lsmod, modinfo, strings, modprobe, rmmod |

---

## Table des matières

1. [Contexte](#contexte)
2. [Objectif](#objectif)
3. [Identification du module suspect](#identification-du-module-suspect)
4. [Collecte d'informations sur le module](#collecte-dinformations-sur-le-module)
5. [Investigation du paramètre unlock_code](#investigation-du-paramètre-unlock_code)
6. [Extraction des parties du flag](#extraction-des-parties-du-flag)
7. [Solution finale](#solution-finale)
8. [Résumé des commandes utilisées](#résumé-des-commandes-utilisées)
9. [Points clés à retenir](#points-clés-à-retenir)

---

## Contexte

ZapZap Technologies fabrique des grille-pains connectés qui tweetent les statistiques de petit-déjeuner. Un ingénieur QA a remarqué des logs inattendus dans le buffer de messages du kernel pendant les tests de routine du firmware. Notre mission est d'investiguer les modules noyau et de trouver un flag caché.

---

## Objectif

Trouver et assembler les trois parties d'un flag dissimulé dans un module kernel suspect.

---

## Identification du module suspect

### Recherche d'un module non signé

Les modules kernel légitimes sont généralement signés cryptographiquement. Un bon point de départ est de chercher les modules dont la vérification de signature a échoué.

```bash
dmesg | grep sign
```

**Résultat :**
```
[    1.941386] regmod: module verification failed: signature and/or required key missing - tainting kernel
```

Le module `regmod` n'est pas signé et "taint" le kernel, ce qui est suspect.

### Vérification du module chargé

```bash
lsmod | grep regmod
```

**Résultat :**
```
regmod                 12288  0
```

Le module est bien chargé en mémoire.

---

## Collecte d'informations sur le module

### Informations détaillées avec modinfo

```bash
modinfo regmod
```

**Résultat :**
```
filename:       /lib/modules/6.11.0-21-generic/extra/regmod.ko
flag_part_one:  Jedha{Kernel
description:    Regular module ver 1.2
author:         Anne Onyme <anne@onyme.org>
license:        GPL
srcversion:     953D484FE715D20AF7551DE
depends:        bluetooth
retpoline:      Y
name:           regmod
vermagic:       6.11.0-21-generic SMP preempt mod_unload modversions
parm:           unlock_code:Special code to unlock hidden features (charp)
```

**Informations clés extraites :**
- **Auteur** : Anne Onyme (jeu de mots sur "anonyme")
- **Dépendance** : bluetooth
- **Flag part 1** : `Jedha{Kernel`
- **Paramètre** : `unlock_code` (type charp = chaîne de caractères)
- **Emplacement du binaire** : `/lib/modules/6.11.0-21-generic/extra/regmod.ko`

### Vérification du chargement au boot

```bash
cat /etc/modules-load.d/regmod.conf
```

**Résultat :**
```
regmod
```

Le module est configuré pour se charger automatiquement au démarrage via `/etc/modules-load.d/regmod.conf`.

---

## Investigation du paramètre unlock_code

### Vérifier la valeur actuelle du paramètre

```bash
cat /sys/module/regmod/parameters/unlock_code
```

**Résultat :**
```
open
```

Le module a été chargé avec `unlock_code="open"`, mais ce n'est pas le bon code.

### Recherche du code correct dans le binaire

```bash
strings /lib/modules/6.11.0-21-generic/extra/regmod.ko | grep -E "open|unlock|code"
```

**Résultat pertinent :**
```
opensesame
6regmod: Unlock code not accepted!
unlock_code
parm=unlock_code:Special code to unlock hidden features
```

Le code secret est `opensesame` (visible juste après "open" dans le binaire).

---

## Extraction des parties du flag

### Déchargement et rechargement avec le bon code

```bash
sudo rmmod regmod
sudo modprobe regmod unlock_code="opensesame"
dmesg | tail -10
```

**Résultat :**
```
regmod: Loading module...
Bluetooth: This is a normal bluetooth log.
regmod: UNLOCKED! flag_part_three: treasure_hunt}
regmod: Module loaded. Stay curious.
```

**Flag part 3** : `treasure_hunt}`

### Récupération de la partie 2 au déchargement

```bash
sudo rmmod regmod
dmesg | tail -5
```

**Résultat :**
```
regmod: Unloading module
regmod: flag_part_two: _modules_
```

**Flag part 2** : `_modules_`

---

## Solution finale

En assemblant les trois parties dans l'ordre :

| Partie | Source | Valeur |
|--------|--------|--------|
| Part 1 | `modinfo regmod` | `Jedha{Kernel` |
| Part 2 | `dmesg` au unload | `_modules_` |
| Part 3 | `dmesg` avec unlock_code correct | `treasure_hunt}` |

### Flag complet

```
Jedha{Kernel_modules_treasure_hunt}
```

---

## Résumé des commandes utilisées

| Commande | Usage |
|----------|-------|
| `dmesg \| grep sign` | Trouver les modules non signés |
| `lsmod` | Lister les modules chargés |
| `modinfo <module>` | Informations détaillées sur un module |
| `cat /sys/module/<module>/parameters/<param>` | Voir la valeur d'un paramètre |
| `strings <fichier.ko>` | Extraire les chaînes d'un binaire |
| `rmmod <module>` | Décharger un module |
| `modprobe <module> param=value` | Charger un module avec paramètres |

---

## Points clés à retenir

1. Les modules non signés génèrent un message de "taint" dans dmesg
2. Les métadonnées d'un module (auteur, paramètres, dépendances) sont accessibles via `modinfo`
3. Les paramètres des modules chargés sont exposés dans `/sys/module/<nom>/parameters/`
4. La commande `strings` permet d'extraire les chaînes lisibles d'un binaire
5. Certains modules peuvent afficher des informations différentes au chargement et au déchargement
6. Le dossier `/etc/modules-load.d/` contrôle les modules chargés au boot

---
