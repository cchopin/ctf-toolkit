# Restrict Permissions with SELinux - Write-up Jedha

![Jedha](https://img.shields.io/badge/Jedha-SE--Linux-green)![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)![Category](https://img.shields.io/badge/Category-Linux-blue)

## Résumé

| Info | Valeur |
|------|--------|
| **Objectif** | Restreindre l'exécution dans /tmp pour un utilisateur confiné |
| **Techniques** | SELinux user mapping, labels de fichiers, booleans SELinux |
| **Outils** | semanage, chcon, restorecon, ausearch, setsebool |

---

## Table des matières

1. [Contexte](#contexte)
2. [Étape 1 : Solution temporaire](#étape-1--solution-temporaire)
3. [Étape 2 : Solution permanente](#étape-2--solution-permanente)
4. [Résumé des commandes](#résumé-des-commandes)
5. [Points clés à retenir](#points-clés-à-retenir)

---

## Contexte

Un nouveau compte utilisateur doit être provisionné pour un contractant temporaire nommé `lbaker`. Cet utilisateur a besoin d'un accès shell basique pour exécuter des diagnostics et lire des logs, mais ne doit **pas pouvoir exécuter de scripts ou binaires depuis /tmp**.

Pour appliquer cette restriction, nous utilisons SELinux pour assigner un rôle confiné à l'utilisateur.

**Connexion au lab :**
- Username : `jedha`
- Password : `jedha`

---

## Étape 1 : Solution temporaire

### 1.1 Créer l'utilisateur lbaker

```bash
sudo useradd lbaker
sudo passwd lbaker
```

### 1.2 Assigner le rôle SELinux confiné staff_u

```bash
sudo semanage login -a -s staff_u lbaker
```

**Vérification :**
```bash
sudo semanage login -l | grep lbaker
```

**Résultat attendu :**
```
lbaker               staff_u              s0-s0:c0.c1023       *
```

### 1.3 Tester l'exécution dans /tmp (avant restriction)

**Se connecter en tant que lbaker via l'interface graphique** (important : ne pas utiliser `su -`).

Copier un binaire dans /tmp et tester :

```bash
cp /usr/bin/ls /tmp/ls_test
/tmp/ls_test
```

**Résultat :** La commande s'exécute normalement.

### 1.4 Appliquer un label temporaire tmp_t sur /tmp

Depuis le compte `jedha` :

```bash
sudo chcon -R -t tmp_t /tmp/*
```

**Vérification du label :**
```bash
ls -Z /tmp/
```

**Résultat attendu :**
```
unconfined_u:object_r:tmp_t:s0 ls_test
```

### 1.5 Vérifier que lbaker ne peut plus exécuter depuis /tmp

Se reconnecter en tant que `lbaker` via l'interface graphique :

```bash
/tmp/ls_test
```

**Résultat attendu :**
```
-bash: /tmp/ls_test: Permission denied
```

L'exécution est maintenant bloquée par SELinux.

### 1.6 Trouver l'alerte SELinux

Depuis le compte `jedha`, rechercher les alertes AVC (Access Vector Cache) :

```bash
sudo ausearch -m avc -ts recent
```

Ou pour une recherche plus ciblée :

```bash
sudo ausearch -m avc | grep ls_test
```

**Résultat attendu :**
```
type=AVC msg=audit(...): avc:  denied  { execute } for  pid=... comm="bash" name="ls_test" dev="..." ino=... scontext=staff_u:staff_r:staff_t:s0-s0:c0.c1023 tcontext=unconfined_u:object_r:tmp_t:s0 tclass=file permissive=0
```

L'alerte montre :
- **denied { execute }** : l'exécution a été refusée
- **scontext** : contexte source (staff_u:staff_r:staff_t)
- **tcontext** : contexte cible (tmp_t)

---

## Étape 2 : Solution permanente

### 2.1 Créer une règle permanente avec semanage

```bash
sudo semanage fcontext -a -t tmp_t "/tmp(/.*)?"
```

### 2.2 Appliquer la règle aux fichiers existants

```bash
sudo restorecon -Rv /tmp
```

### 2.3 Tester avec un nouveau binaire

```bash
cp /usr/bin/whoami /tmp/whoami_test
ls -Z /tmp/whoami_test
```

**Observation :** Le nouveau binaire n'est pas labellisé avec `tmp_t` malgré notre règle. C'est parce que SELinux a des règles par défaut pour `/tmp` qui sont appliquées avant nos règles personnalisées.

### 2.4 Utiliser le boolean SELinux (solution recommandée)

Au lieu de modifier les labels, utiliser le boolean approprié pour empêcher `staff_u` d'exécuter des fichiers depuis /tmp :

```bash
sudo setsebool -P staff_exec_content off
```

**Explication :**
- `setsebool` : modifie un boolean SELinux
- `-P` : rend le changement permanent (Persistent)
- `staff_exec_content off` : désactive l'exécution de contenu pour staff_u

**Vérification :**
```bash
getsebool staff_exec_content
```

**Résultat attendu :**
```
staff_exec_content --> off
```

### 2.5 Tester la restriction

Se connecter en tant que `lbaker` et tester :

```bash
/tmp/whoami_test
```

**Résultat attendu :**
```
-bash: /tmp/whoami_test: Permission denied
```

---

## Résumé des commandes

| Commande | Usage |
|----------|-------|
| `semanage login -a -s staff_u <user>` | Associer un utilisateur Linux à un utilisateur SELinux |
| `semanage login -l` | Lister les mappings utilisateur SELinux |
| `chcon -t <type> <fichier>` | Changer le label SELinux temporairement |
| `semanage fcontext -a -t <type> "<path>"` | Créer une règle de labeling permanente |
| `restorecon -Rv <path>` | Appliquer les règles de labeling aux fichiers |
| `ausearch -m avc` | Rechercher les alertes SELinux (Access Vector Cache) |
| `setsebool -P <boolean> on/off` | Modifier un boolean SELinux de façon permanente |
| `getsebool <boolean>` | Afficher la valeur d'un boolean SELinux |
| `ls -Z` | Afficher les labels SELinux des fichiers |

---

## Points clés à retenir

1. **SELinux User Mapping** : Les utilisateurs Linux peuvent être associés à des utilisateurs SELinux confinés (staff_u, user_u, etc.) via `semanage login`

2. **Labels temporaires vs permanents** :
   - `chcon` : changement temporaire (perdu après `restorecon` ou relabeling)
   - `semanage fcontext` + `restorecon` : changement permanent

3. **Priorité des règles** : Les règles SELinux par défaut pour /tmp sont appliquées avant les règles personnalisées

4. **Booleans SELinux** : Les booleans permettent d'activer/désactiver des fonctionnalités sans modifier la politique
   - `staff_exec_content` : contrôle l'exécution de contenu par staff_u

5. **Audit SELinux** : Les refus SELinux sont loggués et consultables via `ausearch -m avc`

6. **Connexion utilisateur** : Pour que le contexte SELinux soit correctement appliqué, il faut se connecter via l'interface graphique ou SSH, pas via `su -`

---

## Concepts SELinux

### Types d'utilisateurs SELinux

| Utilisateur SELinux | Description |
|---------------------|-------------|
| `unconfined_u` | Utilisateur non confiné (comportement standard) |
| `staff_u` | Utilisateur staff avec restrictions |
| `user_u` | Utilisateur standard très restreint |
| `sysadm_u` | Administrateur système |

### Structure d'un contexte SELinux

```
user:role:type:level
staff_u:staff_r:staff_t:s0
```

- **user** : utilisateur SELinux (staff_u)
- **role** : rôle SELinux (staff_r)
- **type** : type/domaine (staff_t)
- **level** : niveau MLS/MCS (s0)

---
