# Bruteforce de répertoires et fichiers

Outils et commandes pour découvrir des fichiers et répertoires cachés sur un serveur web.

---

## Gobuster

```bash
# Scan basique
gobuster dir -u http://<cible> -w /usr/share/wordlists/dirb/common.txt

# Avec extensions
gobuster dir -u http://<cible> -w wordlist.txt -x php,html,txt,bak

# Avec cookies (authentifié)
gobuster dir -u http://<cible> -w wordlist.txt -c "session=abc123"

# Ignorer erreurs SSL
gobuster dir -u https://<cible> -w wordlist.txt -k

# Codes de statut personnalisés
gobuster dir -u http://<cible> -w wordlist.txt -s "200,204,301,302,307,401"

# Threads et timeout
gobuster dir -u http://<cible> -w wordlist.txt -t 50 --timeout 10s

# Sortie vers fichier
gobuster dir -u http://<cible> -w wordlist.txt -o results.txt
```

---

## Ffuf

```bash
# Scan basique
ffuf -u http://<cible>/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Avec extensions
ffuf -u http://<cible>/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak

# Filtrer par code de statut
ffuf -u http://<cible>/FUZZ -w wordlist.txt -mc 200,301,302

# Filtrer par taille (supprimer faux positifs)
ffuf -u http://<cible>/FUZZ -w wordlist.txt -fs 1234

# Filtrer par nombre de mots
ffuf -u http://<cible>/FUZZ -w wordlist.txt -fw 10

# Filtrer par nombre de lignes
ffuf -u http://<cible>/FUZZ -w wordlist.txt -fl 5

# Fuzzing de paramètres POST
ffuf -u http://<cible>/login -X POST -d "user=admin&pass=FUZZ" -w passwords.txt

# Fuzzing d'en-têtes
ffuf -u http://<cible> -H "Host: FUZZ.target.com" -w subdomains.txt

# Plusieurs wordlists
ffuf -u http://<cible>/FUZZ1/FUZZ2 -w dirs.txt:FUZZ1 -w files.txt:FUZZ2

# Avec cookies
ffuf -u http://<cible>/FUZZ -w wordlist.txt -b "session=abc123"

# Sortie JSON
ffuf -u http://<cible>/FUZZ -w wordlist.txt -o results.json -of json

# Récursif
ffuf -u http://<cible>/FUZZ -w wordlist.txt -recursion -recursion-depth 2
```

---

## Feroxbuster

```bash
# Scan basique (auto-récursif)
feroxbuster -u http://<cible> -w wordlist.txt

# Avec extensions
feroxbuster -u http://<cible> -w wordlist.txt -x php,html,txt

# Nombre de threads
feroxbuster -u http://<cible> -w wordlist.txt -t 100

# Limite de profondeur
feroxbuster -u http://<cible> -w wordlist.txt -d 3
```

---

## Dirb

```bash
# Scan basique
dirb http://<cible> /usr/share/wordlists/dirb/common.txt

# Avec extensions
dirb http://<cible> wordlist.txt -X .php,.html,.txt
```

---

## Dirsearch

```bash
# Scan basique
dirsearch -u http://<cible> -w wordlist.txt

# Avec extensions
dirsearch -u http://<cible> -e php,html,txt
```

---

## Wordlists recommandées

### Petites (rapide)
```
/usr/share/wordlists/dirb/common.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
```

### Moyennes
```
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### Grosses (complètes)
```
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
```

### Spécialisées
```
/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
/usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt
```
