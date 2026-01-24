# Scans Nmap

Guide complet des commandes Nmap pour la reconnaissance.

---

## Scans rapides

```bash
# Scan rapide (top 100 ports)
nmap -F <cible>

# Top 1000 ports (défaut)
nmap <cible>

# Détection de version rapide
nmap -sV <cible>
```

---

## Scans complets

```bash
# Tous les ports
nmap -p- <cible>

# Tous les ports + version + scripts
nmap -p- -sV -sC <cible>

# Scan complet exhaustif
nmap -p- -sV -sC -A <cible>

# Scan UDP (lent mais important)
nmap -sU --top-ports 100 <cible>
```

---

## Scans furtifs

```bash
# SYN scan (défaut, nécessite root)
nmap -sS <cible>

# Connect scan (pas besoin de root)
nmap -sT <cible>

# Null scan
nmap -sN <cible>

# FIN scan
nmap -sF <cible>

# Xmas scan
nmap -sX <cible>
```

---

## Timing

| Option | Description |
|--------|-------------|
| `-T0` | Paranoïaque (très lent) |
| `-T1` | Furtif |
| `-T2` | Poli |
| `-T3` | Normal (défaut) |
| `-T4` | Agressif |
| `-T5` | Insane (très rapide) |

```bash
nmap -T4 <cible>

# Timing personnalisé
nmap --min-rate 1000 <cible>
```

---

## Version et scripts

```bash
# Détection de version
nmap -sV <cible>

# Scripts par défaut
nmap -sC <cible>

# Script spécifique
nmap --script=http-enum <cible>
nmap --script=smb-vuln* <cible>
nmap --script=vuln <cible>
```

**Catégories de scripts** : auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln

---

## Sortie

```bash
# Sortie normale
nmap -oN scan.txt <cible>

# Sortie XML
nmap -oX scan.xml <cible>

# Sortie grepable
nmap -oG scan.gnmap <cible>

# Tous les formats
nmap -oA scan <cible>
```

---

## Scans CTF courants

```bash
# Scan initial rapide
nmap -sC -sV -oN initial.txt <cible>

# Scan tous les ports
nmap -p- --min-rate 1000 -oN allports.txt <cible>

# Scan détaillé sur ports trouvés
nmap -p 22,80,443 -sV -sC -A -oN detailed.txt <cible>

# Scan de vulnérabilités
nmap --script=vuln -oN vuln.txt <cible>
```

---

## Services spécifiques

```bash
# SMB
nmap -p 445 --script=smb-enum-shares,smb-enum-users,smb-vuln* <cible>

# HTTP
nmap -p 80,443 --script=http-enum,http-vuln*,http-methods <cible>

# FTP
nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-vuln* <cible>

# SSH
nmap -p 22 --script=ssh-auth-methods,ssh-hostkey <cible>

# DNS
nmap -p 53 --script=dns-zone-transfer <cible>

# SMTP
nmap -p 25 --script=smtp-enum-users,smtp-vuln* <cible>

# MySQL
nmap -p 3306 --script=mysql-enum,mysql-vuln* <cible>
```

---

## Découverte réseau

```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# Scan ARP (réseau local)
nmap -PR 192.168.1.0/24

# List scan (résolution DNS uniquement)
nmap -sL 192.168.1.0/24
```

---

## Évasion

```bash
# Fragmentation des paquets
nmap -f <cible>

# Decoys
nmap -D RND:10 <cible>

# Spoof source IP
nmap -S <ip_spoofée> <cible>

# Port source personnalisé
nmap --source-port 53 <cible>
```
