# Énumération Linux pour escalade de privilèges

Guide d'énumération manuelle pour l'escalade de privilèges sous Linux.

---

## SUID / SGID / Capabilities

```bash
# Trouver les binaires SUID
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Trouver les binaires SGID
find / -perm -2000 -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# Trouver SUID + SGID
find / -perm -6000 -type f 2>/dev/null

# Trouver les fichiers avec capabilities
getcap -r / 2>/dev/null
/sbin/getcap -r / 2>/dev/null
```

> Toujours vérifier sur [GTFOBins](https://gtfobins.github.io/) si un binaire est exploitable

---

## Fichiers et répertoires modifiables

```bash
# Fichiers modifiables par tous
find / -writable -type f 2>/dev/null | grep -v proc
find / -perm -o+w -type f 2>/dev/null

# Répertoires modifiables par tous
find / -writable -type d 2>/dev/null
find / -perm -o+w -type d 2>/dev/null

# Fichiers appartenant à l'utilisateur courant
find / -user $(whoami) 2>/dev/null

# Fichiers root modifiables par moi
find / -user root -writable 2>/dev/null
```

---

## Tâches planifiées (Cron)

```bash
cat /etc/crontab
cat /etc/cron.d/*
cat /var/spool/cron/crontabs/*
ls -la /etc/cron.*
systemctl list-timers --all

# Scripts cron modifiables
find /etc/cron* -writable 2>/dev/null
```

---

## Mots de passe et credentials

### Fichiers de mots de passe

```bash
cat /etc/passwd
cat /etc/shadow
cat /etc/master.passwd
```

### Recherche dans les fichiers de config

```bash
grep -r "password" /etc/ 2>/dev/null
grep -r "pass" /var/www/ 2>/dev/null
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
```

### Clés SSH

```bash
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
cat ~/.ssh/id_rsa
cat /root/.ssh/id_rsa
```

### Historique

```bash
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.mysql_history
cat ~/.psql_history
```

---

## Sudo

```bash
sudo -l
sudo -V  # Vérifier version pour CVEs
cat /etc/sudoers
cat /etc/sudoers.d/*
```

---

## Utilisateurs et groupes

```bash
id
whoami
groups
cat /etc/passwd | grep -v nologin
cat /etc/group
w
who
last
```

---

## Informations système

```bash
uname -a
cat /etc/os-release
cat /etc/issue
cat /proc/version
hostname
hostnamectl
```

---

## Réseau

```bash
ip a
ifconfig
netstat -tulpn
ss -tulpn
cat /etc/hosts
cat /etc/resolv.conf
arp -a
route -n
```

---

## Processus et services

```bash
ps aux
ps aux | grep root
pstree
systemctl list-units --type=service --state=running
cat /etc/services
```

---

## Logiciels installés

```bash
dpkg -l
rpm -qa
apt list --installed
pip list
pip3 list
```

---

## Fichiers intéressants

### Configurations

```bash
cat /etc/apache2/apache2.conf
cat /etc/nginx/nginx.conf
cat /var/www/html/wp-config.php
cat /var/www/html/.env
cat /var/www/html/config.php
```

### Logs

```bash
cat /var/log/auth.log
cat /var/log/syslog
cat /var/log/apache2/access.log
```

---

## Exploits kernel

```bash
uname -r
# Puis chercher : searchsploit linux kernel <version>
```

### Versions vulnérables connues

| Version | Exploits |
|---------|----------|
| 2.6.x | Dirty COW, etc. |
| 3.x | OverlayFS, etc. |
| 4.x | Divers |
| 5.8+ | DirtyPipe |

---

## Évasion de conteneur

```bash
# Vérifier si dans un conteneur
cat /proc/1/cgroup
ls -la /.dockerenv
hostname

# Docker socket
ls -la /var/run/docker.sock
```
