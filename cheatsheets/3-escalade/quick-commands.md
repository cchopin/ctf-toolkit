# Commandes rapides pour privesc Linux

One-liners essentiels pour l'escalade de privilèges.

---

## SUID

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

---

## SGID

```bash
find / -perm -2000 -type f 2>/dev/null
```

---

## Capabilities

```bash
getcap -r / 2>/dev/null
```

---

## Fichiers modifiables

```bash
find / -writable -type f 2>/dev/null | grep -v proc
```

---

## /etc modifiable

```bash
find /etc -writable 2>/dev/null
```

---

## Cron

```bash
cat /etc/crontab
ls -la /etc/cron*
```

---

## Sudo

```bash
sudo -l
```

---

## SUID + vérification GTFOBins

```bash
find / -perm -4000 2>/dev/null | xargs -I{} basename {} | sort -u
```

> Vérifier chaque binaire sur [GTFOBins](https://gtfobins.github.io/)

---

## Mots de passe dans les fichiers

```bash
grep -r "password" /etc/ 2>/dev/null
grep -r "pass" /var/www/ 2>/dev/null
```

---

## Clés SSH

```bash
find / -name "id_rsa" 2>/dev/null
cat /home/*/.ssh/id_rsa 2>/dev/null
```

---

## Historique

```bash
cat ~/.bash_history
cat /home/*/.bash_history 2>/dev/null
```

---

## Version kernel (exploits)

```bash
uname -a
```

---

## Info OS

```bash
cat /etc/os-release
```

---

## Utilisateurs avec shell

```bash
cat /etc/passwd | grep -E "/bin/(ba)?sh"
```

---

## Ports en écoute

```bash
ss -tulpn
netstat -tulpn
```

---

## Processus root

```bash
ps aux | grep root
```

---

## Docker socket

```bash
ls -la /var/run/docker.sock
```

---

## Dans un conteneur ?

```bash
cat /proc/1/cgroup | grep docker
```

---

## NFS (no_root_squash)

```bash
cat /etc/exports
showmount -e localhost
```

---

## Répertoires PATH modifiables

```bash
echo $PATH | tr ':' '\n' | xargs -I{} find {} -writable 2>/dev/null
```
