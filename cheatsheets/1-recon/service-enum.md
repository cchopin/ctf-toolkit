# Énumération de services

Commandes pour énumérer les services courants par port.

---

## SMB (445)

```bash
# Lister les partages
smbclient -L //<cible> -N
smbmap -H <cible>
smbmap -H <cible> -u guest

# Connexion à un partage
smbclient //<cible>/<share> -N
smbclient //<cible>/<share> -U <username>

# Avec credentials
smbmap -H <cible> -u <user> -p <pass>
smbclient //<cible>/<share> -U '<user>%<pass>'

# Enum4linux (tout-en-un)
enum4linux -a <cible>

# CrackMapExec / NetExec
crackmapexec smb <cible>
crackmapexec smb <cible> --shares
crackmapexec smb <cible> -u <user> -p <pass> --shares
```

> Voir aussi : `cheatsheets/2-exploitation/smb-exploitation.md`

---

## FTP (21)

```bash
# Connexion anonyme
ftp <cible>
# user: anonymous
# pass: (vide ou email)

# Vérifier accès anonyme
nmap -p 21 --script=ftp-anon <cible>

# Télécharger tous les fichiers
wget -m ftp://anonymous:@<cible>
```

---

## SSH (22)

```bash
# Banner grab
nc <cible> 22
nmap -p 22 -sV <cible>

# Méthodes d'authentification
nmap -p 22 --script=ssh-auth-methods <cible>
```

---

## DNS (53)

```bash
# Zone transfer
dig axfr @<cible> domain.com
host -t axfr domain.com <cible>
dnsrecon -d domain.com -t axfr

# Reverse lookup
dnsrecon -r 192.168.1.0/24
```

---

## SMTP (25)

```bash
# Énumération d'utilisateurs
smtp-user-enum -M VRFY -U users.txt -t <cible>
nmap -p 25 --script=smtp-enum-users <cible>

# Connexion
nc <cible> 25
telnet <cible> 25
```

---

## SNMP (161)

```bash
# Bruteforce community string
onesixtyone -c community.txt <cible>

# Énumérer avec community string
snmpwalk -v2c -c public <cible>
snmpwalk -v2c -c public <cible> 1.3.6.1.2.1.1

# snmp-check
snmp-check <cible> -c public
```

---

## LDAP (389)

```bash
# Bind anonyme
ldapsearch -x -H ldap://<cible> -b "dc=domain,dc=com"

# Avec credentials
ldapsearch -x -H ldap://<cible> -D "user@domain.com" -w <password> -b "dc=domain,dc=com"

# Énumérer utilisateurs
ldapsearch -x -H ldap://<cible> -b "dc=domain,dc=com" "(objectClass=user)"
```

---

## NFS (2049)

```bash
# Afficher les montages
showmount -e <cible>

# Monter un partage
mount -t nfs <cible>:/<share> /mnt/nfs
```

---

## RPC (111)

```bash
# Énumération
rpcinfo -p <cible>
rpcclient -U "" <cible>
```

---

## MySQL (3306)

```bash
# Connexion
mysql -h <cible> -u root -p
mysql -h <cible> -u root

# Scripts Nmap
nmap -p 3306 --script=mysql-enum,mysql-info <cible>
```

---

## MSSQL (1433)

```bash
# Connexion avec Impacket
mssqlclient.py <user>:<pass>@<cible>

# Nmap
nmap -p 1433 --script=ms-sql-info <cible>
```

---

## Redis (6379)

```bash
# Connexion
redis-cli -h <cible>

# Commandes utiles
INFO
CONFIG GET *
KEYS *
```

---

## MongoDB (27017)

```bash
# Connexion
mongo <cible>:27017

# Commandes utiles
show dbs
use <dbname>
show collections
db.<collection>.find()
```

---

## WinRM (5985/5986)

```bash
# Evil-WinRM
evil-winrm -i <cible> -u <user> -p <pass>

# CrackMapExec
crackmapexec winrm <cible> -u <user> -p <pass>
```
