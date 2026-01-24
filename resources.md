# Ressources CTF

Liens utiles pour les CTF et le pentesting.

---

## Aide-mémoires et références

### GTFOBins
**https://gtfobins.github.io/**
Liste de binaires Unix exploitables pour bypass de restrictions, escalade de privilèges, transfert de fichiers, reverse shells. Indispensable pour la privesc Linux.

### LOLBAS (Living Off The Land Binaries)
**https://lolbas-project.github.io/**
Équivalent Windows de GTFOBins. Binaires Microsoft signés exploitables pour exécution de code, téléchargement, persistence.

### HackTricks
**https://book.hacktricks.wiki/**
Wiki massif couvrant toutes les techniques : web, privesc Linux/Windows, AD, cloud, forensics, crypto. LA référence.

### PayloadsAllTheThings
**https://github.com/swisskyrepo/PayloadsAllTheThings**
Collection de payloads et bypass pour chaque vulnérabilité (XSS, SQLi, SSTI, XXE...). Déjà inclus dans ce toolkit.

### HackTricks Cloud
**https://cloud.hacktricks.wiki/**
Exploitation des environnements cloud : AWS, GCP, Azure, Kubernetes.

### PentestMonkey
**https://pentestmonkey.net/cheat-sheet/**
Cheatsheets classiques : reverse shells, SQL injection, etc.

---

## Élévation de privilèges

### Élévation de privilèges Linux
**https://github.com/carlospolop/PEASS-ng**
LinPEAS/WinPEAS - Scripts d'énumération automatique. Déjà inclus dans ce toolkit.

**https://github.com/rebootuser/LinEnum**
Script bash d'énumération Linux classique.

**https://github.com/diego-treitos/linux-smart-enumeration**
Alternative à LinPEAS, plus léger.

**https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/**
Article de référence sur la privesc Linux.

### Élévation de privilèges Windows
**https://github.com/itm4n/PrivescCheck**
Script PowerShell d'énumération Windows.

**https://github.com/AonCyberLabs/Windows-Exploit-Suggester**
Suggère des exploits kernel basés sur systeminfo.

**https://www.fuzzysecurity.com/tutorials/16.html**
Guide complet privesc Windows.

**https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md**
Checklist privesc Windows.

---

## Exploitation web

### PortSwigger Web Security Academy
**https://portswigger.net/web-security**
Cours gratuits et labs sur toutes les vulnérabilités web. Excellent pour apprendre.

### OWASP Testing Guide
**https://owasp.org/www-project-web-security-testing-guide/**
Méthodologie complète de test d'applications web.

### CyberChef
**https://gchq.github.io/CyberChef/**
Outil en ligne pour encoder/décoder, analyser des données. Indispensable.

### Crackstation
**https://crackstation.net/**
Lookup de hashes (MD5, SHA1, etc.) dans une base massive.

### JWT.io
**https://jwt.io/**
Décodeur et debugger de JSON Web Tokens.

---

## Rétro-ingénierie et exploitation de binaires

### Ghidra
**https://ghidra-sre.org/**
Désassembleur/décompileur gratuit de la NSA. Alternative à IDA Pro.

### pwntools Documentation
**https://docs.pwntools.com/**
Framework Python pour l'exploitation de binaires.

### ROPgadget
**https://github.com/JonathanSalwan/ROPgadget**
Recherche de gadgets ROP dans les binaires.

### Shell-storm Shellcode Database
**https://shell-storm.org/shellcode/**
Base de données de shellcodes pour différentes architectures.

### Exploit Database
**https://www.exploit-db.com/**
Base de données d'exploits publics. Searchsploit en local.

---

## Cryptographie

### dCode
**https://www.dcode.fr/**
Décodeurs pour tous types de ciphers (César, Vigenère, etc.).

### FactorDB
**http://factordb.com/**
Base de données de factorisations RSA.

### RsaCtfTool
**https://github.com/RsaCtfTool/RsaCtfTool**
Outil automatique pour attaquer RSA faible.

### Boxentriq
**https://www.boxentriq.com/code-breaking**
Outils de cryptanalyse en ligne.

---

## Forensique et stéganographie

### Autopsy
**https://www.autopsy.com/**
Plateforme de forensics open source.

### Volatility
**https://github.com/volatilityfoundation/volatility3**
Analyse de dumps mémoire.

### Steghide
**https://github.com/StefanoDeVuworker/steghide**
Extraction de données cachées dans images/audio.

### Aperi'Solve
**https://www.aperisolve.com/**
Analyse stéganographique en ligne (combine plusieurs outils).

### Forensically
**https://29a.ch/photo-forensics/**
Analyse forensique d'images en ligne.

---

## OSINT

### OSINT Framework
**https://osintframework.com/**
Collection d'outils OSINT classés par catégorie.

### Shodan
**https://www.shodan.io/**
Moteur de recherche d'appareils connectés.

### Censys
**https://search.censys.io/**
Alternative à Shodan.

### crt.sh
**https://crt.sh/**
Recherche de certificats SSL (subdomain enumeration).

### Wayback Machine
**https://web.archive.org/**
Archives de pages web.

---

## Active Directory

### Aide-mémoire attaque/défense AD
**https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet**
Cheatsheet complète pour l'exploitation AD.

### The Hacker Recipes
**https://www.thehacker.recipes/**
Wiki sur l'exploitation AD et environnements Windows.

### Bloodhound
**https://github.com/BloodHoundAD/BloodHound**
Analyse graphique des relations AD pour trouver des chemins d'attaque.

### Impacket
**https://github.com/fortra/impacket**
Collection de scripts Python pour protocoles Windows.

### Rubeus
**https://github.com/GhostPack/Rubeus**
Outil C# pour manipuler Kerberos.

---

## Outils essentiels

### Burp Suite
**https://portswigger.net/burp**
Proxy d'interception HTTP. Indispensable pour le web.

### Nmap
**https://nmap.org/**
Scanner de ports et services.

### Gobuster / Feroxbuster
**https://github.com/OJ/gobuster**
**https://github.com/epi052/feroxbuster**
Brute-force de répertoires et sous-domaines.

### SQLMap
**https://sqlmap.org/**
Exploitation automatique de SQL injection.

### Hashcat
**https://hashcat.net/hashcat/**
Cracking de mots de passe GPU.

### John the Ripper
**https://www.openwall.com/john/**
Cracking de mots de passe CPU.

### Metasploit
**https://www.metasploit.com/**
Framework d'exploitation.

### Responder
**https://github.com/lgandx/Responder**
Poisoning LLMNR/NBT-NS/MDNS.

---

## Plateformes CTF (pour s'entraîner)

### HackTheBox
**https://www.hackthebox.com/**
Machines virtuelles à exploiter. Très populaire.

### TryHackMe
**https://tryhackme.com/**
Parcours guidés, bon pour débuter.

### PicoCTF
**https://picoctf.org/**
CTF orienté débutants/étudiants.

### Root-Me
**https://www.root-me.org/**
Challenges variés, communauté francophone.

### OverTheWire
**https://overthewire.org/wargames/**
Wargames pour apprendre Linux et les bases.

### VulnHub
**https://www.vulnhub.com/**
VMs vulnérables à télécharger.

### CTFtime
**https://ctftime.org/**
Calendrier des CTF et classements.

---

## Listes de mots

### SecLists
**https://github.com/danielmiessler/SecLists**
Collection massive de wordlists. Déjà inclus dans ce toolkit.

### Rockyou
Wordlist classique de 14M de mots de passe. Déjà inclus dans ce toolkit.

### FuzzDB
**https://github.com/fuzzdb-project/fuzzdb**
Payloads et patterns pour fuzzing.

### Assetnote Wordlists
**https://wordlists.assetnote.io/**
Wordlists modernes générées à partir de données réelles.

---

## Générateurs de reverse shells

### RevShells
**https://www.revshells.com/**
Générateur de reverse shells interactif. Supporte tous les langages.

### Reverse Shell Generator (PayloadsAllTheThings)
**https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md**
Cheatsheet complète des reverse shells.

---
