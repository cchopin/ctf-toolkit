# Énumération de sous-domaines

Outils et techniques pour découvrir des sous-domaines.

---

## Ffuf (vhost / sous-domaines)

```bash
# Énumération de virtual hosts
ffuf -u http://<cible> -H "Host: FUZZ.target.com" -w subdomains.txt

# Filtrer par taille (enlever faux positifs)
ffuf -u http://<cible> -H "Host: FUZZ.target.com" -w subdomains.txt -fs 1234

# HTTPS
ffuf -u https://<cible> -H "Host: FUZZ.target.com" -w subdomains.txt -fs 1234
```

---

## Gobuster

```bash
# Bruteforce DNS
gobuster dns -d target.com -w subdomains.txt

# Avec résolveur personnalisé
gobuster dns -d target.com -w subdomains.txt -r 8.8.8.8

# VHOST
gobuster vhost -u http://target.com -w subdomains.txt
```

---

## Sublist3r

```bash
# Énumération basique (passive)
sublist3r -d target.com

# Avec bruteforce
sublist3r -d target.com -b

# Fichier de sortie
sublist3r -d target.com -o subdomains.txt
```

---

## Amass

```bash
# Énumération passive
amass enum -passive -d target.com

# Énumération active
amass enum -active -d target.com

# Bruteforce
amass enum -brute -d target.com -w subdomains.txt

# Sortie
amass enum -d target.com -o results.txt
```

---

## Subfinder

```bash
# Basique
subfinder -d target.com

# Mode silencieux (résultats uniquement)
subfinder -d target.com -silent

# Sortie
subfinder -d target.com -o subdomains.txt
```

---

## Assetfinder

```bash
assetfinder target.com
assetfinder --subs-only target.com
```

---

## DNSRecon

```bash
# Énumération standard
dnsrecon -d target.com

# Bruteforce
dnsrecon -d target.com -D subdomains.txt -t brt

# Zone transfer
dnsrecon -d target.com -t axfr
```

---

## Dig / Host

```bash
# Tentative de zone transfer
dig axfr @ns1.target.com target.com
host -t axfr target.com ns1.target.com

# Tous les enregistrements
dig any target.com
```

---

## Outils en ligne

### crt.sh (Certificate Transparency)

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

> Autres : VirusTotal, Shodan, Censys (nécessitent des clés API)

---

## Wordlists

```
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Discovery/DNS/namelist.txt
/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
```

---

## One-liner combo

```bash
# Passif + actif combiné
(subfinder -d target.com -silent; amass enum -passive -d target.com; assetfinder --subs-only target.com) | sort -u | httpx -silent
```
