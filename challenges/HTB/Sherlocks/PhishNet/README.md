# PhishNet - Sherlock Write-up

**Difficulté**: Very Easy
**Catégorie**: Email Forensics / Phishing Analysis

## Scénario

Une équipe comptable reçoit une demande de paiement urgente d'un fournisseur connu. L'email semble légitime mais contient un lien suspect et une pièce jointe .zip cachant un malware. L'objectif est d'analyser les en-têtes de l'email et découvrir le schéma de l'attaquant.

## Fichier fourni

- `email.eml` - L'email de phishing à analyser

---

## Task 1: What is the originating IP address of the sender?

**Réponse**: `45.67.89.10`

**Explication**: L'IP d'origine se trouve dans l'en-tête `X-Originating-IP`:

```
X-Originating-IP: [45.67.89.10]
```

On peut aussi la confirmer avec `X-Sender-IP: 45.67.89.10`.

---

## Task 2: Which mail server relayed this email before reaching the victim?

**Réponse**: `mail.business-finance.com`

**Explication**: Les en-têtes `Received` se lisent de bas en haut (chronologiquement). Le dernier serveur avant la victime est visible ici:

```
Received: from mail.business-finance.com ([203.0.113.25])
    by mail.target.com (Postfix) with ESMTP id ABC123;
```

Le serveur `mail.business-finance.com` a relayé l'email vers `mail.target.com` (le serveur de la victime).

---

## Task 3: What is the sender's email address?

**Réponse**: `finance@business-finance.com`

**Explication**: L'adresse de l'expéditeur se trouve dans l'en-tête `From`:

```
From: "Finance Dept" <finance@business-finance.com>
```

---

## Task 4: What is the 'Reply-To' email address specified in the email?

**Réponse**: `support@business-finance.com`

**Explication**: L'en-tête `Reply-To` indique où les réponses seront envoyées:

```
Reply-To: <support@business-finance.com>
```

Cette technique est souvent utilisée en phishing pour rediriger les réponses vers une adresse contrôlée par l'attaquant.

---

## Task 5: What is the SPF (Sender Policy Framework) result for this email?

**Réponse**: `pass`

**Explication**: Le résultat SPF se trouve dans l'en-tête `Received-SPF` ou `Authentication-Results`:

```
Received-SPF: Pass (protection.outlook.com: domain of business-finance.com designates 45.67.89.10 as permitted sender)
```

Un SPF "pass" signifie que l'IP de l'expéditeur est autorisée à envoyer des emails pour ce domaine. L'attaquant contrôle probablement le domaine `business-finance.com`.

---

## Task 6: What is the domain used in the phishing URL inside the email?

**Réponse**: `secure.business-finance.com`

**Explication**: Dans le corps HTML de l'email, on trouve le lien de phishing:

```html
<a href="https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment">Download Invoice</a>
```

Le domaine utilisé est `secure.business-finance.com`.

---

## Task 7: What is the fake company name used in the email?

**Réponse**: `Business Finance Ltd.`

**Explication**: Le nom de la fausse entreprise apparaît dans la signature de l'email:

```html
<p>Best regards,<br>Finance Department<br>Business Finance Ltd.</p>
```

On le retrouve aussi dans l'en-tête `X-Organization: Business Finance Ltd.`

---

## Task 8: What is the name of the attachment included in the email?

**Réponse**: `Invoice_2025_Payment.zip`

**Explication**: Le nom de la pièce jointe se trouve dans les en-têtes MIME:

```
Content-Type: application/zip; name="Invoice_2025_Payment.zip"
Content-Disposition: attachment; filename="Invoice_2025_Payment.zip"
```

---

## Task 9: What is the SHA-256 hash of the attachment?

**Réponse**: `8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a`

**Explication**: La pièce jointe est encodée en base64 dans l'email. Pour obtenir le hash:

```bash
# Extraire le contenu base64 et le décoder
echo "UEsDBBQAAAAIABh/WloXPY4qcxITALvMGQAYAAAAaW52b2ljZV9kb2N1bWVudC5wZGYuYmF0zL3ZzuzIsR18LQN+h62DPujWX0e7" | base64 -d > attachment.zip

# Calculer le hash SHA-256
shasum -a 256 attachment.zip
# ou
sha256sum attachment.zip
```

---

## Task 10: What is the filename of the malicious file contained within the ZIP attachment?

**Réponse**: `invoice_document.pdf.bat`

**Explication**: En analysant le contenu du ZIP (même tronqué), on peut extraire les métadonnées:

```bash
echo "UEsDBBQAAAAIABh/WloXPY4qcxITALvMGQAYAAAAaW52b2ljZV9kb2N1bWVudC5wZGYuYmF0zL3ZzuzIsR18LQN+h62DPujWX0e7" | base64 -d | strings
```

Résultat: `invoice_document.pdf.bat`

C'est une technique de **double extension**: le fichier apparaît comme un PDF mais c'est en réalité un fichier batch (.bat) exécutable Windows. Sur Windows, si les extensions sont masquées, l'utilisateur ne verra que "invoice_document.pdf".

---

## Task 11: Which MITRE ATT&CK techniques are associated with this attack?

**Réponse**: `T1566.001, T1204.002, T1036.007`

**Explication**: Cette attaque utilise plusieurs techniques documentées par MITRE ATT&CK:

| Technique ID | Nom | Description |
|--------------|-----|-------------|
| **T1566.001** | Phishing: Spearphishing Attachment | L'email contient une pièce jointe malveillante (.zip) |
| **T1204.002** | User Execution: Malicious File | L'attaque nécessite que l'utilisateur ouvre/exécute le fichier |
| **T1036.007** | Masquerading: Double File Extension | Le fichier `.pdf.bat` se fait passer pour un PDF |

---

## Indicateurs de Compromission (IOCs)

| Type | Valeur |
|------|--------|
| IP | 45.67.89.10 |
| IP | 203.0.113.25 |
| Domaine | business-finance.com |
| Domaine | secure.business-finance.com |
| Email | finance@business-finance.com |
| Email | support@business-finance.com |
| Fichier | Invoice_2025_Payment.zip |
| Fichier | invoice_document.pdf.bat |
| SHA-256 | 8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a |

---

## Commandes utiles

```bash
# Voir les en-têtes de l'email
cat email.eml | head -35

# Extraire et décoder la pièce jointe base64
grep -A1 "Content-Transfer-Encoding: base64" email.eml | tail -1 | base64 -d > attachment.zip

# Hash SHA-256
shasum -a 256 attachment.zip

# Lister le contenu d'un ZIP
unzip -l attachment.zip

# Extraire les strings d'un fichier binaire
strings attachment.zip
```

---
