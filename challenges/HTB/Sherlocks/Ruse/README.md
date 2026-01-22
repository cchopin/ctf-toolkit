# Ruse - Sherlock Write-up

- **Difficulté**: Hard  
- **Catégorie**: macOS Forensics  
- **Outils utilisés**: sqlite3, strings, log show, xattr, hdiutil, plutil  

## Scénario

Un système macOS a été compromis après qu'un attaquant ait obtenu un accès initial via une entité déguisée. L'intrusion a escaladé les privilèges, établi une persistence et activé un accès distant non autorisé.

## Artefacts fournis

- Collection de triage macOS (fsevents, logs, Safari history, etc.)
- Dossier `Deleted-Users/loki.dmg` - Home archivé de l'utilisateur malveillant

---

## Task 1: What is the version of the MacOS system?

**Méthode**: Lecture du fichier `SystemVersion.plist`

```bash
cat ireks-Mac-Triage/System/Library/CoreServices/SystemVersion.plist
```

Le champ `ProductUserVisibleVersion` contient la version de macOS.

---

## Task 2: What is the name of the malicious entity responsible for the initial access?

**Méthode**: Analyse des fichiers dans la Trash et de l'historique Safari

Chercher les applications suspectes dans `Users/irek/.Trash/` et analyser leur contenu (notamment les scripts shell).

---

## Task 3: When did the user first initiate the download of that malicious entity (UTC)?

**Méthode**: Analyse du fichier Downloads.plist de Safari

```bash
plutil -convert xml1 -o - Users/irek/Library/Safari/Downloads.plist
```

Chercher le champ `DownloadEntryDateAddedKey` associé au fichier malveillant.

---

## Task 4: What was the timestamp (UTC) of the user's most recent interaction with the malicious file?

**Méthode**: Analyse des logs launchd

```bash
grep "nom-de-l-app" private/var/log/com.apple.xpc.launchd/launchd.log*
```

Chercher l'événement `WILL_SPAWN`. Les timestamps launchd sont en heure locale (EET = UTC+2).

---

## Task 5: The attacker used a tool to drop files and bypass Gatekeeper. What is the name of the tool used for this technique?

**Explication**: Les fichiers téléchargés via certains outils CLI ne reçoivent pas l'attribut `com.apple.quarantine`, ce qui permet de contourner Gatekeeper.

Analyser les commandes utilisées par l'attaquant après avoir obtenu un reverse shell.

---

## Task 6: What is the full file path of the Mach-O executable crafted by the attacker for privilege escalation?

**Méthode**: Rechercher les exécutables Mach-O dans la Trash ou sur le Desktop

```bash
file Users/irek/.Trash/*
file Users/irek/Desktop/*
```

---

## Task 7: What is the CVE number associated with the exploit leveraged by the attacker?

**Méthode**: Analyser le code source de l'exploit (fichier .c) présent dans la Trash

Rechercher les fonctions caractéristiques et les commentaires qui peuvent indiquer la CVE exploitée. Il s'agit d'une race condition dans le kernel macOS.

---

## Task 8: During the privilege escalation phase, the attacker mimicked the use of a well-known system file by altering a specific word in its configuration. What is the specific word that was changed?

**Méthode**: Comparer le fichier PAM original avec le fichier modifié par l'attaquant

```bash
diff /etc/pam.d/su Users/irek/.Trash/overwrite_file.bin
```

Chercher quel module PAM a été modifié pour permettre une élévation de privilèges sans authentification.

---

## Task 9: After gaining root privilege, the attacker created a new user. When did he create that user (UTC)?

**Méthode**: Analyse des Unified Logs

```bash
log show --archive "UnifiedLogs/ireks-Mac_20250308_160413.logarchive" \
  --predicate "eventMessage contains \"loki\"" --style compact
```

Chercher l'événement "Creating home directory". Conversion timezone: local (EET) - 2h = UTC.

---

## Task 10: At what point did the attacker successfully enable SSH on the system (UTC)?

**Méthode**: Analyse des Unified Logs et launchd

```bash
log show --archive "UnifiedLogs/..." --predicate "eventMessage contains \"ssh\"" --style compact
grep "ssh" private/var/log/com.apple.xpc.launchd/launchd.log*
```

Chercher l'événement "Enabling service com.openssh.sshd" (succès de launchctl load).

---

## Task 11: The user noticed unusual activity and shut down the device. A day after, he turned on his laptop. At what time (UTC) did he turn on his laptop?

**Méthode**: Analyse du system.log et des Unix timestamps ASL

```bash
grep "BOOT_TIME" private/var/log/system.log
```

Le timestamp Unix après BOOT_TIME est déjà en UTC.

---

## Task 12: After enabling SSH, the attacker successfully established an SSH connection when the user turned on their machine. At what specific time (UTC) did the attacker establish the SSH connection?

**Méthode**: Analyse des logs ASL et system.log

```bash
grep "sshd.*loki" private/var/log/system.log
strings private/var/log/asl/*.asl | grep -E "sshd|loki"
```

---

## Task 13: The attacker downloaded and dropped a malicious file onto the system to establish persistence. What is the name of this malicious file?

**Méthode**: Analyse du dossier de l'utilisateur malveillant dans le DMG

```bash
hdiutil attach Users/Deleted-Users/loki.dmg -readonly
ls -la /Volumes/loki/Desktop/
```

Comparer les hash MD5 avec les fichiers de persistence.

---

## Task 14: The malicious file created a specific file to ensure the malware runs every time the user logs in. What is the name of this file?

**Méthode**: Montage du DMG et analyse des LaunchAgents

```bash
hdiutil attach Users/Deleted-Users/loki.dmg -readonly
ls /Volumes/loki/Library/LaunchAgents/
```

---

## Task 15: The file points to an executable that runs upon user login. What is the full path of this executable file?

**Méthode**: Lecture du plist de persistence

```bash
plutil -convert xml1 -o - /Volumes/loki/Library/LaunchAgents/*.plist
```

Chercher la clé `ProgramArguments`.

---

## Task 16: What is the MITRE ATT&CK technique ID associated with the persistence mechanism used by the attacker?

**Méthode**: Identifier le mécanisme de persistence (LaunchAgent) et chercher la technique MITRE correspondante.

Les LaunchAgents sont documentés dans la matrice ATT&CK sous "Create or Modify System Process".

---

## Task 17: Based on the analysis of the malicious file and its persistence mechanism, what is the most prevalent malware family associated with this attack?

**Méthode**: Analyser les strings du binaire malveillant

```bash
strings /Volumes/loki/.local/bin/sysetmd | grep -i "kbr\|whatismyip\|icanhazip"
```

Rechercher les indicateurs caractéristiques (extensions de fichiers, services IP lookup, framework C2 utilisé).

---

## Task 18: The legitimate user noticed and deleted the unauthorized account created by the attacker. When did the user delete the attacker-created account (UTC)?

**Méthode**: Analyse des logs launchd et de l'historique Safari

```bash
# Recherches de l'utilisateur
sqlite3 "Users/irek/Library/Safari/History.db" \
  "SELECT datetime(visit_time + 978307200, 'unixepoch'), url FROM history_visits v
   JOIN history_items i ON v.history_item = i.id WHERE url LIKE '%delete%user%';"

# Événements de suppression
grep "writeconfig\|user/502" private/var/log/com.apple.xpc.launchd/launchd.log*
```

Sur macOS, la suppression d'un utilisateur via System Preferences archive automatiquement le home directory en DMG.

---

## Artefacts macOS clés pour l'investigation

### Logs
| Artefact | Chemin | Description |
|----------|--------|-------------|
| Unified Logs | `/private/var/db/diagnostics/*.logarchive` | Logs système consolidés |
| Launchd Logs | `/private/var/log/com.apple.xpc.launchd/` | Événements de processus |
| System Log | `/private/var/log/system.log` | Log système général |
| ASL Logs | `/private/var/log/asl/` | Apple System Logs (format binaire) |

### Persistence
| Artefact | Chemin | Description |
|----------|--------|-------------|
| LaunchAgents (User) | `~/Library/LaunchAgents/` | Persistence au login utilisateur |
| LaunchAgents (System) | `/Library/LaunchAgents/` | Persistence pour tous les utilisateurs |
| LaunchDaemons | `/Library/LaunchDaemons/` | Services système au boot |

### Historique utilisateur
| Artefact | Chemin | Description |
|----------|--------|-------------|
| Safari History | `~/Library/Safari/History.db` | Historique de navigation (SQLite) |
| Safari Downloads | `~/Library/Safari/Downloads.plist` | Historique des téléchargements |
| Quarantine DB | `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` | Fichiers téléchargés |

---

## Commandes utiles pour l'analyse macOS

```bash
# Historique Safari (timestamps en UTC via Cocoa epoch)
sqlite3 "Library/Safari/History.db" \
  "SELECT datetime(visit_time + 978307200, 'unixepoch'), url FROM history_visits v
   JOIN history_items i ON v.history_item = i.id ORDER BY visit_time;"

# Events de quarantaine (Gatekeeper)
sqlite3 "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" \
  "SELECT datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch'), *
   FROM LSQuarantineEvent;"

# Unified Logs
log show --archive file.logarchive --predicate "eventMessage contains 'keyword'" --style compact

# Logs système
grep "BOOT_TIME\|sshd\|sysadminctl" private/var/log/system.log

# Logs launchd
grep -E "sysadminctl|systemsetup|sshd" private/var/log/com.apple.xpc.launchd/*.log*

# Monter un DMG en lecture seule
hdiutil attach file.dmg -readonly -nobrowse

# Attributs étendus (quarantine)
xattr -l /path/to/file

# Strings d'un binaire
strings /path/to/binary | grep -i "keyword"

# Conversion timestamp Unix vers date
python3 -c "import datetime; print(datetime.datetime.utcfromtimestamp(TIMESTAMP))"
```

---

## Notes importantes sur les timezones macOS - (Ca peut vous rendre chèvre)

- **Timezone du système**: EET (Eastern European Time) = UTC+2
- **Launchd logs**: Timestamps en heure LOCALE (nécessite conversion -2h pour UTC)
- **Unified logs**: Timestamps en heure LOCALE avec indicateur de timezone (+0200)
- **Safari History DB**: Timestamps stockés en UTC (Cocoa epoch + 978307200)
- **ASL logs**: Timestamps Unix (déjà en UTC)
- **system.log**: Timestamps en heure LOCALE

**Formule de conversion**: `UTC = Local Time - 2 heures` (pour EET)

---
