# Ruse - Write-up Sherlock

- **Difficulté** : Difficile
- **Catégorie** : Forensique macOS
- **Outils utilisés** : sqlite3, strings, log show, xattr, hdiutil, plutil  

## Scénario

Un système macOS a été compromis après qu'un attaquant ait obtenu un accès initial via une entité déguisée. L'intrusion a escaladé les privilèges, établi une persistence et activé un accès distant non autorisé.

## Artefacts fournis

- Collection de triage macOS (fsevents, logs, Safari history, etc.)
- Dossier `Deleted-Users/loki.dmg` - Home archivé de l'utilisateur malveillant

---

## Tâche 1 : Quelle est la version du système macOS ?

**Méthode** : Lecture du fichier `SystemVersion.plist`

```bash
cat ireks-Mac-Triage/System/Library/CoreServices/SystemVersion.plist
```

Le champ `ProductUserVisibleVersion` contient la version de macOS.

---

## Tâche 2 : Quel est le nom de l'entité malveillante responsable de l'accès initial ?

**Méthode** : Analyse des fichiers dans la Corbeille et de l'historique Safari

Chercher les applications suspectes dans `Users/irek/.Trash/` et analyser leur contenu (notamment les scripts shell).

---

## Tâche 3 : Quand l'utilisateur a-t-il initié le téléchargement de cette entité malveillante (UTC) ?

**Méthode** : Analyse du fichier Downloads.plist de Safari

```bash
plutil -convert xml1 -o - Users/irek/Library/Safari/Downloads.plist
```

Chercher le champ `DownloadEntryDateAddedKey` associé au fichier malveillant.

---

## Tâche 4 : Quel était le timestamp (UTC) de la dernière interaction de l'utilisateur avec le fichier malveillant ?

**Méthode** : Analyse des logs launchd

```bash
grep "nom-de-l-app" private/var/log/com.apple.xpc.launchd/launchd.log*
```

Chercher l'événement `WILL_SPAWN`. Les timestamps launchd sont en heure locale (EET = UTC+2).

---

## Tâche 5 : L'attaquant a utilisé un outil pour déposer des fichiers et contourner Gatekeeper. Quel est le nom de l'outil utilisé ?

**Explication** : Les fichiers téléchargés via certains outils CLI ne reçoivent pas l'attribut `com.apple.quarantine`, ce qui permet de contourner Gatekeeper.

Analyser les commandes utilisées par l'attaquant après avoir obtenu un reverse shell.

---

## Tâche 6 : Quel est le chemin complet de l'exécutable Mach-O créé par l'attaquant pour l'élévation de privilèges ?

**Méthode** : Rechercher les exécutables Mach-O dans la Corbeille ou sur le Bureau

```bash
file Users/irek/.Trash/*
file Users/irek/Desktop/*
```

---

## Tâche 7 : Quel est le numéro CVE associé à l'exploit utilisé par l'attaquant ?

**Méthode** : Analyser le code source de l'exploit (fichier .c) présent dans la Corbeille

Rechercher les fonctions caractéristiques et les commentaires qui peuvent indiquer la CVE exploitée. Il s'agit d'une race condition dans le kernel macOS.

---

## Tâche 8 : Durant la phase d'élévation de privilèges, l'attaquant a imité l'utilisation d'un fichier système bien connu en modifiant un mot spécifique dans sa configuration. Quel est le mot qui a été modifié ?

**Méthode** : Comparer le fichier PAM original avec le fichier modifié par l'attaquant

```bash
diff /etc/pam.d/su Users/irek/.Trash/overwrite_file.bin
```

Chercher quel module PAM a été modifié pour permettre une élévation de privilèges sans authentification.

---

## Tâche 9 : Après avoir obtenu les privilèges root, l'attaquant a créé un nouvel utilisateur. Quand a-t-il créé cet utilisateur (UTC) ?

**Méthode** : Analyse des Unified Logs

```bash
log show --archive "UnifiedLogs/ireks-Mac_20250308_160413.logarchive" \
  --predicate "eventMessage contains \"loki\"" --style compact
```

Chercher l'événement "Creating home directory". Conversion timezone : local (EET) - 2h = UTC.

---

## Tâche 10 : À quel moment l'attaquant a-t-il réussi à activer SSH sur le système (UTC) ?

**Méthode** : Analyse des Unified Logs et launchd

```bash
log show --archive "UnifiedLogs/..." --predicate "eventMessage contains \"ssh\"" --style compact
grep "ssh" private/var/log/com.apple.xpc.launchd/launchd.log*
```

Chercher l'événement "Enabling service com.openssh.sshd" (succès de launchctl load).

---

## Tâche 11 : L'utilisateur a remarqué une activité inhabituelle et a éteint l'appareil. Un jour après, il a rallumé son ordinateur portable. À quelle heure (UTC) l'a-t-il rallumé ?

**Méthode** : Analyse du system.log et des Unix timestamps ASL

```bash
grep "BOOT_TIME" private/var/log/system.log
```

Le timestamp Unix après BOOT_TIME est déjà en UTC.

---

## Tâche 12 : Après avoir activé SSH, l'attaquant a réussi à établir une connexion SSH quand l'utilisateur a rallumé sa machine. À quelle heure précise (UTC) l'attaquant a-t-il établi la connexion SSH ?

**Méthode** : Analyse des logs ASL et system.log

```bash
grep "sshd.*loki" private/var/log/system.log
strings private/var/log/asl/*.asl | grep -E "sshd|loki"
```

---

## Tâche 13 : L'attaquant a téléchargé et déposé un fichier malveillant sur le système pour établir la persistance. Quel est le nom de ce fichier malveillant ?

**Méthode** : Analyse du dossier de l'utilisateur malveillant dans le DMG

```bash
hdiutil attach Users/Deleted-Users/loki.dmg -readonly
ls -la /Volumes/loki/Desktop/
```

Comparer les hash MD5 avec les fichiers de persistance.

---

## Tâche 14 : Le fichier malveillant a créé un fichier spécifique pour s'assurer que le malware s'exécute à chaque connexion de l'utilisateur. Quel est le nom de ce fichier ?

**Méthode** : Montage du DMG et analyse des LaunchAgents

```bash
hdiutil attach Users/Deleted-Users/loki.dmg -readonly
ls /Volumes/loki/Library/LaunchAgents/
```

---

## Tâche 15 : Le fichier pointe vers un exécutable qui s'exécute à la connexion de l'utilisateur. Quel est le chemin complet de ce fichier exécutable ?

**Méthode** : Lecture du plist de persistance

```bash
plutil -convert xml1 -o - /Volumes/loki/Library/LaunchAgents/*.plist
```

Chercher la clé `ProgramArguments`.

---

## Tâche 16 : Quel est l'ID de technique MITRE ATT&CK associé au mécanisme de persistance utilisé par l'attaquant ?

**Méthode** : Identifier le mécanisme de persistance (LaunchAgent) et chercher la technique MITRE correspondante.

Les LaunchAgents sont documentés dans la matrice ATT&CK sous "Create or Modify System Process".

---

## Tâche 17 : Basé sur l'analyse du fichier malveillant et de son mécanisme de persistance, quelle est la famille de malware la plus répandue associée à cette attaque ?

**Méthode** : Analyser les strings du binaire malveillant

```bash
strings /Volumes/loki/.local/bin/sysetmd | grep -i "kbr\|whatismyip\|icanhazip"
```

Rechercher les indicateurs caractéristiques (extensions de fichiers, services IP lookup, framework C2 utilisé).

---

## Tâche 18 : L'utilisateur légitime a remarqué et supprimé le compte non autorisé créé par l'attaquant. Quand l'utilisateur a-t-il supprimé le compte créé par l'attaquant (UTC) ?

**Méthode** : Analyse des logs launchd et de l'historique Safari

```bash
# Recherches de l'utilisateur
sqlite3 "Users/irek/Library/Safari/History.db" \
  "SELECT datetime(visit_time + 978307200, 'unixepoch'), url FROM history_visits v
   JOIN history_items i ON v.history_item = i.id WHERE url LIKE '%delete%user%';"

# Événements de suppression
grep "writeconfig\|user/502" private/var/log/com.apple.xpc.launchd/launchd.log*
```

Sur macOS, la suppression d'un utilisateur via Préférences Système archive automatiquement le répertoire home en DMG.

---

## Artefacts macOS clés pour l'investigation

### Logs
| Artefact | Chemin | Description |
|----------|--------|-------------|
| Unified Logs | `/private/var/db/diagnostics/*.logarchive` | Logs système consolidés |
| Launchd Logs | `/private/var/log/com.apple.xpc.launchd/` | Événements de processus |
| System Log | `/private/var/log/system.log` | Log système général |
| ASL Logs | `/private/var/log/asl/` | Apple System Logs (format binaire) |

### Persistance
| Artefact | Chemin | Description |
|----------|--------|-------------|
| LaunchAgents (utilisateur) | `~/Library/LaunchAgents/` | Persistance à la connexion utilisateur |
| LaunchAgents (système) | `/Library/LaunchAgents/` | Persistance pour tous les utilisateurs |
| LaunchDaemons | `/Library/LaunchDaemons/` | Services système au démarrage |

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

## Notes importantes sur les fuseaux horaires macOS (ça peut rendre chèvre)

- **Fuseau horaire du système** : EET (Eastern European Time) = UTC+2
- **Launchd logs** : Timestamps en heure LOCALE (nécessite conversion -2h pour UTC)
- **Unified logs** : Timestamps en heure LOCALE avec indicateur de fuseau horaire (+0200)
- **Safari History DB** : Timestamps stockés en UTC (Cocoa epoch + 978307200)
- **ASL logs** : Timestamps Unix (déjà en UTC)
- **system.log** : Timestamps en heure LOCALE

**Formule de conversion** : `UTC = Heure locale - 2 heures` (pour EET)

---
