---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Rapport DFIR : Ransomware Incident Response (Analyse statique Ghidra/PowerShell)"
date: 2026-10-15
categories: [DFIR]
tags: [dfir, ransomware, incident-response, powershell, ghidra, static-analysis, hexdump, windows, ctf]
---

# Rapport DFIR : Ransomware Incident Response

> **Type de lab :** DFIR, C Programming, Ghidra, Incident Response
> **Objectif :** identifier le mécanisme du ransomware et récupérer le flag
> **Résultat :** ✅ flag récupéré par analyse statique, sans exécution du binaire


## 1. Contexte et méthode

L'incident concerne un poste Windows accessible en RDP depuis le réseau VPN du lab. Le scénario indique qu'un ransomware a compromis la machine et que les fichiers du Bureau doivent être examinés.

**Approche suivie : non destructive.** Inventaire des fichiers, calcul d'empreintes, recherche de programmes suspects, extraction statique de chaînes et lecture hexadécimale du fichier de preuve. **Aucun exécutable suspect n'a été lancé.**

| Élément | Valeur observée |
| --- | --- |
| Adresse de la machine | `10.8.0.100` |
| Compte utilisé | `Administrator` |
| Répertoire utilisateur | `C:\Users\Administrator` |
| Répertoire de travail IR | `C:\IR` |
| Échantillon suspect | `C:\Windows\ntdll.exe` |
| Taille de l'échantillon | 264 078 octets |
| Hash SHA-256 de l'échantillon | `800A3F327EB12ED300D083FB8AED7624BBA20B5B81A81A9ECBEF2ACCD9F83073` |
| Fichier de preuve | `C:\Users\Administrator\Desktop\proof.txt` |
| Taille du fichier de preuve | 41 octets |

## 2. Préparation de la collecte

Le répertoire `C:\IR` a été créé afin de centraliser les résultats et de ne pas mélanger les fichiers d'analyse avec les artefacts originaux.

```powershell
New-Item C:\IR -ItemType Directory -Force | Out-Null
```

**Sortie :** aucune sortie affichée — normal, puisque `Out-Null` masque le résultat de création du répertoire.

**Interprétation :** le répertoire de travail a été créé avec succès. L'option `-Force` permet également de continuer si le dossier existait déjà.

## 3. Inventaire du Bureau

La première collecte a porté sur le Bureau de l'utilisateur `Administrator`.

```powershell
Get-ChildItem "$env:USERPROFILE\Desktop" -Force |
  Select-Object FullName,Length,Extension,LastWriteTime |
  Tee-Object C:\IR\desktop.txt
```

Sortie observée :

```text
C:\Users\Administrator\Desktop\desktop.ini                            282 .ini      9/9/2024 6:48:02 PM
C:\Users\Administrator\Desktop\EC2 Feedback.website                   527 .website  9/1/2026 4:40:19 PM
C:\Users\Administrator\Desktop\EC2 Microsoft Windows Guide.website    554 .website  9/1/2026 4:40:19 PM
C:\Users\Administrator\Desktop\Microsoft Edge.lnk                    2308 .lnk      9/1/2026 4:40:19 PM
C:\Users\Administrator\Desktop\proof.txt                               41 .txt      9/1/2026 4:40:19 PM
```

**Interprétation :** le Bureau ne présentait pas de série de fichiers avec une extension typique de ransomware telle que `.locked`, `.enc` ou `.encrypted`. Le fichier inhabituel et pertinent pour le lab est `proof.txt`, d'une taille de 41 octets. Une taille aussi faible justifie une vérification du contenu binaire plutôt qu'une simple lecture textuelle.

## 4. Calcul des empreintes du Bureau

Des empreintes SHA-256 ont été calculées pour tous les fichiers présents sur le Bureau.

```powershell
Get-ChildItem "$env:USERPROFILE\Desktop" -File -Force |
  ForEach-Object { Get-FileHash $_.FullName -Algorithm SHA256 } |
  Tee-Object C:\IR\hashes.txt
```

| Fichier | SHA-256 |
| --- | --- |
| `desktop.ini` | `4B9D687AC625690FD026ED4B236DAD1CAC90EF69E7AD256CC42766A065B50026` |
| `EC2 Feedback.website` | `A27939E9DCAE819D98EE073700194771D53C1F53EE7BDE3425FCD4F25859CC54` |
| `EC2 Microsoft Windows Guide.website` | `5BCEB76F1900054920F86A5DBCB228FFA418252C59514F54881139D5EBB7E4BC` |
| `Microsoft Edge.lnk` | `094BFDA29E52BACD20B78A7A8C5C9AD6477628E5E5528DC52CF2CEC3DEB1BF37` |
| `proof.txt` | `B2E1BBDC95C2C0AD8BCF7D7FC29D8F036ACC85BF3048881F6F21EC160F469D8F` |

> ℹ️ L'affichage PowerShell fourni était tronqué horizontalement pour certaines colonnes de chemin, mais les cinq fichiers correspondent à l'inventaire du Bureau.

## 5. Recherche initiale de programmes suspects

Une recherche a été effectuée dans les répertoires `Downloads` et `Desktop` pour les extensions exécutables ou scriptées.

```powershell
Get-ChildItem C:\Users\Administrator\Downloads,C:\Users\Administrator\Desktop `
  -Recurse -File -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Extension -match '\.(exe|dll|ps1|bat|cmd|vbs|js)$' } |
  Select-Object FullName,Length,LastWriteTime |
  Out-File C:\IR\suspects.txt
```

**Sortie :** le fichier `C:\IR\suspects.txt` ne contenait pas de résultat exploitable. La commande a toutefois été saisie une première fois avec des caractères corrompus dans certains noms de propriétés, probablement à cause du collage dans la console. Cette erreur n'a pas affecté les fichiers originaux et a été contournée par des commandes plus simples.

**Interprétation :** l'absence d'échantillon dans `Desktop` et `Downloads` indique que le programme suspect devait être recherché plus largement dans le système de fichiers.

## 6. Recherche élargie des artefacts

La recherche a été étendue à la racine `C:\`, en ciblant les extensions susceptibles d'être associées au binaire, au code source, aux symboles ou aux fichiers chiffrés.

```powershell
Get-ChildItem C:\ -Recurse -File -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Extension -in '.exe','.dll','.pdb','.c','.h','.txt','.locked','.enc','.encrypted','.ransom' } |
  Select-Object FullName,Length,Extension,LastWriteTime |
  Out-File C:\IR\all_candidates.txt
```

**Résultat pertinent :** la sortie contenait principalement des composants Windows et Amazon EC2 (par exemple `C:\Boot\memtest.exe`, les composants de `C:\Program Files\Amazon` et de nombreux fichiers de `C:\Windows`). L'artefact intéressant découvert ensuite est :

```text
C:\Windows\ntdll.exe
```

**Interprétation :** le nom est anormal. Sur Windows, `ntdll` est normalement associé à la bibliothèque système `ntdll.dll` ; un fichier `ntdll.exe` placé directement dans `C:\Windows` constitue donc un indicateur de compromission dans le contexte de ce lab. **Il ne fallait pas le lancer.**

## 7. Identification et empreinte de l'échantillon

```powershell
Get-FileHash C:\Windows\ntdll.exe -Algorithm SHA256
```

```text
Algorithm  Hash
---------  ----
SHA256     800A3F327EB12ED300D083FB8AED7624BBA20B5B81A81A9ECBEF2ACCD9F83073
Path       C:\Windows\ntdll.exe
```

Métadonnées obtenues :

```powershell
Get-Item C:\Windows\ntdll.exe |
  Select-Object FullName,Length,CreationTime,LastWriteTime
```

| Propriété | Valeur |
| --- | --- |
| Chemin | `C:\Windows\ntdll.exe` |
| Taille | 264 078 octets |
| Date de création | 9/9/2024 18:59:53 |
| Date de modification | 9/9/2024 19:00:03 |

**Interprétation :** le fichier est un exécutable de 264 078 octets, créé et modifié à quelques secondes d'intervalle. Cette chronologie est compatible avec le dépôt ou la génération d'un échantillon de test. L'empreinte SHA-256 a été conservée pour l'identification et la traçabilité.

## 8. Analyse statique des chaînes

La commande Unix `strings` n'était pas disponible dans PowerShell :

```text
strings : The term 'strings' is not recognized as the name of a cmdlet, function, script file, or operable program.
```

Une méthode native PowerShell/.NET a donc été utilisée. Elle lit les octets du fichier, les convertit en ASCII et conserve les séquences imprimables d'au moins cinq caractères.

```powershell
$b = [IO.File]::ReadAllBytes('C:\Windows\ntdll.exe')
$s = [Text.Encoding]::ASCII.GetString($b)
[regex]::Matches($s,'[ -~]{5,}') |
  ForEach-Object Value |
  Set-Content C:\IR\ntdll_strings.txt
Get-Content C:\IR\ntdll_strings.txt
```

**Chaînes significatives observées :**

```text
This program cannot be run in DOS mode.
.text
.data
.rdata
.pdata
.xdata
.bss
.idata
.reloc
\\Desktop
Encrypt
GenerateKey
xtxtmode.c
```

D'autres chaînes génériques liées à l'environnement C et Windows étaient également présentes, notamment `_findfirst64`, des symboles de type `WriteFile`, des noms de drapeaux de structures et des symboles MinGW. Elles ne sont pas toutes spécifiques au ransomware.

**Interprétation :** les sections `.text`, `.data`, `.rdata`, `.idata` et `.reloc` indiquent un exécutable PE Windows. Les chaînes `Encrypt` et `GenerateKey` sont directement cohérentes avec les objectifs du lab : le programme contient une routine de chiffrement et une routine de génération de clé. La chaîne `\\Desktop` montre que le programme cible le Bureau. Le fichier présente donc les caractéristiques de l'échantillon ransomware attendu.

## 9. Lecture hexadécimale du fichier de preuve

Une lecture textuelle simple de `proof.txt` n'a rien affiché. Le fichier devait donc être consulté au niveau des octets.

```powershell
Format-Hex -Path C:\Users\Administrator\Desktop\proof.txt
```

Sortie observée :

```text
Path: C:\Users\Administrator\Desktop\proof.txt

           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000   66 6C 61 67 5F 35 35 32 61 32 38 36 39 5F 34 34  flag_552a2869_44
00000010   66 32 5F 34 36 39 30 5F 39 63 30 33 5F 64 32 65  f2_4690_9c03_d2e
00000020   39 63 66 37 31 39 39 65 38                       9cf7199e8
```

**Conversion ASCII :**

| Octets hexadécimaux | Caractères ASCII |
| --- | --- |
| `66 6C 61 67 5F 35 35 32 61 32 38 36 39 5F 34 34` | `flag_552a2869_44` |
| `66 32 5F 34 36 39 30 5F 39 63 30 33 5F 64 32 65` | `f2_4690_9c03_d2e` |
| `39 63 66 37 31 39 39 65 38` | `9cf7199e8` |

En concaténant les trois lignes, on obtient :

```text
flag_552a2869_44f2_4690_9c03_d2e9cf7199e8
```

## 10. Conclusion et réponse du lab

L'analyse a suivi une progression de réponse à incident : inventaire du Bureau, conservation des empreintes, recherche élargie, identification d'un exécutable anormal, analyse statique de ses chaînes puis examen hexadécimal du fichier de preuve.

Le binaire `C:\Windows\ntdll.exe` est l'artefact ransomware probable, notamment en raison de son emplacement inhabituel et des chaînes `Encrypt`, `GenerateKey` et `\\Desktop`.

Le flag a été validé par conversion directe des octets de `proof.txt` en ASCII. **Aucun lancement du binaire ni modification des fichiers de preuve n'a été nécessaire.**

**Flag final :**

```text
flag_552a2869_44f2_4690_9c03_d2e9cf7199e8
```

## Annexe — commandes principales regroupées

```powershell
New-Item C:\IR -ItemType Directory -Force | Out-Null

Get-ChildItem "$env:USERPROFILE\Desktop" -Force |
  Select-Object FullName,Length,Extension,LastWriteTime |
  Tee-Object C:\IR\desktop.txt

Get-ChildItem "$env:USERPROFILE\Desktop" -File -Force |
  ForEach-Object { Get-FileHash $_.FullName -Algorithm SHA256 } |
  Tee-Object C:\IR\hashes.txt

Get-ChildItem C:\Windows\ntdll.exe |
  Select-Object FullName,Length,CreationTime,LastWriteTime

Get-FileHash C:\Windows\ntdll.exe -Algorithm SHA256

$b = [IO.File]::ReadAllBytes('C:\Windows\ntdll.exe')
$s = [Text.Encoding]::ASCII.GetString($b)
[regex]::Matches($s,'[ -~]{5,}') |
  ForEach-Object Value |
  Set-Content C:\IR\ntdll_strings.txt
Get-Content C:\IR\ntdll_strings.txt |
  Select-String -Pattern 'Encrypt|GenerateKey|Desktop|flag|key|decrypt|xor|DFIR|CTF' -CaseSensitive:$false

Format-Hex -Path C:\Users\Administrator\Desktop\proof.txt
```

## Leçons retenues

- Une taille de fichier anormalement petite (41 octets pour `proof.txt`) est un signal à vérifier au niveau binaire plutôt qu'en lecture texte simple — le contenu peut sembler vide alors qu'il contient des données exploitables.
- Un nom de fichier imitant un composant système légitime (`ntdll.exe` au lieu de `ntdll.dll`), placé dans un répertoire système (`C:\Windows`), est un indicateur de compromission classique à rechercher.
- En l'absence de l'outil Unix `strings`, une regex PowerShell (`[regex]::Matches($s,'[ -~]{5,}')`) sur les octets ASCII du fichier permet d'obtenir un résultat équivalent sans dépendance externe.
- L'analyse statique (sections PE, chaînes de caractères) peut suffire à confirmer le comportement d'un ransomware sans jamais l'exécuter, limitant le risque pour l'environnement d'analyse.

## Références

- Format de fichier **PE (Portable Executable)** — sections `.text`, `.data`, `.rdata`, `.idata`, `.reloc`
- `Format-Hex` — cmdlet PowerShell pour l'inspection binaire
