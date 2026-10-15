---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab Durcissement AD : AS-REP Roasting, Kerberoasting, privilèges et RDP (SecDojo #182)"
date: 2026-10-15
categories: [Active Directory, Hardening]
tags: [active-directory, as-rep-roasting, kerberoasting, uac, least-privilege, rdp, gpo, secedit, powershell, secdojo, ctf]
---

# Lab Durcissement Active Directory : AS-REP Roasting, Kerberoasting, privilèges et RDP

> **Plateforme :** SecDojo (lab 182)
> **Domaine :** `secdojo.local`
> **Points :** 105
> **Résultat :** ✅ 4 erreurs de configuration identifiées et corrigées, 4 flags récupérés


## 1. Objectif et contexte

Ce laboratoire consiste à identifier puis corriger **quatre erreurs de configuration volontaires** dans un domaine Active Directory. Chaque correction validée est confirmée par le remplissage du champ `Description` de l'objet concerné, qui contient le flag à soumettre.

**Accès :** RDP sur le contrôleur de domaine avec le compte `sys_admin` (membre de `Domain Admins`). Toutes les commandes ont été exécutées dans PowerShell, sur le contrôleur de domaine.

```powershell
xfreerdp /v:<IP_DC> /u:sys_admin /p:'<mot_de_passe>' /cert:ignore /dynamic-resolution
```

### Synthèse des erreurs de configuration

| Compte / objet | Erreur de configuration | Correction | Questions |
| --- | --- | --- | --- |
| `svc_backup` | Pré-authentification Kerberos désactivée (`DONT_REQ_PREAUTH`) | Réactivation de la pré-authentification | Q1 à Q5 |
| `svc_monitoring` | SPN inutile `HTTP/monitoringserver.secdojo.local` | Suppression du SPN | Q6 à Q11 |
| `RH` | Membre de `Domain Admins` | Retrait du groupe | Q12 à Q15 |
| `svc_sql` | Droit RDP sur le contrôleur de domaine | Retrait du droit et du groupe | Q16 à Q21 |

## 2. Préalable : élévation des privilèges (UAC)

Première tentative de correction depuis une console PowerShell normale : la commande a échoué.

```powershell
try { Set-ADAccountControl -Identity svc_backup -DoesNotRequirePreAuth $false -ErrorAction Stop } catch { $_.Exception.Message }
```

```text
Insufficient access rights to perform the operation
```

Diagnostic avec `whoami /groups` (extrait) : le niveau d'intégrité est `Medium` et les groupes `Domain Admins` et `BUILTIN\Administrators` sont marqués **« Group used for deny only »**. Le jeton est filtré par l'UAC.

```powershell
whoami /groups
```

```text
BUILTIN\Administrators        Alias   S-1-5-32-544   Group used for deny only
SECDOJO\Domain Admins         Group   S-1-5-21-...-512 Group used for deny only
Mandatory Label\Medium Mandatory Level   Label   S-1-16-8192
```

Vérification des ACL de l'objet : `Administrators` et `Domain Admins` disposent bien des droits d'écriture. Le problème vient donc uniquement de la session non élevée.

```powershell
(Get-Acl "AD:$((Get-ADUser svc_backup).DistinguishedName)").Access | Where-Object { $_.IdentityReference -match "sys_admin|Domain Admins|Administrators" } | Select IdentityReference, AccessControlType, ActiveDirectoryRights
```

```text
IdentityReference       AccessControlType   ActiveDirectoryRights
BUILTIN\Administrators  Allow               ... WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner
SECDOJO\Domain Admins   Allow               ... WriteProperty, ExtendedRight, GenericRead, WriteDacl, WriteOwner
```

> 💡 **Solution :** ouvrir PowerShell avec **« Exécuter en tant qu'administrateur »**. Toutes les corrections suivantes ont été faites dans cette console élevée (invite : `PS C:\Windows\system32>`).

## 3. Partie 1 : AS-REP Roasting (Q1 à Q5)

### Q1 — Nom de l'attaque

Demander un TGT pour un compte sans connaître ses identifiants correspond à l'**AS-REP Roasting**.

**Réponse :** C.

### Q2 — Compte vulnérable

```powershell
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth | Select SamAccountName
```

```text
SamAccountName
--------------
svc_backup
```

**Réponse Q2 :** `svc_backup`

### Q3 et Q4

| # | Réponse |
| --- | --- |
| Q3 | C — documentation obsolète ou croyances erronées sur la compatibilité logicielle, ce qui expose à l'AS-REP Roasting |
| Q4 | `DONT_REQ_PREAUTH`, indicateur de l'attribut `userAccountControl` (valeur `0x400000` soit `4194304`) |

### Q5 — Correction et flag

État avant correction (dans la console non élevée) :

```text
SamAccountName DoesNotRequirePreAuth Description
-------------- --------------------- -----------
svc_backup                      True {}
```

Correction dans la console élevée :

```powershell
Import-Module ActiveDirectory
Set-ADAccountControl -Identity svc_backup -DoesNotRequirePreAuth $false
Get-ADUser svc_backup -Properties DoesNotRequirePreAuth, Description | Select SamAccountName, DoesNotRequirePreAuth, Description
```

```text
SamAccountName DoesNotRequirePreAuth Description
-------------- --------------------- -----------
svc_backup                     False
```

La description se remplit après un court délai (script de validation du lab) :

```powershell
Get-ADUser svc_backup -Properties Description | Select SamAccountName, Description
```

```text
SamAccountName Description
-------------- -----------
svc_backup     8e5f9c2d4a0b46d0a93b70b61cbe9f2a
```

**Flag Q5 :** `8e5f9c2d4a0b46d0a93b70b61cbe9f2a`

## 4. Partie 2 : Kerberoasting (Q6 à Q11)

### Q6 — Nom de l'attaque

Obtenir le TGS d'un service : **Kerberoasting**.

**Réponse :** B.

### Q7 — Comptes vulnérables

```powershell
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName | Select SamAccountName, ServicePrincipalName
```

```text
SamAccountName ServicePrincipalName
-------------- --------------------
svc_monitoring {HTTP/monitoringserver.secdojo.local}
krbtgt         {kadmin/changepw}
svc_sql        {MSSQLSvc/sqlserver01.secdojo.local}
```

`krbtgt` est un compte système dont le SPN est interne à Kerberos, il est écarté. Le champ attendait plusieurs comptes séparés par des virgules (format « user1, user2… »).

**Réponse Q7 (acceptée) :** `svc_monitoring, svc_sql`

> ⚠️ **Retour d'expérience :** la saisie d'un seul compte (`svc_monitoring` puis `svc_sql`) était refusée. Il faut lire le format d'exemple du champ de réponse avant de soumettre.

### Q8, Q9 et Q10

| # | Réponse |
| --- | --- |
| Q8 | B — un agent de supervision se connecte en sortie et n'héberge pas de service authentifié par Kerberos, donc un SPN n'a pas de raison d'être |
| Q9 | `servicePrincipalName : HTTP/monitoringserver.secdojo.local` |
| Q10 | D — supprimer le SPN défini sur le compte |

### Q11 — Correction et flag

```powershell
Set-ADUser svc_monitoring -ServicePrincipalNames @{Remove="HTTP/monitoringserver.secdojo.local"}
Get-ADUser svc_monitoring -Properties ServicePrincipalName, Description | Select SamAccountName, ServicePrincipalName, Description
```

```text
SamAccountName ServicePrincipalName Description
-------------- -------------------- -----------
svc_monitoring {}                   3d9b71a6e24547d2a0f1c06e0b6c91df
```

**Flag Q11 :** `3d9b71a6e24547d2a0f1c06e0b6c91df`

> ℹ️ Le SPN de `svc_sql` (`MSSQLSvc/sqlserver01.secdojo.local`) est légitime et n'a pas été supprimé. Le risque de Kerberoasting sur ce compte se traite par un mot de passe long et aléatoire (ou un compte de service géré, **gMSA**).

## 5. Partie 3 : groupe trop privilégié (Q12 à Q15)

### Q12

**Réponse :** `Domain Admins` (Admins du domaine), le groupe de domaine le plus privilégié.

### Q13 — Utilisateur qui n'a rien à faire dans le groupe

```powershell
Get-ADGroupMember "Domain Admins" | Select SamAccountName
```

```text
SamAccountName
--------------
Administrator
sys_admin
RH
```

**Réponse Q13 :** `RH`. `Administrator` et `sys_admin` sont légitimes ; `sys_admin` est le compte de travail du lab et ne doit pas être retiré.

### Q14

**Réponse :** A — les droits d'administrateur de domaine sont trop puissants pour être attribués sur la seule base de la confiance ou de l'influence ; le principe du moindre privilège s'applique.

### Q15 — Correction et flag

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members RH -Confirm:$false
Get-ADGroupMember "Domain Admins" | Select SamAccountName
Get-ADUser RH -Properties Description | Select SamAccountName, Description
```

```text
SamAccountName Description
-------------- -----------
RH             7c2a1f89b5e04332a9d38b2a16d812e1
```

**Flag Q15 :** `7c2a1f89b5e04332a9d38b2a16d812e1`

> ⚠️ La sortie de la vérification de l'appartenance au groupe après retrait n'a pas été capturée. **Bonne pratique :** la conserver comme preuve.

## 6. Partie 4 : accès RDP au contrôleur de domaine (Q16 à Q21)

### Q16

**Réponse :** `Remote Desktop Users` (Utilisateurs du Bureau à distance).

### Q17

**Réponse :** B, `SeRemoteInteractiveLogonRight`.

### Q18 — Utilisateur pouvant se connecter en RDP

```powershell
Get-ADGroupMember "Remote Desktop Users" | Select SamAccountName
```

```text
SamAccountName
--------------
svc_sql
```

**Réponse Q18 :** `svc_sql`

### Q19 et Q20

| # | Réponse |
| --- | --- |
| Q19 | B — les comptes de service sont souvent vulnérables à Kerberos et ont des mots de passe faibles ou statiques ; un accès RDP au contrôleur de domaine aggrave fortement le risque de compromission du domaine |
| Q20 | A, Kerberoasting — `svc_sql` possède un SPN : n'importe quel utilisateur du domaine peut demander son TGS et casser le mot de passe hors ligne |

### Q21 — Correction et flag

Le droit est aussi attribué directement dans la stratégie locale, ce que confirme l'export de la politique de sécurité :

```powershell
secedit /export /cfg C:\Windows\Temp\sec.cfg
Select-String -Path C:\Windows\Temp\sec.cfg -Pattern "SeRemoteInteractiveLogonRight"
```

```text
The task has completed successfully.
See log %windir%\security\logs\scesrv.log for detail info.

C:\Windows\Temp\sec.cfg:122:SeRemoteInteractiveLogonRight = svc_sql,*S-1-5-32-544
```

Le droit est donné à `svc_sql` et au groupe `Administrators` (`S-1-5-32-544`). Ce dernier doit être conservé pour ne pas perdre l'accès RDP de `sys_admin`. **Correction appliquée :** retrait de `svc_sql` du droit et du groupe.

```powershell
(Get-Content C:\Windows\Temp\sec.cfg) -replace 'SeRemoteInteractiveLogonRight = svc_sql,\*S-1-5-32-544','SeRemoteInteractiveLogonRight = *S-1-5-32-544' | Set-Content C:\Windows\Temp\sec.cfg
secedit /configure /db C:\Windows\Security\Local.sdb /cfg C:\Windows\Temp\sec.cfg /areas USER_RIGHTS
gpupdate /force
Remove-ADGroupMember -Identity "Remote Desktop Users" -Members svc_sql -Confirm:$false
```

Lecture du flag :

```powershell
Get-ADUser svc_sql -Properties Description | Select SamAccountName, Description
```

```text
SamAccountName Description
-------------- -----------
svc_sql        e3b0c44298fc1c149afbf4c8996fb924
```

**Flag Q21 :** `e3b0c44298fc1c149afbf4c8996fb924`

> ⚠️ Les sorties de `secedit /configure` et `gpupdate` ne sont pas reproduites ici car elles n'ont pas été capturées pendant le lab.

## 7. Récapitulatif des réponses

| Question | Réponse |
| --- | --- |
| Q1 | C, AS-REP Roasting |
| Q2 | `svc_backup` |
| Q3 | C |
| Q4 | `DONT_REQ_PREAUTH` |
| Q5 | `8e5f9c2d4a0b46d0a93b70b61cbe9f2a` |
| Q6 | B, Kerberoasting |
| Q7 | `svc_monitoring, svc_sql` |
| Q8 | B |
| Q9 | `servicePrincipalName : HTTP/monitoringserver.secdojo.local` |
| Q10 | D, supprimer le SPN |
| Q11 | `3d9b71a6e24547d2a0f1c06e0b6c91df` |
| Q12 | `Domain Admins` |
| Q13 | `RH` |
| Q14 | A |
| Q15 | `7c2a1f89b5e04332a9d38b2a16d812e1` |
| Q16 | `Remote Desktop Users` |
| Q17 | B, `SeRemoteInteractiveLogonRight` |
| Q18 | `svc_sql` |
| Q19 | B |
| Q20 | A, Kerberoasting |
| Q21 | `e3b0c44298fc1c149afbf4c8996fb924` |

## 8. Points à retenir

- **AS-REP Roasting :** tout compte avec `DONT_REQ_PREAUTH` permet d'obtenir un hash cassable hors ligne sans identifiants. Ce paramètre doit rester désactivé (pré-authentification obligatoire).
- **Kerberoasting :** un compte avec un SPN expose un TGS chiffré avec son mot de passe. Supprimer les SPN inutiles, utiliser des mots de passe longs et aléatoires ou des gMSA.
- **Moindre privilège :** aucun compte métier (`RH`) ne doit appartenir à `Domain Admins`. Auditer régulièrement l'appartenance aux groupes privilégiés.
- **RDP sur les contrôleurs de domaine :** à limiter aux administrateurs. Un compte de service ne doit jamais y avoir accès. Vérifier aussi le droit `SeRemoteInteractiveLogonRight` dans les GPO, pas seulement les groupes.
- **Outil de travail :** sous UAC, l'erreur « Insufficient access rights » peut venir d'une console non élevée. Vérifier le niveau d'intégrité avec `whoami /groups`.

## Références

- Attribut `userAccountControl` — flag `DONT_REQ_PREAUTH` (`0x400000`)
- Droit utilisateur Windows **`SeRemoteInteractiveLogonRight`**
- Technique MITRE ATT&CK **T1558.004** — AS-REP Roasting
- Technique MITRE ATT&CK **T1558.003** — Kerberoasting
