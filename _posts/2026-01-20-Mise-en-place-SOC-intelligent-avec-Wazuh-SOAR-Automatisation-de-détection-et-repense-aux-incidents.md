---
layout: single
header:
  overlay_image: /assets/images/banner-014.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
title: "Mise en place d'un SOC intelligent avec Wazuh + SOAR"
date: 2026-10-13
categories: [SOC, Projet]
tags: [wazuh, shuffle, soar, siem, active-response, mitre-attck, docker, hydra, brute-force, pfe]
---

# Mise en place d'un SOC intelligent avec Wazuh + SOAR

> **Sous-titre :** Automatisation de détection et réponse aux incidents
> **Auteur :** BERRAHAL Mohammed
> **Type :** Projet de fin d'études (PFE)


## Résumé

Face à l'évolution des cybermenaces, les entreprises doivent adopter des solutions de sécurité automatisées. Ce mémoire présente la conception d'un **Security Operations Center (SOC)** automatisé utilisant des technologies open source pour une détection et une réponse en temps réel aux incidents.

L'architecture intègre **Wazuh** (SIEM) et **Shuffle** (SOAR), créant une chaîne de traitement automatisé des incidents. Ce travail démontre la viabilité d'un SOC automatisé open source dans le contexte marocain, prouvant que les contraintes locales peuvent être surmontées par une architecture bien pensée.

## Introduction

Les infrastructures informatiques modernes font face à des menaces de plus en plus sophistiquées. Les cyberattaques ne sont plus des actes isolés, mais s'inscrivent dans des stratégies organisées menées par des cybercriminels, des groupes étatiques ou des hacktivistes. Les solutions de sécurité traditionnelles ne suffisent plus : les entreprises doivent adopter une approche proactive et automatisée.

Ce projet propose la mise en place d'un SOC automatisé fondé sur des technologies open source : **Wazuh** et **Shuffle**.

Les rapports récents montrent une hausse significative des incidents touchant des secteurs critiques (santé, finance, télécommunications). Les ransomwares, DDoS, phishing avancé, exploitation de vulnérabilités zero-day et mouvements latéraux mettent gravement en danger la confidentialité, l'intégrité et la disponibilité des systèmes.

Au-delà des pertes financières, ces menaces provoquent des perturbations opérationnelles, une dégradation d'image et une perte de confiance des partenaires. **Il ne suffit plus de réagir après une compromission ; il est indispensable de détecter les menaces dès leurs premiers signes.**

## Chapitre 1 : Cadre théorique

### 1.1 Introduction

Le paysage de la cybersécurité a connu une transformation profonde. Les menaces se sont multipliées et sophistiquées, obligeant les entreprises à repenser leur approche de la sécurité informatique.

### 1.2 Contexte

**A. Évolution des cybermenaces**
Au cours de la dernière décennie, les attaques sont devenues plus fréquentes, plus ciblées et plus dévastatrices : ransomwares, DDoS, phishing sophistiqué, exploitation zero-day.

**B. Nécessité d'une surveillance continue**
La complexité croissante des infrastructures IT rend la surveillance manuelle inefficace. Une surveillance continue 24/7, capable de corréler des événements hétérogènes et de détecter des anomalies en temps réel, est devenue indispensable.

**C. Émergence des SOC**
Un SOC est une unité centralisée chargée de surveiller, détecter, analyser et répondre aux incidents de sécurité. Les SOC traditionnels présentent cependant plusieurs défis : coûts élevés, nécessité de personnel qualifié en permanence, complexité de gestion des alertes, risque de fatigue des analystes.

**D. Tendance à l'automatisation**
L'automatisation permet de réduire le temps de réponse aux incidents et de traiter un volume important d'alertes de manière cohérente. Les plateformes SOAR orchestrent et automatisent les workflows de sécurité, **sans remplacer l'humain mais en l'assistant efficacement**.

### 1.3 Problématique

**A. Challenges de la détection et de la réponse**
Volume massif d'alertes quotidiennes, pénurie de compétences en cybersécurité, complexité technique des infrastructures modernes. Le phénomène **"alert fatigue"** conduit à l'épuisement des analystes et au risque de manquer des alertes critiques.

**B. Limites des approches manuelles**
Chaque minute compte lors d'une attaque. Le traitement manuel implique des étapes chronophages, une incohérence des actions entre analystes, et une documentation souvent négligée dans l'urgence.

### 1.4 Intérêts du sujet

**Pour les entreprises :** solution pragmatique renforçant la sécurité tout en optimisant les ressources ; réduction drastique des délais de réponse ; disponibilité 24/7 ; architecture modulaire évolutive.

**Pour le domaine académique :** contribution à la littérature sur les SOC automatisés, méthodologie structurée de conception/implémentation/évaluation, validation expérimentale avec métriques précises.

## Chapitre 2 : État de l'art et analyse des solutions

### 2.1 Fondements des systèmes d'information de sécurité

#### 2.1.1 Rappel sur les systèmes d'information

Un système d'information (SI) est un ensemble organisé de ressources (matérielles, logicielles, humaines, données, procédures) permettant de collecter, stocker, traiter et diffuser l'information. La sécurité d'un SI repose sur trois piliers, l'acronyme **CIA** :

| Pilier | Définition |
| --- | --- |
| Confidentialité | Garantir que seules les personnes autorisées peuvent accéder à l'information |
| Intégrité | Assurer que les données ne sont pas altérées de manière non autorisée |
| Disponibilité | S'assurer que les ressources sont accessibles aux utilisateurs légitimes quand ils en ont besoin |

Deux approches complémentaires coexistent dans la gestion des SI :

| Approche | Principe | Exemple |
| --- | --- | --- |
| Déclarative | Définir "ce que l'on veut" obtenir | "Tous les systèmes doivent être à jour" |
| Impérative | Définir "comment faire" | "Si alerte niveau 10 → créer un cas → enrichir avec VirusTotal → notifier via Slack" |

Le SOC automatisé de ce projet combine les deux :

- **Déclarative dans Wazuh** : définition des menaces à détecter via des règles.
- **Impérative dans Shuffle** : définition des actions à exécuter automatiquement.

#### 2.1.2 Évolution vers les SOC

Face à la sophistication croissante des cybermenaces, les approches traditionnelles (pare-feu, antivirus) se sont révélées insuffisantes. Un SOC combine ressources humaines (analystes), processus (playbooks) et technologies (SIEM, SOAR, IDS/IPS).

#### 2.1.3 Architecture SOC et niveaux opérationnels

Un SOC moderne s'organise selon trois niveaux opérationnels, permettant une escalade progressive des incidents.

| Niveau | Rôle | Compétences requises |
| --- | --- | --- |
| **L1** — Triage et surveillance | Surveillance 24/7, triage initial, gestion des incidents de routine via playbooks, escalade vers L2 | Connaissances générales en sécurité, capacité à suivre des procédures |
| **L2** — Investigation approfondie | Analyse forensique, extraction d'IOCs, coordination avec les équipes IT, documentation et recommandations | Expertise forensique, connaissance des techniques d'attaque |
| **L3** — Threat hunting et expertise avancée | Threat hunting proactif, analyse de malwares, développement de règles de détection, veille, mentorat | Reverse engineering, amélioration continue des processus |

**Dans l'architecture automatisée, Shuffle remplace une grande partie du travail L1 :**

- Triage automatique basé sur le niveau de sévérité (règle : niveau ≥ 10)
- Classification automatique selon le type d'attaque détecté
- Exécution automatique des premières actions de réponse

Les analystes L1 se concentrent alors sur la vérification des alertes escaladées, la validation des actions automatiques et la gestion des cas atypiques.

#### 2.1.4 Normes et cadres de référence

L'architecture s'aligne avec **ISO/IEC 27001**, norme internationale de référence pour la gestion de la sécurité de l'information (SMSI), définissant les exigences pour établir, mettre en œuvre, maintenir et améliorer continuellement un SMSI.

### 2.2 Solutions open source

#### 2.2.1 Tableau comparatif

**A. Solutions SIEM open source**

| Solution | Points forts | Points faibles | Cas d'usage idéal |
| --- | --- | --- | --- |
| **Wazuh** | Intégration XDR, gestion des agents simple, conformité (PCI DSS, GDPR), très actif | Consommation ressources agents, complexité de configuration avancée | PME et grandes entreprises cherchant une solution tout-en-un |
| ELK / OpenSearch | Flexibilité totale, immense communauté, visualisations puissantes | Pas un SIEM "out-of-the-box", nécessite beaucoup de tuning | Équipes avec de fortes compétences en ingénierie de données |
| Graylog | Excellente gestion des logs, recherche rapide, moins gourmand en stockage que ELK | Version open source limitée par rapport à l'Enterprise | Analyse de logs pure et monitoring de performance |
| Security Onion | Suite complète (IDS, NSM, SIEM), prêt à l'emploi pour le réseau | Courbe d'apprentissage abrupte, lourd à faire tourner | Monitoring réseau profond et SOC complet |
| OSSIM | Intègre de nombreux outils (OpenVAS, Snort), interface unifiée | Version open source vieillissante, moins de mises à jour que Wazuh | Petites structures voulant une visibilité rapide |

> **Conclusion de l'évaluation :** Wazuh a été retenu comme offrant le meilleur compromis entre richesse fonctionnelle, facilité de déploiement et qualité des intégrations.

**B. Solutions SOAR open source**

| Solution | Points forts | Points faibles | Cas d'usage idéal |
| --- | --- | --- | --- |
| **Shuffle** | Interface intuitive (workflow), centaines d'intégrations, très moderne | Communauté plus petite que TheHive, encore en pleine croissance | Automatisation moderne et rapide des workflows SOC |
| StackStorm | Automatisation robuste basée sur les événements, très stable | Courbe d'apprentissage technique (YAML/Python), pas orienté "sécurité" nativement | Automatisation d'infrastructure et de sécurité complexe |
| n8n | Low-code, extrêmement simple à prendre en main, polyvalent | Moins de focus sur les protocoles de sécurité spécifiques | Automatisation de tâches répétitives simples |

> **Conclusion de l'évaluation :** Shuffle s'est démarqué par son interface intuitive et ses 500+ applications préconfigurées.

#### 2.2.2 Wazuh — Solution SIEM

Wazuh centralise tous les événements de sécurité via trois composants Docker :

| Composant | Rôle |
| --- | --- |
| Manager | Reçoit les logs et applique les règles de corrélation |
| Indexer (OpenSearch) | Stocke et indexe les événements |
| Dashboard | Visualisation en temps réel |

Les agents Wazuh, légers et multiplateformes, collectent les logs système, surveillent l'intégrité des fichiers, détectent les rootkits et maintiennent un inventaire du matériel. La communication avec le Manager est chiffrée via AES.

Wazuh intègre plus de **3000 règles de détection** prêtes à l'emploi (brute force, exploitation de vulnérabilités, malwares, attaques web, mouvements latéraux), organisées par niveaux de sévérité de 0 à 15, chacune mappée au framework **MITRE ATT&CK**. La configuration du projet déclenche l'automatisation Shuffle pour les alertes de niveau ≥ 10.

L'API REST sur le port **55000** permet la gestion programmatique complète. L'intégration avec Shuffle utilise un webhook HTTP configuré dans `ossec.conf`, envoyant automatiquement chaque alerte critique en format JSON vers Shuffle.

#### 2.2.3 Shuffle — Plateforme SOAR

Shuffle automatise les workflows de réponse aux incidents via quatre conteneurs Docker :

| Composant | Rôle |
| --- | --- |
| Frontend (React) | Interface web avec éditeur drag-and-drop |
| Backend (Go) | API REST et gestion des workflows |
| Orborus | Exécution isolée des actions |
| OpenSearch | Stockage des métadonnées |

La bibliothèque contient plus de **500 apps préconfigurées**, incluant TheHive, MISP, VirusTotal et Slack. Les webhooks génèrent une URL unique permettant de recevoir des données JSON et de déclencher instantanément les workflows.

## Chapitre 3 : Réalisation de la solution proposée

### 3.1 Schéma de l'architecture physique

<p align="center"><a href="/assets/images/01-architecture-globale.png"><img src="/assets/images/01-architecture-globale.png"></a></p>

L'attaquant (Kali Linux) cible l'endpoint Windows 10 équipé de l'agent Wazuh. Les logs et alertes remontent vers le SIEM (Ubuntu-Wazuh), qui transmet les événements de sécurité au SOAR (Ubuntu-Shuffle) via webhook. Shuffle déclenche en retour une réponse automatisée (API/script) vers l'endpoint.

<p align="center"><a href="/assets/images/02-workflow-detection-reponse.png"><img src="/assets/images/02-workflow-detection-reponse.png"></a></p>

Ce second schéma détaille les 5 étapes du workflow : attaque → détection → alerte → enrichissement (VirusTotal) → réponse automatisée.

### 3.2 Configuration de l'environnement VMware

| Machine virtuelle | OS | Adresse IP | RAM | Stockage | Rôle stratégique |
| --- | --- | --- | --- | --- | --- |
| Windows 10 | Windows 10 | `192.168.223.128` | 1 Go | 16 Go | Cible / Endpoint — surveillée via l'agent Wazuh |
| Ubuntu-Wazuh | Ubuntu | `192.168.223.129` | 6 Go | 35 Go | SIEM / XDR — analyse des logs, corrélation, alertes |
| Ubuntu-Shuffle | Ubuntu | `192.168.223.130` | 5 Go | 25 Go | SOAR — orchestration et exécution des playbooks |
| Kali Linux | Kali Linux | `192.168.223.131` | 1,5 Go | 20 Go | Attaquant — simulation de menaces réelles |

### 3.3 Installation de Wazuh

**Préparation système :**

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget gnupg apt-transport-https unzip jq
```

**Installation officielle, stable :**

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
chmod +x wazuh-install.sh
sudo ./wazuh-install.sh -a
```
<p align="center"><a href="/assets/images/03-wazuh-install-log.png"><img src="/assets/images/03-wazuh-install-log.png"></a></p>

> ℹ️ À la fin de l'installation, le script affiche aussi les identifiants du compte `admin` du Dashboard (nom d'utilisateur et mot de passe généré). Ce mot de passe a été retiré de la capture ci-dessus avant publication.

**Accès au Dashboard :**

```text
https://192.168.223.129
```
<p align="center"><a href="/assets/images/04-wazuh-login-page.png"><img src="/assets/images/04-wazuh-login-page.png"></a></p>

<p align="center"><a href="/assets/images/05-wazuh-dashboard-overview.png"><img src="/assets/images/05-wazuh-dashboard-overview.png"></a></p>

**Déploiement de l'agent sur Windows 10 :**

<p align="center"><a href="/assets/images/06-wazuh-add-agent-wizard.png"><img src="/assets/images/06-wazuh-add-agent-wizard.png"></a></p>

L'assistant du Dashboard génère automatiquement la commande PowerShell d'installation, avec l'adresse du Manager déjà renseignée :

<p align="center"><a href="/assets/images/07-wazuh-agent-install-command.png"><img src="/assets/images/07-wazuh-agent-install-command.png"></a></p>

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile ${env:tmp}\wazuh-agent; msiexec.exe /i ${env:tmp}\wazuh-agent /q WAZUH_MANAGER='192.168.223.129' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='windows10' WAZUH_REGISTRATION_SERVER='192.168.223.129'
NET START WazuhSvc
```
<p align="center"><a href="/assets/images/08-wazuh-agent-powershell-success.png"><img src="/assets/images/08-wazuh-agent-powershell-success.png"></a></p>

### 3.4 Installation de Shuffle (SOAR)

**Mise à jour des paquets, installation de Docker et Docker Compose :**

```bash
sudo apt update && sudo apt install -y docker.io docker-compose
```

**Activation et démarrage du service Docker :**

```bash
sudo systemctl enable docker && sudo systemctl start docker
```

**Téléchargement du code source de Shuffle depuis GitHub :**

```bash
git clone https://github.com/Shuffle/Shuffle.git
cd Shuffle
```

**Accès au Dashboard :**

```text
https://192.168.223.130:3443
```

<p align="center"><a href="/assets/images/09-shuffle-login-page.png"><img src="/assets/images/09-shuffle-login-page.png"></a></p>

**Création du flux de travail :**

1. Créer un compte, s'inscrire et se connecter.
2. *Flux de travail* → *Nouveau flux de travail*, nommé **"laboratoire d'automatisation SOC"**.
3. Sélectionner un cas d'utilisation et valider.
4. Ajouter un déclencheur **Webhook**, nommé "Wazuh-alerte", et copier son URL.

<p align="center"><a href="/assets/images/10-shuffle-workflow-overview.png"><img src="/assets/images/10-shuffle-workflow-overview.png"></a></p>

Le nœud intermédiaire ("Change Me") exécute un petit script Python qui extrait l'adresse IP source de l'alerte JSON reçue :

<p align="center"><a href="/assets/images/11-shuffle-change-me-node.png"><img src="/assets/images/11-shuffle-change-me-node.png"></a></p>

**Intégration VirusTotal :**

1. Créer une clé API sur [virustotal.com](https://www.virustotal.com).
2. Dans Shuffle, rechercher l'app **VirusTotal**, l'activer et la glisser dans le workflow.
3. Configurer l'action VirusTotal (*Get an ip address report*) avec la clé API en authentification.

<p align="center"><a href="/assets/images/12-shuffle-virustotal-node-config.png"><img src="/assets/images/12-shuffle-virustotal-node-config.png"></a></p>

> ⚠️ **Non inclus :** la capture de la page "Ma clé API" de VirusTotal a été volontairement exclue de ces notes, car elle affiche une clé API réelle en clair ainsi que le nom du compte associé. Les clés API ne doivent jamais être publiées, même par capture d'écran.

**Configuration de Wazuh pour la connexion avec Shuffle :**

```bash
sudo nano /var/ossec/etc/ossec.conf
```

<p align="center"><a href="/assets/images/13-ossec-conf-integration.png"><img src="/assets/images/13-ossec-conf-integration.png"></a></p>

```xml
<integration>
    <name>shuffle</name>
    <hook_url>http://<SHUFFLE_IP>:3443/api/v1/hooks/webhook_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
</integration>
```

> ⚠️ **Point d'attention :** respecter l'indentation du fichier de configuration (espaces, pas de tabulations). L'URL ci-dessus est anonymisée — remplace-la par celle de ta propre instance si tu republies cette configuration.

**Redémarrage de Wazuh :**

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

## Chapitre 4 : Scénarios d'attaque et analyse des résultats

### 4.1 Lancement de l'attaque SMB Brute Force

Depuis la machine Kali Linux (`192.168.223.131`), lancement d'une attaque SMB brute force ciblant Windows 10 (`192.168.223.128`), avec désactivation préalable du pare-feu Windows (pour les besoins du test).

```bash
echo "=== Lancement de l'attaque brute force SMB ==="
hydra -L users.txt -P passwords.txt 192.168.223.128 smb -V -t 1
```

<p align="center"><a href="/assets/images/18-hydra-smb-bruteforce-launch.png"><img src="/assets/images/18-hydra-smb-bruteforce-launch.png"></a></p>

### 4.2 Analyse des résultats

Dès la détection de l'attaque brute force, le mécanisme **Wazuh Active Response** se déclenche automatiquement et bloque l'adresse IP source.

<p align="center"><a href="/assets/images/14-wazuh-dashboard-after-attack.png"><img src="/assets/images/14-wazuh-dashboard-after-attack.png"></a></p>

<p align="center"><a href="/assets/images/15-wazuh-security-alerts-table.png"><img src="/assets/images/15-wazuh-security-alerts-table.png"></a></p>

Le détail JSON d'une alerte confirme l'origine de l'attaque et le protocole d'authentification ciblé (NTLM) :

<p align="center"><a href="/assets/images/16-wazuh-alert-detail-json-1.png"><img src="/assets/images/16-wazuh-alert-detail-json-1.png"></a></p>

<p align="center"><a href="/assets/images/17-wazuh-alert-detail-json-2.png"><img src="/assets/images/17-wazuh-alert-detail-json-2.png"></a></p>

Lors d'une seconde tentative d'attaque, l'IP reste bloquée — même un ping vers Windows 10 échoue :

<p align="center"><a href="/assets/images/19-ping-blocked-after-attack.png"><img src="/assets/images/19-ping-blocked-after-attack.png"></a></p>

**Détection de l'incident (Wazuh) :**

| Élément | Valeur |
| --- | --- |
| Niveau d'alerte | 10 (règle 60204 observée dans le Dashboard) |
| Technique MITRE ATT&CK | T1110 — Brute Force |
| Tactique | Credential Access |
| Cible | poste `windows10` (`192.168.223.128`) |
| Source de l'attaque | `192.168.223.131` |
| Protocole | NTLM / SMB |

**Constat :** le nombre élevé de
