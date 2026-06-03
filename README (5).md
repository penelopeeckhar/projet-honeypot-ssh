# 🍯 SSH Honeypot — ELK Stack

Honeypot SSH interactif containerisé avec détection de brute-force et centralisation des logs via la stack ELK (Elasticsearch, Logstash, Kibana).

Réalisé dans le cadre du cursus GDNC4 — ENSA Fès.

---

## 🧠 Fonctionnement

Le honeypot se présente comme un serveur SSH Ubuntu légitime sur le port `2222`. Il **accepte toutes les connexions** (password et clé publique) pour capturer les tentatives d'intrusion, enregistre chaque événement au format JSON, et les transfère en temps réel vers Elasticsearch via Logstash pour visualisation dans Kibana.

```
Attaquant → SSH :2222 → Honeypot Python (Paramiko)
                              ↓ JSON logs
                         Logstash :5044
                              ↓
                     Elasticsearch :9200
                              ↓
                        Kibana :5601
```

---

## 🔐 Sécurité du conteneur

Le conteneur honeypot est durci par plusieurs mécanismes :

- **AppArmor** : profil personnalisé (`apparmor-honeypot`) qui restreint les appels système
- **Seccomp** : profil Docker limitant les syscalls autorisés (`seccomp-profile.json`)
- **Capabilities** : toutes les capabilities Linux supprimées sauf `NET_BIND_SERVICE`

---

## 📦 Stack technique

| Composant | Rôle |
|---|---|
| Python 3 + Paramiko | Serveur SSH honeypot |
| Docker + Docker Compose | Orchestration des services |
| Elasticsearch 8.11 | Stockage et indexation des logs |
| Logstash 8.11 | Pipeline de collecte/parsing |
| Kibana 8.11 | Visualisation et dashboards |

---

## 🚀 Déploiement

### Prérequis
- Docker et Docker Compose installés
- Profil AppArmor chargé (optionnel, Linux uniquement)

### Lancement

```bash
# Cloner le repo
git clone https://github.com/penelopeeckhar/projet-honeypot-ssh.git
cd projet-honeypot-ssh

# (Optionnel) Charger le profil AppArmor
sudo apparmor_parser -r -W apparmor-honeypot

# Démarrer tous les services
docker-compose up -d --build

# Vérifier que tout tourne
docker-compose ps
```

### Accès aux interfaces

| Service | URL |
|---|---|
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 |
| Honeypot SSH | `ssh -p 2222 anyuser@localhost` |

---

## 📊 Événements capturés

Chaque événement est enregistré en JSON dans `logs/honeypot/honeypot.log` :

| Type d'événement | Description |
|---|---|
| `honeypot_started` | Démarrage du service |
| `login_attempt` | Tentative de connexion (username + password capturés) |
| `command_execution` | Commande exécutée dans le shell interactif |
| `command_result` | Résultat de la commande (limité à 500 chars) |
| `brute_force_alert` | Détection de ≥3 tentatives en 60 secondes |
| `session_closed` | Déconnexion de l'attaquant |

---

## 🗂️ Structure du projet

```
projet-honeypot-ssh/
├── honeypot/
│   ├── honeypot.py          # Serveur SSH honeypot (Paramiko)
│   ├── Dockerfile           # Image Python durcie
│   ├── requirements.txt     # Dépendances Python
│   └── seccomp-profile.json # Profil Seccomp Docker
├── logstash/
│   └── logstash.conf        # Pipeline Logstash → Elasticsearch
├── logs/
│   └── honeypot/            # Logs JSON (générés à l'exécution)
├── apparmor-honeypot        # Profil AppArmor
├── wordlist.txt             # Wordlist brute-force pour tests
└── docker-compose.yml       # Orchestration ELK + Honeypot
```

---

## DEMO

SSH Honeypot — ELK Stack : https://drive.google.com/file/d/1bp0NVej-wHShJWNiqv3pTOovaIBszkP8/view?usp=drive_link

## ⚠️ Avertissement légal

Ce projet est destiné à un usage éducatif en environnement isolé (VM/lab). Ne pas déployer sur une infrastructure de production ou exposer sur internet sans mesures de sécurité supplémentaires.
