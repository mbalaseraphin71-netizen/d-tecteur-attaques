#  AfriKore Security  
### African Cyber Defense Framework & SIEM Engine

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red)
![Status](https://img.shields.io/badge/Status-Active%20Development-green)
![Security](https://img.shields.io/badge/Cybersecurity-SIEM-black)
![License](https://img.shields.io/badge/License-Academic-lightgrey)

---

# 🇫🇷 Version Française

##  Présentation

AfriKore Security est un framework de cybersécurité et un système SIEM développé en Python.

Il est conçu pour analyser des logs système en temps réel et détecter des attaques dans des environnements critiques ou hors-ligne.

---

##  Fonctionnalités

- Détection brute force SSH
- Analyse des logs système
- Détection d’utilisateurs invalides
- Surveillance des accès root
- Score de risque des adresses IP
- Blacklist locale automatique
- Génération de rapports PDF
- Dashboard interactif (Streamlit)

---

##  Architecture

- Parser basé sur regex optimisées
- Validation réseau IPv4 / IPv6
- Détection via fenêtre glissante (60s)
- Moteur de réputation IP (O(1))
- Reporting PDF via fpdf2

---

##  Installation

```bash
git clone https://github.com/your-repo/afrikore-security
cd AfriKore-Security

pip install -r requirements.txt
streamlit run app.py
 Roadmap
L1 : parsing logs + blacklist
L2 : SIEM complet + dashboard
L3 : base de données + authentification
L4 : threat intelligence API
L5 : SOAR automatisé


---
## 🇬🇧 English Version
 ##  Overview

 AfriKore Security is a Python-based cybersecurity framework and SIEM system designed for real-time log analysis and threat detection.

It works in offline and critical environments (air-gapped systems).

 ##  Features
SSH brute-force detection
System log analysis
Invalid user detection
Root access monitoring
IP risk scoring engine
Automatic blacklist system
PDF incident reporting
Interactive Streamlit dashboard
 ##  Architecture
Regex-based parsing engine
IPv4 / IPv6 validation layer
Sliding window detection (60s)
IP reputation engine (O(1))
PDF reporting via fpdf2
##  Installation
git clone https://github.com/your-repo/afrikore-security
cd AfriKore-Security

pip install -r requirements.txt
streamlit run app.py
 Roadmap
L1: log parsing + blacklist
L2: full SIEM dashboard
L3: database + RBAC
L4: threat intelligence APIs
L5: SOAR automation
##  Author

Séraphin Mbala
Cybersecurity Engineering Path
© 2026
