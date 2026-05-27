# AfriKore Security : African Cyber Defense Framework & Log Analyzer

<p align="center">
  <img src="https://shields.io" alt="Python Version">
  <img src="https://shields.io" alt="Streamlit">
  <img src="https://shields.io" alt="Security Level">
  <img src="https://shields.io" alt="Sovereign Infrastructure">
</p>

---

##  Version Française

###  Présentation du Projet
**AfriKore Security** est une application web de cybersécurité automatisée développée en Python. Elle analyse les fichiers de logs réseau (comme les logs SSH) pour détecter les activités malveillantes en temps réel. L'outil automatise la détection des menaces (Force Brute, élévation de privilèges) et génère des rapports de conformité PDF téléchargeables.

Ce projet s'inscrit dans le cadre de la validation des compétences pratiques de niveau **Ingénieur Cybersécurité - Étape L1**.

###  Fonctionnalités Opérationnelles (Version L1)
*   **Analyse Heuristique & Menaces** : Extraction automatique des adresses IPv4 et blocage des tentatives d'accès répétées.
*   **Contrôle de Réputation** : Confrontation en temps réel des IP avec une liste locale de menaces (`blacklist.txt`).
*   **Tableau de Bord Streamlit** : Indicateurs de performance dynamiques et clairs via des cartes de score de couleur.
*   **Rapports PDF Automatisés** : Génération en un clic d'un rapport d'incident structuré (propulsé par `fpdf2`).

###  Logique de Détection & Seuils
*   **Alerte Brute Force** : Se déclenche automatiquement à partir de $\ge 3$ tentatives de connexion échouées (`failed password`).
*   **Analyse Syntaxique** : Extraction de précision des adresses IPv4 par expressions régulières native (`re`).

###  Installation et Lancement Local
```bash
git clone https://github.com
cd AfriKore-Security
pip install -r requirements.txt
python -m streamlit run Detecteur_Web.py
```

---

## 🇬🇧 English Version

###  Project Overview
**AfriKore Security** is an automated cybersecurity web application developed in Python. It parses and analyzes network server logs (such as SSH logs) to detect malicious activities in real time. The engine automates threat detection (Brute Force, privilege escalation) and generates production-ready, downloadable PDF security compliance reports.

This repository serves as a practical engineering validation for **Cybersecurity & Sovereign Digital Infrastructure - Level L1**.

###  Core Features (L1 Operational Version)
*   **Threat Intelligence & Heuristics**: Automatic extraction of source IPv4 addresses attempting repetitive unauthorized access.
*   **Dynamic Reputation Control**: Real-time cross-referencing of extracted IPs against a localized threat blacklist (`blacklist.txt`).
*   **Streamlit Web UI**: High-level security metrics displayed via responsive, color-coded scorecards.
*   **Compliance Reporting**: One-click generation of an incident response report without encoding errors (`fpdf2`).

###  Detection Thresholds & Logic
*   **Brute Force Threshold**: Triggered automatically when an IP matches $\ge 3$ failed password attempts.
*   **Syntax & Parsing Rules**: High-fidelity IPv4 extraction built entirely on native Regular Expressions (`re` module).

### Installation & Local Deployment
```bash
git clone https://github.com
cd AfriKore-Security
pip install -r requirements.txt
python -m streamlit run Detecteur_Web.py
```

---

##  Strategic Venture Roadmap (L1 to L5 Enterprise Goal)

*   [x] **Phase L1 (Current / Actuelle)**: Core parsing engine stabilization, dynamic local blacklisting, and production web deployment. / *Stabilisation du code web, intégration de la logique de blacklist locale et déploiement cloud.*
*   [ ] **Phase L2**: User authentication module, PostgreSQL logging history, and Threat Intelligence API hooks (VirusTotal). / *Module d'authentification sécurisé, base de données relationnelle et connexion aux API.*
*   [ ] **Phase L3**: Architecture containerization via Docker, live packet monitoring, and ML-driven network anomaly detection. / *Conteneurisation (Docker), monitoring réseau en temps réel et détection d'anomalies par IA.*
*   [ ] **Phase L4 - L5**: Enterprise scaling, deployment on sovereign African servers, infrastructure auditing, and full commercialization of the **AfriKore Security Suite**. / *Déploiement sur des serveurs souverains africains, audits d'infrastructure et création de l'entreprise.*

---
*« Protect Content, Empower Sovereign Infrastructure »*  
**Engineered with absolute rigor by Séraphin Mbala** | Future Cybersecurity Engineer © 2026
