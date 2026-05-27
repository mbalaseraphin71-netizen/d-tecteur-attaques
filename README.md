#  AfriKore Security : African Cyber Defense Framework & Log Analyzer

<p align="center">
  <img src="https://shields.io" alt="Python Version">
  <img src="https://shields.io" alt="Streamlit">
  <img src="https://shields.io" alt="Security Level">
  <img src="https://shields.io" alt="Sovereign Infrastructure">
</p>

---

##  Version Française / French Version

###  Présentation du Projet
**AfriKore Security** (anciennement CyberSentinel) est une application web de cybersécurité industrielle développée en Python. Elle permet d'analyser des fichiers de logs (serveurs, authentification SSH standard comme `auth.log`) pour détecter des activités malveillantes et des indicateurs de compromission (IoC) en temps réel. L'outil automatise la détection des menaces courantes, centralise les informations critiques et génère des rapports de sécurité professionnels exportables au format PDF.

Ce projet s'inscrit dans le cadre de la validation des compétences pratiques et de la construction du portfolio de niveau **Ingénieur Cybersécurité - Étape L1**, avec une vision stratégique s'étendant jusqu'en **L5**.

### Fonctionnalités Opérationnelles (Version L1 Complète)

#### 1. Analyse de Sécurité & Heuristique
*   **Détection de Brute Force SSH** : Identification automatique des adresses IP effectuant des tentatives répétées et infructueuses d'accès au serveur (`failed password`).
*   **Extraction et Filtrage de Profils** : Isolation immédiate des tentatives de connexion via des utilisateurs invalides ou inconnus du système (`invalid user`).
*   **Alerte d'Élévation de Privilèges** : Surveillance critique et mise en avant de tous les accès réussis en tant qu'utilisateur `root` (`accepted password for root`).

#### 2. Gestion de Blacklist Dynamique
*   **Contrôle de Réputation** : Confrontation automatique et instantanée des adresses IP extraites avec une liste noire locale de serveurs malveillants connus (`blacklist.txt`).
*   **Marquage des Menaces** : Signalement visuel immédiat dans l'interface des machines déjà répertoriées dans le système de surveillance comme dangereuses.

#### 3. Interface Web Moderne (Streamlit)
*   **Tableau de Bord Intuitif** : Visualisation claire de la santé du système via des indicateurs de performance en temps réel (cartes de score / *st.metric* dynamiques).
*   **Analyse Multi-Logs simultanée** : Zone de dépôt de fichiers (*Drag & Drop*) supportant le traitement et le parsing en parallèle de plusieurs fichiers `.log` ou `.txt`.

#### 4. Reporting Automatisé de Conformité
*   **Génération PDF Native** : Exportation sécurisée en un clic d'un rapport d'incident complet, structuré et épuré.
*   **Classification des Risques** : Marquage automatisé des adresses IP suspectes par niveau de menace directe (SUSPECT pour les anomalies légères / DANGER-ATTAQUE pour les cyberattaques avérées).

### Logique de Détection & Seuils
*   **Seuil d'Alerte Brute Force** : Déclenché automatiquement à partir de $\ge 3$ tentatives de connexion échouées sur une même adresse IP.
*   **Analyse Lexicale** : Isolation des connexions via des comptes non enregistrés grâce aux mots-clés système standardisés.
*   **Analyse Syntaxique** : Extraction de haute précision des adresses IPv4 via l'utilisation d'expressions régulières (Regex) natives sous Python.

### Technologies Utilisées
*   **Langage principal** : Python 3.14+
*   **Framework Web UI** : Streamlit (Architecture Cloud & Exécution Locale)
*   **Moteur PDF Core** : fpdf2 (Génération de rapports professionnels sans crash d'encodage de caractères)
*   **Traitement de données** : Module natif `re` (Expressions Régulières) et gestion de flux de fichiers locaux (`os`).

### Installation et Lancement en Local
1. **Clonage du projet** :
   ```bash
   git clone https://github.com
   cd AfriKore-Security
   ```
2. **Installation des dépendances** :
   ```bash
   pip install -r requirements.txt
   ```
3. **Exécution de l'application** :
   ```bash
   python -m streamlit run Detecteur_Web.py
   ```

---

## 🇬🇧 English Version / Version Anglaise

###  Project Overview
**AfriKore Security** (formerly CyberSentinel) is an enterprise-grade cybersecurity web application engineered in Python. It parses and analyzes critical network and server authentication logs (such as standard SSH `auth.log` dumps) to detect suspicious behaviors and Indicators of Compromise (IoC) in real time. The engine automates the discovery of common infrastructure threats, centralizes security alerts, and generates downloadable PDF compliance reports.

This repository serves as a practical software engineering validation for **Cybersecurity & Sovereign Digital Infrastructure - Level L1**, with a strategic scaling roadmap built up to **L5**.

### Core Features (Complete L1 Operational Version)

#### 1. Threat Intelligence & Heuristic Analysis
*   **SSH Brute Force Detection**: Automatic extraction and monitoring of source IPv4 addresses attempting repetitive failed authentications (`failed password`).
*   **Invalid Profiling Filtering**: Automated isolation and mapping of connections originating from unregistered or illegal usernames (`invalid user`).
*   **Privilege Escalation Monitoring**: Critical tracking, filtering, and logging of all successful `root` access logs (`accepted password for root`).

#### 2. Dynamic Blacklist & Reputation Management
*   **Reputation Control Engine**: Real-time cross-referencing of extracted log IPs against a localized threat intelligence blacklist file (`blacklist.txt`).
*   **Threat Tagging**: Instant marking and flagging of dangerous host machines already cataloged within the monitoring infrastructure.

#### 3. Responsive Web UI (Streamlit)
*   **Executive Dashboard**: High-level system health metrics displayed via clean, color-coded, and interactive scorecards (*st.metric* flags).
*   **Concurrent Multi-Log Processing**: High-performance Drag & Drop upload container supporting parallel parsing of multiple `.log` or `.txt` file structures.

#### 4. Automated Compliance & Incident Reporting
*   **Native PDF Generator**: One-click generation and immediate download of clean, production-ready incident response reports.
*   **Risk Classification Matrix**: Automated tagging of suspicious machines by calculated threat levels (SUSPECT for minor anomalies / DANGER-ATTACK for confirmed intrusions).

###  Detection Thresholds & Parsing Logic
*   **Brute Force Threshold**: Triggered automatically when an individual IP matches $\ge 3$ failed password attempts.
*   **Syntax & Parsing Rules**: High-fidelity IPv4 token extraction built entirely on native Regular Expressions (`re` module).
*   **Sovereign Infrastructure Execution**: Configured to run in air-gapped networks, securing logs locally without leaking structural information to external clouds.

### Technology Stack
*   **Language**: Python 3.14+
*   **Framework UI**: Streamlit (Cloud & Local Server Architecture)
*   **PDF Core Engine**: fpdf2 (Robust corporate reporting without character encoding overhead)
*   **Data Processing**: Native Python Regular Expressions (`re`) and local file-system handlers (`os`).

###  Installation & Local Deployment
1. **Clone the repository** :
   ```bash
   git clone https://github.com
   cd AfriKore-Security
   ```
2. **Install corporate packages** :
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the local server application** :
   ```bash
   python -m streamlit run Detecteur_Web.py
   ```

---

##  Strategic Venture Roadmap (L1 to L5 Enterprise Goal)

*   [x] **Phase L1 (Current / Actuelle)**: Core parsing engine stabilization, dynamic local blacklisting, clean bicultural code documentation, and active Streamlit Community Cloud deployment. / *Stabilisation du code web, intégration de la logique de blacklist dynamique locale, documentation bilingue complète et déploiement cloud.*
*   [ ] **Phase L2**: Implementation of a cryptographically secure user authentication module (RBAC), relational database (PostgreSQL/SQLite) logging history, and automated threat intelligence API hooks (VirusTotal). / *Module d'authentification sécurisé des utilisateurs, base de données relationnelle pour l'historique et connexion aux API de Threat Intelligence.*
*   [ ] **Phase L3**: Software environment containerization via Docker, cloud deployment orchestration, live packet monitoring (real-time network traffic sniffing), and ML-driven network anomaly detection. / *Conteneurisation complète avec Docker, monitoring réseau passif en temps réel et détection des anomalies par Intelligence Artificielle.*
*   [ ] **Phase L4 - L5**: Enterprise scaling, testing with beta users, infrastructure deployment on sovereign African servers, and full commercialization of the **AfriKore Security Suite** (SaaS model for SME protection). / *Déploiement sur des serveurs souverains africains, audits d'infrastructure réels, modèle économique par abonnement et création officielle de l'entreprise.*

---
*« Protect Content, Empower Sovereign Infrastructure »*  
**Engineered with absolute rigor by Séraphin Mbala** | Future Cybersecurity Engineer & Tech Entrepreneur © 2026
