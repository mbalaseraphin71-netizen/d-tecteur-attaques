#  CyberSentinel : Analyseur de Logs & Détecteur d'Attaques Multi-Logs

##  Description
**CyberSentinel** est une application web de cybersécurité développée en Python permettant d'analyser des fichiers de logs (serveurs, SSH) pour détecter des activités suspectes en temps réel. L'outil automatise la détection de menaces courantes (Brute Force, élévation de privilèges) et génère des rapports de sécurité professionnels exportables au format PDF.

Ce projet s'inscrit dans le cadre de la validation des compétences pratiques de niveau **Ingénieur Cybersécurité - Étape L1**.

---

## Fonctionnalités Opérationnelles (Version L1)

### Analyse de Sécurité & Heuristique
* **Détection de Brute Force SSH** : Identification automatique des adresses IP effectuant des tentatives répétées d'accès infructueuses.
* **Extraction de Profils** : Filtrage et isolation des tentatives de connexion via des utilisateurs invalides ou inconnus.
* **Alerte d'Élévation de Privilèges** : Surveillance critique des accès réussis en tant qu'utilisateur `root`.

### Gestion de Blacklist (Nouveauté L1)
* **Contrôle de Réputation** : Confrontation des adresses IP extraites avec une liste noire de serveurs malveillants connus (`blacklist.txt`).
* **Marquage des Menaces** : Signalement instantané des machines déjà répertoriées dans le système de surveillance.

###  Interface Web Moderne (Streamlit)
* **Tableau de Bord Intuitif** : Visualisation claire via des indicateurs de performance (cartes de score dynamiques).
* **Analyse Multi-Logs** : Zone de dépôt de fichiers (*Drag & Drop*) supportant le traitement simultané de plusieurs fichiers `.log` ou `.txt`.

### Rapports Automatisés
* **Génération PDF Native** : Export en un clic d'un rapport d'incident structuré et épuré.
* **Indicateurs de Risque** : Classification automatisée des adresses IP suspectes par niveau de menace (SUSPECT / DANGER-ATTAQUE).

---

## Logique de Détection & Seils

* **Seuil d'Alerte Brute Force** : Déclenché à partir de $\ge 3$ tentatives de connexion échouées (`failed password`).
* **Analyse Lexicale** : Isolation des connexions via des comptes non enregistrés grâce au mot-clé `invalid user`.
* **Analyse Syntaxique** : Extraction de précision des adresses IPv4 par expressions régulières (Regex).

---

## Technologies Utilisées

* **Langage principal** : Python 3.14+
* **Framework Web UI** : Streamlit (Architecture Cloud & Locale)
* **Moteur PDF** : fpdf2 (Génération de rapports sécurisés sans crash d'encodage)
* **Traitement de données** : Module natif `re` (Expressions Régulières Python)

---

## Installation et Lancement en Local

### 1. Clonage du projet
```bash
git clone https://github.com
cd CyberSentinel
```

### 2. Installation des dépendances
Installez les bibliothèques requises listées dans le fichier de configuration :
```bash
pip install -r requirements.txt
```

### 3. Exécution de l'application
Lancez le serveur local Streamlit via l'interpréteur Python :
```bash
python -m streamlit run Detecteur_Web.py
```

---

## Feuille de Route du Projet (Roadmap)

* [x] **Étape L1 (Actuelle)** : Stabilisation du code web, intégration de la logique de blacklist locale, génération de rapports PDF robustes (fpdf2) et déploiement Streamlit Cloud.
* [ ] **Étape L2** : Implémentation d'un module d'authentification sécurisé, base de données relationnelle pour l'historique des alertes et connexion à des API de Threat Intelligence.
* [ ] **Étape L3** : Conteneurisation (Docker), monitoring réseau en temps réel et détection d'anomalies par apprentissage automatique (IA Sécurité).

---
*Développé avec rigueur par **Séraphin Mbala** | Profil Ingénieur Cybersécurité © 2026*
