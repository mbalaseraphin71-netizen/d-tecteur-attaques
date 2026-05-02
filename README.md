# Détecteur d’Attaques SSH (Python + Interface Graphique)
##  Description
Ce projet est un outil d’analyse de logs SSH permettant de détecter des activités suspectes telles que des tentatives de brute force, l’utilisation d’utilisateurs inconnus et des connexions root.

Développé en Python, il intègre une interface graphique (Tkinter) facilitant l’analyse de plusieurs fichiers logs et la génération automatique de rapports de sécurité au format PDF.

---

##  Fonctionnalités

###  Analyse de sécurité
- Détection des tentatives de brute force SSH (basée sur les échecs de connexion)
- Identification des utilisateurs inconnus (tentatives invalides)
- Détection des connexions root acceptées (potentiellement critiques)

###  Gestion multi-fichiers
- Importation de plusieurs fichiers logs (.log, .txt)
- Analyse simultanée de plusieurs sources

###  Interface graphique (GUI)
- Sélection de fichiers via interface
- Affichage des résultats en temps réel
- Interface simple et intuitive

### Génération de rapports
- Export automatique en PDF
- Rapport structuré avec :
- Statut des IP (SÉCURISÉ / DANGER-ATTAQUE)
- Liste des activités suspectes
- Résumé des connexions root

---

## Logique de détection

- Une adresse IP est considérée comme suspecte si elle effectue plusieurs tentatives échouées ("failed")
- Détection des utilisateurs inconnus via le mot-clé "invalid"
- Extraction automatique des adresses IP avec expressions régulières (regex)
- Seuil de détection brute force : ≥ 3 tentatives

---

##  Technologies utilisées

- Python 3
- Tkinter (interface graphique)
- FPDF (génération de rapports PDF)
- Regex (analyse de logs)

---

## Installation

1. Cloner le projet :
```bash
git clone https://github.com/ton-username/detecteur-attaques.git
