import re
import os
import tkinter as tk
from fpdf import FPDF
from tkinter import filedialog, messagebox

# =================================================================
# 1. LOGIQUE D'ANALYSE (Cœur du programme)
# =================================================================

def lire_logs(fichier):
    """Ouvre un fichier et transforme chaque ligne en un élément de liste."""
    # errors="ignore" évite que le programme plante si le log contient des caractères bizarres
    with open(fichier, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()

def analyser_logs(logs):
    """Scanne les lignes pour compter les échecs, les inconnus et les accès root."""
    brute_force = {}
    utilisateurs_inconnus = {}
    connexions_root = []

    for ligne in logs:
        ligne_min = ligne.lower() # Met tout en minuscule pour faciliter la recherche
        
        # Regex : Cherche un motif de type 000.000.000.000 (adresse IP)
        ip_trouvee = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ligne)
        
        if ip_trouvee:
            ip = ip_trouvee.group()
            
            # Si le mot "failed" est dans la ligne, on incrémente le compteur de cette IP
            if "failed" in ligne_min:
                brute_force[ip] = brute_force.get(ip, 0) + 1
            
            # Si le mot "invalid" est présent (utilisateur n'existe pas)
            if "invalid" in ligne_min:
                utilisateurs_inconnus[ip] = utilisateurs_inconnus.get(ip, 0) + 1

        # Détection des accès root réussis (très important pour la sécurité)
        if "accepted" in ligne_min and "root" in ligne_min:
            connexions_root.append(ligne.strip())

    return brute_force, utilisateurs_inconnus, connexions_root

# =================================================================
# 2. GÉNÉRATION DU RAPPORT PDF
# =================================================================

def generer_pdf(brute_force, utilisateurs_inconnus, connexions_root, chemin_log):
    """Crée un fichier PDF structuré avec les résultats de l'analyse."""
    pdf = FPDF()
    pdf.add_page()
    
    # Configuration du Titre Principal
    pdf.set_font("Times", "B", 18)
    pdf.cell(200, 10, "RAPPORT DE SÉCURITÉ", ln=True, align="C")
    
    # Affichage du nom du fichier d'origine
    nom_pur = os.path.basename(chemin_log)
    pdf.set_font("Times", "I", 12)
    pdf.cell(200, 10, f"Fichier analysé : {nom_pur}", ln=True, align="C")
    pdf.ln(10) # Saut de ligne

    # SECTION 1 : Brute Force
    pdf.set_font("Times", "B", 14)
    pdf.cell(200, 10, "1. Tentatives de Brute Force SSH", ln=True)
    pdf.set_font("Times", size=12)
    for ip, nb in brute_force.items():
        # Définition du statut selon le seuil de 3 tentatives
        status = "DANGER-ATTAQUE" if nb >= 3 else "SÉCURISÉ"
        pdf.cell(200, 8, f"IP: {ip:15} | Tentatives: {nb} | Statut: {status}", ln=True)
    
    pdf.ln(5)

    # SECTION 2 : Utilisateurs Inconnus
    pdf.set_font("Times", "B", 14)
    pdf.cell(200, 10, "2. Utilisateurs Inconnus", ln=True)
    pdf.set_font("Times", size=12)
    for ip, nb in utilisateurs_inconnus.items():
        pdf.cell(200, 8, f"IP: {ip:15} | Tentatives: {nb} | SUSPECT", ln=True)

    pdf.ln(5)

    # SECTION 3 : Root
    pdf.set_font("Times", "B", 14)
    pdf.cell(200, 10, "3. Connexions Root Acceptées", ln=True)
    pdf.set_font("Times", "I", 10)
    for ligne in connexions_root:
        # On coupe la ligne si elle est trop longue pour le PDF (max 85 car.)
        pdf.cell(200, 8, f"> {ligne[:85]}", ln=True)

    # Enregistrement du fichier avec un nom préfixé par "rapport_"
    pdf.output(f"rapport_{nom_pur}.pdf")

# =================================================================
# 3. INTERFACE GRAPHIQUE (Fenêtres et Boutons)
# =================================================================

def afficher_aide():
    """Affiche une petite fenêtre avec les crédits de l'auteur."""
    messagebox.showinfo("À propos", 
        "DÉTECTEUR D'ATTAQUES v2.1\n\n"
        "Développé par SÉRAPHIN MBALA\n"
        "Analyseur de logs SSH multi-fichiers.\n\n"
        "© 2024 - Tous droits réservés.")

def lancer_interface():
    """Crée et gère la fenêtre principale de l'application."""
    fenetre = tk.Tk()
    fenetre.title("Détecteur d'Attaques Multi-Logs - Séraphin Mbala")
    fenetre.geometry("550x600")

    fichiers_selectionnes = [] # Contiendra la liste des chemins vers les logs choisis

    # Titre affiché dans la fenêtre
    tk.Label(fenetre, text="DÉTECTEUR D'ATTAQUES", font=("Arial", 16, "bold")).pack(pady=10)

    def choisir_fichiers():
        """Ouvre une boîte de dialogue pour sélectionner un ou plusieurs fichiers."""
        nonlocal fichiers_selectionnes
        fichiers = filedialog.askopenfilenames(filetypes=[("Logs", "*.log *.txt")])
        if fichiers:
            fichiers_selectionnes = list(fichiers)
            lbl_chemin.config(text=f"{len(fichiers_selectionnes)} fichier(s) sélectionné(s)")

    # Bouton de sélection de fichiers
    tk.Button(fenetre, text="📂 Choisir fichiers log", command=choisir_fichiers).pack(pady=5)
    lbl_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné", fg="blue")
    lbl_chemin.pack()

    # Zone de texte pour afficher les résultats en direct dans l'interface
    resultat_zone = tk.Text(fenetre, height=18, width=65)
    resultat_zone.pack(pady=10)

    def analyser_tout():
        """Lance l'analyse sur tous les fichiers choisis et affiche le texte."""
        if not fichiers_selectionnes:
            messagebox.showerror("Erreur", "Sélectionnez au moins un fichier")
            return
        
        resultat_zone.delete("1.0", tk.END) # Vide la zone avant d'écrire
        for f in fichiers_selectionnes:
            logs = lire_logs(f)
            brute, inconnus, roots = analyser_logs(logs)
            
            resultat_zone.insert(tk.END, f"--- FICHIER : {os.path.basename(f)} ---\n")
            for ip, nb in brute.items():
                status = "DANGER-ATTAQUE" if nb >= 3 else "SÉCURISÉ"
                resultat_zone.insert(tk.END, f"  {ip:15} | {nb} tentatives | {status}\n")
            
            resultat_zone.insert(tk.END, f"⚠️ Connexions Root détectées : {len(roots)}\n")
            resultat_zone.insert(tk.END, "-"*40 + "\n")

    def exporter_pdf():
        """Lance la création d'un rapport PDF pour chaque fichier sélectionné."""
        if not fichiers_selectionnes:
            messagebox.showerror("Erreur", "Analysez des fichiers d'abord")
            return
        for f in fichiers_selectionnes:
            logs = lire_logs(f)
            brute, inconnus, roots = analyser_logs(logs)
            generer_pdf(brute, inconnus, roots, f)
        messagebox.showinfo("Succès", "Rapports PDF générés avec succès !")

    # Création des boutons d'action (Analyser, PDF, À propos)
    tk.Button(fenetre, text=" ANALYSER", command=analyser_tout, bg="blue", fg="white", width=20).pack(pady=5)
    tk.Button(fenetre, text=" GÉNÉRER PDF", command=exporter_pdf, bg="green", fg="white", width=20).pack(pady=5)
    tk.Button(fenetre, text="ℹ À PROPOS", command=afficher_aide, bg="#555555", fg="white", width=20).pack(pady=10)

    fenetre.mainloop() # Lance la boucle infinie de l'interface

# Point d'entrée du programme
if __name__ == "__main__":
    lancer_interface()
