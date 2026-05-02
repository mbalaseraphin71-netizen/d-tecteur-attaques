import re
import os
import tkinter as tk
from fpdf import FPDF
from tkinter import filedialog, messagebox

# --- 1. LOGIQUE D'ANALYSE ---

def lire_logs(fichier):
    with open(fichier, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()

def analyser_logs(logs):
    brute_force = {}
    utilisateurs_inconnus = {}
    connexions_root = []

    for ligne in logs:
        ligne_min = ligne.lower()
        # Extraction de l'IP (Regex universel)
        ip_trouvee = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ligne)
        
        if ip_trouvee:
            ip = ip_trouvee.group()
            if "failed" in ligne_min:
                brute_force[ip] = brute_force.get(ip, 0) + 1
            if "invalid" in ligne_min:
                utilisateurs_inconnus[ip] = utilisateurs_inconnus.get(ip, 0) + 1

        if "accepted" in ligne_min and "root" in ligne_min:
            connexions_root.append(ligne.strip())

    return brute_force, utilisateurs_inconnus, connexions_root

# --- 2. GÉNÉRATION PDF (Titre MAJUSCULE puis fichier) ---

def generer_pdf(brute_force, utilisateurs_inconnus, connexions_root, chemin_log):
    pdf = FPDF()
    pdf.add_page()
    
    # Titre principal en MAJUSCULES
    pdf.set_font("Times", "B", 18)
    pdf.cell(200, 10, "RAPPORT DE SÉCURITÉ", ln=True, align="C")
    
    # Spécification du fichier
    nom_pur = os.path.basename(chemin_log)
    pdf.set_font("Times", "I", 12)
    pdf.cell(200, 10, f"Fichier analysé : {nom_pur}", ln=True, align="C")
    pdf.ln(10)

    # Section 1 : Brute Force avec statuts précis
    pdf.set_font("Times", "B", 14)
    pdf.cell(200, 10, "1. Tentatives de Brute Force SSH", ln=True)
    pdf.set_font("Times", size=12)
    for ip, nb in brute_force.items():
        status = "DANGER-ATTAQUE" if nb >= 3 else "SÉCURISÉ"
        pdf.cell(200, 8, f"IP: {ip:15} | Tentatives: {nb} | Statut: {status}", ln=True)
    
    pdf.ln(5)

    # Section 2 : Inconnus
    pdf.set_font("Times", "B", 14)
    pdf.cell(200, 10, "2. Utilisateurs Inconnus", ln=True)
    pdf.set_font("Times", size=12)
    for ip, nb in utilisateurs_inconnus.items():
        pdf.cell(200, 8, f"IP: {ip:15} | Tentatives: {nb} | SUSPECT", ln=True)

    pdf.ln(5)

    # Section 3 : Root
    pdf.set_font("Times", "B", 14)
    pdf.cell(200, 10, "3. Connexions Root Acceptées", ln=True)
    pdf.set_font("Times", "I", 10)
    for ligne in connexions_root:
        pdf.cell(200, 8, f"> {ligne[:85]}", ln=True)

    # Sauvegarde
    pdf.output(f"rapport_{nom_pur}.pdf")

# --- 3. INTERFACE GRAPHIQUE ---

def afficher_aide():
    messagebox.showinfo("À propos", 
        "DÉTECTEUR D'ATTAQUES v2.1\n\n"
        "Développé par SÉRAPHIN MBALA\n"
        "Analyseur de logs SSH multi-fichiers.\n\n"
        "© 2024 - Tous droits réservés.")

def lancer_interface():
    fenetre = tk.Tk()
    fenetre.title("Détecteur d'Attaques Multi-Logs - Séraphin Mbala")
    fenetre.geometry("550x600")

    fichiers_selectionnes = []

    tk.Label(fenetre, text="DÉTECTEUR D'ATTAQUES", font=("Arial", 16, "bold")).pack(pady=10)

    def choisir_fichiers():
        nonlocal fichiers_selectionnes
        fichiers = filedialog.askopenfilenames(filetypes=[("Logs", "*.log *.txt")])
        if fichiers:
            fichiers_selectionnes = list(fichiers)
            lbl_chemin.config(text=f"{len(fichiers_selectionnes)} fichier(s) sélectionné(s)")

    tk.Button(fenetre, text="📂 Choisir fichiers log", command=choisir_fichiers).pack(pady=5)
    lbl_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné", fg="blue")
    lbl_chemin.pack()

    resultat_zone = tk.Text(fenetre, height=18, width=65)
    resultat_zone.pack(pady=10)

    def analyser_tout():
        if not fichiers_selectionnes:
            messagebox.showerror("Erreur", "Sélectionnez au moins un fichier")
            return
        
        resultat_zone.delete("1.0", tk.END)
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
        if not fichiers_selectionnes:
            messagebox.showerror("Erreur", "Analysez des fichiers d'abord")
            return
        for f in fichiers_selectionnes:
            logs = lire_logs(f)
            brute, inconnus, roots = analyser_logs(logs)
            generer_pdf(brute, inconnus, roots, f)
        messagebox.showinfo("Succès", "Rapports PDF générés avec succès !")

    # Boutons d'action
    tk.Button(fenetre, text="🔍 ANALYSER", command=analyser_tout, bg="blue", fg="white", width=20).pack(pady=5)
    tk.Button(fenetre, text="📄 GÉNÉRER PDF", command=exporter_pdf, bg="green", fg="white", width=20).pack(pady=5)
    tk.Button(fenetre, text="ℹ️ À PROPOS", command=afficher_aide, bg="#555555", fg="white", width=20).pack(pady=10)

    fenetre.mainloop()

if __name__ == "__main__":
    lancer_interface()
