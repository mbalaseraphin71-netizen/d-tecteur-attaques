import re
import os
import streamlit as st
from fpdf import FPDF
import io

# --- 1. LOGIQUE D'ANALYSE (Inchangée) ---

def analyser_logs(logs):
    brute_force = {}
    utilisateurs_inconnus = {}
    connexions_root = []

    for ligne in logs:
        # Streamlit lit parfois en bytes, on décode en texte
        if isinstance(ligne, bytes):
            ligne = ligne.decode("utf-8", errors="ignore")
            
        ligne_min = ligne.lower()
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

# --- 2. GÉNÉRATION PDF (Adaptée pour le téléchargement Web) ---

def generer_pdf_web(brute_force, utilisateurs_inconnus, connexions_root, nom_log):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 18)
    pdf.cell(200, 10, "RAPPORT DE SÉCURITÉ", ln=True, align="C")
    
    pdf.set_font("Arial", "I", 12)
    pdf.cell(200, 10, f"Fichier analysé : {nom_log}", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", "B", 14)
    pdf.cell(200, 10, "1. Tentatives de Brute Force SSH", ln=True)
    pdf.set_font("Arial", size=12)
    for ip, nb in brute_force.items():
        status = "DANGER-ATTAQUE" if nb >= 3 else "SÉCURISÉ"
        pdf.cell(200, 8, f"IP: {ip:15} | Tentatives: {nb} | Statut: {status}", ln=True)
    
    pdf.ln(5)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(200, 10, "2. Connexions Root Acceptées", ln=True)
    pdf.set_font("Courier", size=9)
    for ligne in connexions_root:
        pdf.cell(200, 7, f"> {ligne[:85]}", ln=True)

    # Au lieu d'enregistrer sur le disque, on renvoie les bytes du PDF
    return pdf.output(dest='S').encode('latin-1')

# --- 3. INTERFACE WEB (Streamlit remplace CustomTkinter) ---

st.set_page_config(page_title="CyberSentinel - Séraphin Mbala", page_icon="🛡️")

st.title("🛡️ Détecteur d'Attaques Multi-Logs")
st.subheader("Par SÉRAPHIN MBALA")

# Zone de dépôt de fichiers (Drag & Drop)
fichiers_charges = st.file_uploader("Glissez vos fichiers .log ou .txt ici", accept_multiple_files=True)

if fichiers_charges:
    for uploaded_file in fichiers_charges:
        st.write(f"--- Analyse de : **{uploaded_file.name}** ---")
        
        # Lecture des logs
        lignes = uploaded_file.readlines()
        brute, inconnus, roots = analyser_logs(lignes)
        
        # Affichage des résultats en colonnes
        col1, col2 = st.columns(2)
        with col1:
            st.error(f"🔴 Brute Force : {len(brute)} IP")
            for ip, nb in brute.items():
                if nb >= 3:
                    st.write(f"⚠️ {ip} ({nb} essais)")
        
        with col2:
            st.warning(f"⚠️ Accès Root : {len(roots)}")
            for r in roots:
                st.write(f"➜ {r[:50]}...")

        # Bouton de téléchargement PDF pour ce fichier
        pdf_data = generer_pdf_web(brute, inconnus, roots, uploaded_file.name)
        st.download_button(
            label=f"📥 Télécharger le Rapport PDF ({uploaded_file.name})",
            data=pdf_data,
            file_name=f"rapport_{uploaded_file.name}.pdf",
            mime="application/pdf"
        )
        st.divider()

# Section À propos dans la barre latérale
st.sidebar.title("À propos")
st.sidebar.info("Développé par SÉRAPHIN MBALA\n\n© 2026 - Tous droits réservés.")
