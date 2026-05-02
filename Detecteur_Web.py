import re
import streamlit as st
from fpdf import FPDF

# --- 1. LOGIQUE D'ANALYSE (Vos idées conservées) ---

def analyser_logs(logs):
    brute_force = {}
    utilisateurs_inconnus = {}
    connexions_root = []

    for ligne in logs:
        # Streamlit lit en bytes, on décode en texte proprement
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

# --- 2. GÉNÉRATION PDF (Optimisée pour le rendu Web) ---

def generer_pdf_web(brute_force, utilisateurs_inconnus, connexions_root, nom_log):
    pdf = FPDF()
    pdf.add_page()
    
    # En-tête
    pdf.set_font("Arial", "B", 18)
    pdf.cell(200, 10, "RAPPORT DE SECURITE", ln=True, align="C")
    
    pdf.set_font("Arial", "I", 12)
    pdf.cell(200, 10, f"Fichier analyse : {nom_log}", ln=True, align="C")
    pdf.ln(10)

    # 1. Brute Force
    pdf.set_font("Arial", "B", 14)
    pdf.cell(200, 10, "1. Tentatives de Brute Force SSH", ln=True)
    pdf.set_font("Arial", size=12)
    for ip, nb in brute_force.items():
        status = "DANGER-ATTAQUE" if nb >= 3 else "SECURISE"
        pdf.cell(200, 8, f"IP: {ip:15} | Tentatives: {nb} | Statut: {status}", ln=True)

    # 2. Connexions Root
    pdf.ln(5)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(200, 10, "2. Connexions Root Acceptees", ln=True)
    pdf.set_font("Courier", size=9)
    for ligne in connexions_root:
        # On limite la longueur pour éviter que ça sorte de la page
        pdf.cell(200, 7, f"> {ligne[:85]}", ln=True)

    # Sortie en bytes (plus stable pour Streamlit)
    return pdf.output(dest='S').encode('latin-1', errors='replace')

# --- 3. INTERFACE WEB (Streamlit) ---

st.set_page_config(page_title="CyberSentinel - Séraphin Mbala", page_icon="🛡️")

st.title("🛡️ Détecteur d'Attaques Multi-Logs")
st.subheader("Par SÉRAPHIN MBALA")

# Zone de dépôt de fichiers
fichiers_charges = st.file_uploader("Glissez vos fichiers .log ou .txt ici", accept_multiple_files=True)

if fichiers_charges:
    for uploaded_file in fichiers_charges:
        st.write(f"--- Analyse de : **{uploaded_file.name}** ---")
        
        # Analyse
        lignes = uploaded_file.readlines()
        brute, inconnus, roots = analyser_logs(lignes)
        
        # Affichage des résultats
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
        
        # Bouton PDF
        try:
            pdf_data = generer_pdf_web(brute, inconnus, roots, uploaded_file.name)
            st.download_button(
                label=f"📥 Télécharger le Rapport PDF ({uploaded_file.name})",
                data=pdf_data,
                file_name=f"rapport_{uploaded_file.name}.pdf",
                mime="application/pdf"
            )
        except Exception as e:
            st.error(f"Erreur lors de la génération du PDF : {e}")
            
        st.divider()

# Barre latérale
st.sidebar.title("À propos")
st.sidebar.info("Développé par SÉRAPHIN MBALA\n\n© 2026 - Tous droits réservés.")
