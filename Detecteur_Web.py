import re
import os
import streamlit as st
from fpdf import FPDF

# --- 1. LOGIQUE D'ANALYSE DYNAMIQUE ---

def charger_blacklist():
    """Charge dynamiquement les IP de la blacklist depuis le fichier local."""
    blacklist_locale = []
    nom_fichier = "blacklist.txt"
    
    # Vérifie si le fichier existe pour éviter un crash de l'application
    if os.path.exists(nom_fichier):
        with open(nom_fichier, "r", encoding="utf-8") as f:
            for ligne in f:
                ip = ligne.strip()
                # On ne garde que les lignes non vides et qui ne sont pas des commentaires
                if ip and not ip.startswith("#"):
                    blacklist_locale.append(ip)
    else:
        # Valeurs de secours si le fichier n'est pas trouvé
        blacklist_locale = ["192.168.1.50", "10.0.0.99", "45.75.12.3"]
        
    return blacklist_locale

def analyser_logs(logs):
    brute_force = {}
    utilisateurs_inconnus = {}
    connexions_root = []
    
    # Appel de la fonction dynamique
    blacklist = charger_blacklist()

    for ligne in logs:
        if isinstance(ligne, bytes):
            ligne = ligne.decode("utf-8", errors="ignore")
        
        ligne_min = ligne.lower()
        ip_trouvee = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ligne)
        
        if ip_trouvee:
            ip = ip_trouvee.group()
            # On marque l'IP si elle est déjà blacklistée
            if ip in blacklist:
                ligne_min += " (blacklistee)"
                
            if "failed" in ligne_min:
                brute_force[ip] = brute_force.get(ip, 0) + 1
            if "invalid" in ligne_min:
                utilisateurs_inconnus[ip] = utilisateurs_inconnus.get(ip, 0) + 1
        
        if "accepted" in ligne_min and "root" in ligne_min:
            connexions_root.append(ligne.strip())

    return brute_force, utilisateurs_inconnus, connexions_root

# --- 2. GÉNÉRATION PDF CORRIGÉE (fpdf2) ---

def generer_pdf_web(brute_force, utilisateurs_inconnus, connexions_root, nom_log):
    pdf = FPDF()
    pdf.add_page()
    
    # En-tête (Suppression des accents pour éviter les crashs d'encodage)
    pdf.set_font("Arial", "B", 18)
    pdf.cell(200, 10, "RAPPORT DE SECURITE - CYBERSENTINEL", ln=True, align="C")
    
    pdf.set_font("Arial", "I", 12)
    pdf.cell(200, 10, f"Fichier analyse : {nom_log}", ln=True, align="C")
    pdf.ln(10)

    # 1. Brute Force
    pdf.set_font("Arial", "B", 14)
    pdf.cell(200, 10, "1. Tentatives de Brute Force SSH", ln=True)
    pdf.set_font("Arial", size=12)
    
    if not brute_force:
        pdf.cell(200, 8, "Aucune tentative detectee.", ln=True)
    for ip, nb in brute_force.items():
        status = "DANGER-ATTAQUE" if nb >= 3 else "SUSPECT"
        pdf.cell(200, 8, f"IP: {ip} | Tentatives: {nb} | Statut: {status}", ln=True)

    # 2. Connexions Root
    pdf.ln(5)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(200, 10, "2. Connexions Root Acceptees", ln=True)
    pdf.set_font("Courier", size=9)
    
    if not connexions_root:
        pdf.cell(200, 8, "Aucune connexion root detectee.", ln=True)
    for ligne in connexions_root:
        pdf.cell(200, 7, f"> {ligne[:80]}", ln=True)

    # Conversion explicite en bytes valide pour fpdf2
    return bytes(pdf.output())


# --- 3. INTERFACE WEB (Streamlit) ---

st.set_page_config(page_title="CyberSentinel - Séraphin Mbala", page_icon="🛡️", layout="wide")

st.title("🛡️ CyberSentinel : Analyseur de Logs")
st.caption("Développé par **SÉRAPHIN MBALA** | Profil Enseignant & Ingénieur Cybersécurité")

fichiers_charges = st.file_uploader("Glissez vos fichiers .log ou .txt ici", accept_multiple_files=True)

if fichiers_charges:
    for uploaded_file in fichiers_charges:
        st.write(f"### 📄 Analyse de : `{uploaded_file.name}`")
        
        lignes = uploaded_file.readlines()
        brute, inconnus, roots = analyser_logs(lignes)
        
        # Affichage moderne avec des cartes (st.metric)
        m1, m2, m3 = st.columns(3)
        m1.metric(label="IP Brute Force", value=len(brute), delta="Alertes" if len(brute) > 0 else "RAS", delta_color="inverse")
        m2.metric(label="Utilisateurs Invalides", value=len(inconnus))
        m3.metric(label="Connexions Root", value=len(roots), delta="Critique" if len(roots) > 0 else "RAS", delta_color="inverse")
        
        # Layout des détails
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("🔴 Activités Suspectes (IP)")
            if brute:
                for ip, nb in brute.items():
                    if nb >= 3:
                        st.error(f"🚨 **{ip}** : {nb} échecs (Alerte Brute Force)")
                    else:
                        st.warning(f"⚠️ **{ip}** : {nb} échecs")
            else:
                st.success("Aucune IP suspecte trouvée.")
        
        with col2:
            st.subheader("🔑 Accès Root Réussis")
            if roots:
                for r in roots:
                    st.code(r[:70] + "...", language="bash")
            else:
                st.success("Aucun accès root détecté.")
        
        # Section Téléchargement
        try:
            pdf_data = generer_pdf_web(brute, inconnus, roots, uploaded_file.name)
            st.download_button(
                label=f"📥 Télécharger le Rapport PDF",
                data=pdf_data,
                file_name=f"CyberSentinel_{uploaded_file.name}.pdf",
                mime="application/pdf"
            )
        except Exception as e:
            st.error(f"Erreur PDF : {e}. Vérifiez que 'fpdf2' est installé.")
            
        st.divider()

# Barre latérale informative pour les bourses / recruteurs
with st.sidebar:
    st.image("https://shields.io")
    st.title("Framework de Validation")
    st.markdown("""
    **CyberSentinel v1.0 (L1)**
    - Analyse de logs SSH standard
    - Détection brute force heuristique
    - Extraction des élévations de privilèges
    - Blacklist dynamique intégrée
    ---
    *© 2026 - Séraphin Mbala*
    """)
